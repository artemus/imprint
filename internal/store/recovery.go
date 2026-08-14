package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type RecoveryResult struct {
	Status             string `json:"status"`
	WALBytesBefore     int64  `json:"wal_bytes_before"`
	CheckpointBusy     int    `json:"checkpoint_busy"`
	CheckpointFrames   int    `json:"checkpoint_frames"`
	CheckpointedFrames int    `json:"checkpointed_frames"`
	Integrity          string `json:"integrity"`
}

// Recover exclusively asks SQLite to replay and retire crash-resident WAL
// state. Imprint never interprets or deletes canonical WAL frames itself.
func Recover(ctx context.Context, path string) (result RecoveryResult, returned error) {
	before, err := requireRegularStore(path)
	if err != nil {
		return result, err
	}
	for _, sidecar := range sqliteSidecars(path) {
		if _, err := os.Lstat(sidecar); err == nil {
			if err = requireRegularSidecar(sidecar); err != nil {
				return result, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
	}
	wal := path + "-wal"
	if info, err := os.Lstat(wal); err == nil {
		result.WALBytesBefore = info.Size()
	}
	if err := secureSQLite(path); err != nil {
		return result, err
	}

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rw")
	if err != nil {
		return result, err
	}
	db.SetMaxOpenConns(1)
	defer func() {
		closeErr := db.Close()
		secureErr := secureSQLite(path)
		if returned == nil && closeErr != nil {
			returned = closeErr
		}
		if returned == nil && secureErr != nil {
			returned = secureErr
		}
	}()
	connection, err := db.Conn(ctx)
	if err != nil {
		return result, recoveryDatabaseError(err)
	}
	defer connection.Close()
	if _, err = connection.ExecContext(ctx, "PRAGMA busy_timeout=0"); err != nil {
		return result, recoveryDatabaseError(err)
	}
	var lockingMode string
	if err = connection.QueryRowContext(ctx, "PRAGMA locking_mode=EXCLUSIVE").Scan(&lockingMode); err != nil || strings.ToLower(lockingMode) != "exclusive" {
		return result, recoveryDatabaseError(err)
	}
	if _, err = connection.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		if sqliteLockConflict(err) {
			return result, errors.New("store recovery refused because a live SQLite connection holds the store")
		}
		return result, recoveryDatabaseError(err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = connection.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	if err = requireCompatibleConnection(ctx, connection); err != nil {
		return result, err
	}
	if err = connection.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result.Integrity); err != nil {
		return result, recoveryDatabaseError(err)
	}
	if result.Integrity != "ok" {
		return result, fmt.Errorf("store integrity check failed: %s", result.Integrity)
	}
	if _, err = connection.ExecContext(ctx, "COMMIT"); err != nil {
		return result, recoveryDatabaseError(err)
	}
	committed = true
	if err = connection.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&result.CheckpointBusy, &result.CheckpointFrames, &result.CheckpointedFrames); err != nil {
		return result, recoveryDatabaseError(err)
	}
	if result.CheckpointBusy != 0 || result.CheckpointedFrames < result.CheckpointFrames {
		return result, errors.New("store recovery refused because live SQLite activity prevented a full checkpoint")
	}
	if err = connection.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result.Integrity); err != nil {
		return result, recoveryDatabaseError(err)
	}
	if result.Integrity != "ok" {
		return result, fmt.Errorf("store integrity check failed after recovery: %s", result.Integrity)
	}
	var journalMode string
	if err = connection.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&journalMode); err != nil || strings.ToLower(journalMode) != "delete" {
		return result, errors.New("SQLite refused to retire recovered WAL state")
	}
	if err = connection.Close(); err != nil {
		return result, err
	}
	if err = db.Close(); err != nil {
		return result, err
	}

	if info, err := os.Lstat(wal); err == nil {
		if err = requireRegularSidecar(wal); err != nil {
			return result, err
		}
		if info.Size() != 0 {
			return result, errors.New("store recovery left nonempty WAL state")
		}
		if err = os.Remove(wal); err != nil {
			return result, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	shm := path + "-shm"
	if _, err := os.Lstat(shm); err == nil {
		if err = requireRegularSidecar(shm); err != nil {
			return result, err
		}
		if err = os.Remove(shm); err != nil {
			return result, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return result, errors.New("store path changed during recovery")
	}
	result.Status = "clean"
	if result.WALBytesBefore > 0 {
		result.Status = "recovered"
	}
	return result, nil
}

func rejectAmbiguousSQLiteState(path string) error {
	wal, shm := path+"-wal", path+"-shm"
	walInfo, walErr := os.Lstat(wal)
	shmInfo, shmErr := os.Lstat(shm)
	walExists := walErr == nil
	shmExists := shmErr == nil
	if !walExists && !shmExists {
		return nil
	}
	if (walErr != nil && !errors.Is(walErr, os.ErrNotExist)) || (shmErr != nil && !errors.Is(shmErr, os.ErrNotExist)) {
		return errors.New("cannot inspect SQLite sidecar state")
	}
	if walExists && shmExists && walInfo.Mode().IsRegular() && shmInfo.Mode().IsRegular() && walInfo.Size() == 0 && cleanReaderSHM(shm, shmInfo.Size()) {
		return nil
	}
	return errors.New("store has ambiguous or crash-resident WAL/SHM state; run explicit store recover")
}

func cleanReaderSHM(path string, size int64) bool {
	if size < 32768 || size%32768 != 0 {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) < 96 || string(raw[:48]) != string(raw[48:96]) {
		return false
	}
	header := raw[:48]
	return binary.LittleEndian.Uint32(header[:4]) == 3007000 && (header[12] == 0 || header[12] == 1) && binary.LittleEndian.Uint32(header[16:20]) == 0
}

func requireRegularStore(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("store does not exist")
	}
	if err != nil {
		return nil, errors.New("store is unreadable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("store path must be a regular non-symlink file")
	}
	return info, nil
}

func requireRegularSidecar(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("SQLite recovery sidecar is not a regular non-symlink file")
	}
	return nil
}

func sqliteSidecars(path string) []string {
	return []string{path + "-wal", path + "-shm", path + "-journal"}
}

func sqliteLockConflict(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") || strings.Contains(message, "database table is locked") || strings.Contains(message, "busy")
}

func recoveryDatabaseError(err error) error {
	if err == nil {
		return errors.New("store recovery failed; SQLite state is corrupt or unreadable")
	}
	return fmt.Errorf("store recovery failed; SQLite state is corrupt or unreadable: %w", err)
}

type connectionQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func requireCompatibleConnection(ctx context.Context, connection connectionQueryer) error {
	var storeVersion, ontologyVersion string
	if err := connection.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='store_schema_version'").Scan(&storeVersion); err != nil {
		return errors.New("existing store is missing store_schema_version")
	}
	if err := connection.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='ontology_schema_version'").Scan(&ontologyVersion); err != nil {
		return errors.New("existing store is missing ontology_schema_version")
	}
	if storeVersion != StoreSchemaVersion {
		return fmt.Errorf("incompatible store schema %q", storeVersion)
	}
	if ontologyVersion != OntologySchemaVersion {
		return fmt.Errorf("incompatible ontology schema %q", ontologyVersion)
	}
	return nil
}
