package store

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/artemus/imprint/internal/urn"
)

func TestRecoveryCrashHelper(t *testing.T) {
	path := os.Getenv("IMPRINT_TEST_CRASH_STORE")
	if path == "" {
		return
	}
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rw")
	if err != nil {
		os.Exit(91)
	}
	for _, statement := range []string{"PRAGMA journal_mode=WAL", "PRAGMA wal_autocheckpoint=0", "CREATE TABLE recovery_probe(value TEXT NOT NULL)", "INSERT INTO recovery_probe VALUES('committed-before-crash')"} {
		if _, err = database.Exec(statement); err != nil {
			os.Exit(92)
		}
	}
	os.Exit(0)
}

func TestRecoverReplaysCrashWALAndOrdinaryOpenFailsClosed(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(root, "imprint.db")
	operator, _ := urn.New("operator")
	database, err := Open(path, operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestRecoveryCrashHelper$")
	command.Env = append(os.Environ(), "IMPRINT_TEST_CRASH_STORE="+path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("crash helper: %v %s", err, output)
	}
	walInfo, err := os.Stat(path + "-wal")
	if err != nil || walInfo.Size() == 0 {
		t.Fatalf("missing crash WAL: info=%v err=%v", walInfo, err)
	}
	if opened, err := Open(path, operator, "primary"); err == nil {
		opened.Close()
		t.Fatal("ordinary open accepted crash-resident WAL")
	} else if !strings.Contains(err.Error(), "explicit store recover") {
		t.Fatalf("unexpected open error: %v", err)
	}
	result, err := Recover(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "recovered" || result.WALBytesBefore == 0 || result.CheckpointBusy != 0 || result.Integrity != "ok" {
		t.Fatalf("result=%#v", result)
	}
	database, err = Open(path, operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var value string
	if err = database.db.QueryRow("SELECT value FROM recovery_probe").Scan(&value); err != nil || value != "committed-before-crash" {
		t.Fatalf("value=%q err=%v", value, err)
	}
}

func TestRecoverRefusesLiveWriter(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(root, "imprint.db")
	operator, _ := urn.New("operator")
	database, err := Open(path, operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	database.Close()
	writer, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err = writer.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer writer.Exec("ROLLBACK")
	if _, err = Recover(context.Background(), path); err == nil || !strings.Contains(err.Error(), "live SQLite connection") {
		t.Fatalf("err=%v", err)
	}
}

func TestRecoverCleanStore(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(root, "imprint.db")
	operator, _ := urn.New("operator")
	database, err := Open(path, operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	database.Close()
	result, err := Recover(context.Background(), path)
	if err != nil || result.Status != "clean" || result.Integrity != "ok" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}
