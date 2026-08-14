package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/uuid"

	"github.com/artemus/imprint/internal/authority"
	"github.com/artemus/imprint/internal/privateio"
)

type AuthorityKeyReconciliation struct {
	QuarantinedOrphans int `json:"quarantined_orphans"`
	ActiveBindings     int `json:"active_bindings"`
}

func (s *Store) ReconcileAuthorityKeys(ctx context.Context, dataRoot string) (result AuthorityKeyReconciliation, returned error) {
	root, err := s.ownedAuthorityDataRoot(dataRoot)
	if err != nil {
		return result, err
	}
	journal, err := authority.LoadRecoveryPublicationJournal(root)
	if err != nil {
		return result, err
	}
	if journal != nil {
		return result, errors.New("unfinished recovery publication requires native reconciliation; retained destination=" + journal.Destination)
	}
	keysDirectory := filepath.Join(root, "authority", "keys")
	quarantine := filepath.Join(root, "authority", "quarantine")
	if err := ensureAuthorityDirectory(keysDirectory, "authority key directory is unsafe"); err != nil {
		return result, err
	}
	if err := ensureAuthorityDirectory(quarantine, "authority quarantine directory is unsafe"); err != nil {
		return result, err
	}
	returned = s.AuthorityTransaction(ctx, func(tx *sql.Tx) error {
		bindings, err := loadAuthorityKeyBindings(ctx, tx)
		if err != nil {
			return err
		}
		referenced := make(map[string]bool, len(bindings))
		if len(bindings) != 0 {
			var storeIdentity string
			if err := tx.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='store_identity'`).Scan(&storeIdentity); err != nil {
				return err
			}
			chain, err := authority.LoadVerifiedChain(ctx, tx, s.operatorID, storeIdentity)
			if err != nil {
				return err
			}
			for _, binding := range bindings {
				state, exists := chain.Keys[binding.keyID]
				if !exists || binding.operatorID != chain.OperatorID || binding.storeIdentity != chain.StoreIdentity ||
					state.Kind != "installation" || state.Status != binding.status || state.InstallID != binding.installID ||
					state.PublicKeyB64 != binding.publicKeyB64 || state.PublicKeyFingerprint != binding.publicKeyFingerprint ||
					state.CertificateSequence != binding.ledgerSequence || state.BlobRelativePath != binding.blobRelativePath ||
					state.BlobSHA256 != binding.blobSHA256 || state.BlobSize != binding.blobSize || state.AlgorithmSuite != binding.algorithmSuite {
					return errors.New("authority key materialization disagrees with the signed ledger")
				}
				if _, err := readLocalAuthorityKeyBlob(root, binding); err != nil {
					return err
				}
				referenced[filepath.Clean(filepath.Join(root, filepath.FromSlash(binding.blobRelativePath)))] = true
			}
		}
		entries, err := os.ReadDir(keysDirectory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			candidate := filepath.Join(keysDirectory, entry.Name())
			if referenced[candidate] {
				continue
			}
			info, err := os.Lstat(candidate)
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("unsafe unbound authority key artifact")
			}
			target := filepath.Join(quarantine, "orphan-"+uuid.NewString()+".blob")
			if err := os.Rename(candidate, target); err != nil {
				return err
			}
			if runtime.GOOS != "windows" {
				if err := os.Chmod(target, 0o600); err != nil {
					return err
				}
			}
			result.QuarantinedOrphans++
		}
		result.ActiveBindings = len(bindings)
		return syncAuthorityDirectories(keysDirectory, quarantine)
	})
	return result, returned
}

func loadAuthorityKeyBindings(ctx context.Context, tx *sql.Tx) ([]localAuthorityKey, error) {
	rows, err := tx.QueryContext(ctx, `SELECT operator_id,install_id,store_identity,key_id,public_key_b64,public_key_fingerprint,status,blob_rel_path,blob_sha256,algorithm_suite,enrollment_nonce,created_at,ledger_sequence,blob_size FROM authority_keys ORDER BY ledger_sequence,key_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bindings := []localAuthorityKey{}
	for rows.Next() {
		var binding localAuthorityKey
		if err := rows.Scan(&binding.operatorID, &binding.installID, &binding.storeIdentity, &binding.keyID,
			&binding.publicKeyB64, &binding.publicKeyFingerprint, &binding.status, &binding.blobRelativePath,
			&binding.blobSHA256, &binding.algorithmSuite, &binding.enrollmentNonce, &binding.createdAt,
			&binding.ledgerSequence, &binding.blobSize); err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

func ensureAuthorityDirectory(path, message string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return privateio.EnsureDir(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New(message)
	}
	return nil
}

func syncAuthorityDirectories(paths ...string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	for _, path := range paths {
		directory, err := os.Open(path)
		if err != nil {
			return err
		}
		err = directory.Sync()
		closeErr := directory.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
