package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/artemus/imprint/internal/authority"
)

type localAuthorityKey struct {
	operatorID, installID, storeIdentity      string
	keyID, publicKeyB64, publicKeyFingerprint string
	status, blobRelativePath, blobSHA256      string
	algorithmSuite                            string
	enrollmentNonce, createdAt                string
	ledgerSequence, blobSize                  int64
}

func (s *Store) CreateAuthorityCheckpoint(ctx context.Context, dataRoot, passphrase string, now time.Time, ttl time.Duration) (result authority.Checkpoint, returned error) {
	root, err := s.ownedAuthorityDataRoot(dataRoot)
	if err != nil {
		return result, err
	}
	if _, err := s.ReconcileAuthorityKeys(ctx, root); err != nil {
		return result, err
	}
	var privateKey ed25519.PrivateKey
	defer func() { clear(privateKey) }()
	returned = s.AuthorityTransaction(ctx, func(tx *sql.Tx) error {
		anchor, err := authority.AssertAuthorityWritesAllowed(ctx, tx)
		if err != nil {
			return err
		}
		chain, err := authority.LoadVerifiedChain(ctx, tx, anchor.OperatorID, anchor.StoreIdentity)
		if err != nil {
			return err
		}
		binding, err := loadLocalAuthorityKey(ctx, tx, s.operatorID)
		if err != nil {
			return err
		}
		chainKey, exists := chain.Keys[binding.keyID]
		if !exists || chainKey.Kind != "installation" || chainKey.Status != "active" || chainKey.InstallID != binding.installID || chainKey.PublicKeyB64 != binding.publicKeyB64 {
			return errors.New("local authority key state disagrees with the signed ledger")
		}
		blob, err := readLocalAuthorityKeyBlob(root, binding)
		if err != nil {
			return err
		}
		privateKey, err = authority.DecryptPrivateKey(blob, passphrase, authority.KeyAAD{
			OperatorID: binding.operatorID, InstallID: binding.installID, StoreIdentity: binding.storeIdentity,
			KeyID: binding.keyID, PublicKeyB64: binding.publicKeyB64, PublicKeyFingerprint: binding.publicKeyFingerprint,
			CreatedAt: binding.createdAt, AlgorithmSuite: binding.algorithmSuite,
			LedgerSequence: binding.ledgerSequence, EnrollmentNonce: binding.enrollmentNonce,
		})
		if err != nil {
			return err
		}
		if err := authority.VerifyPublicBinding(privateKey, binding.publicKeyB64); err != nil {
			return err
		}
		result, err = authority.SignCheckpoint(chain, binding.keyID, privateKey, anchor.CheckpointSHA256, now, ttl)
		if err != nil {
			return err
		}
		encoded, err := authority.CanonicalCheckpoint(result)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(encoded)
		_, err = authority.PinLocalCheckpoint(ctx, tx, chain, result, "local-checkpoint:"+hex.EncodeToString(digest[:]), now)
		return err
	})
	return result, returned
}

func (s *Store) ownedAuthorityDataRoot(dataRoot string) (string, error) {
	root := filepath.Clean(dataRoot)
	relativeStore, err := filepath.Rel(root, s.path)
	if strings.TrimSpace(dataRoot) == "" || !filepath.IsAbs(root) || err != nil || relativeStore == ".." || strings.HasPrefix(relativeStore, ".."+string(filepath.Separator)) {
		return "", errors.New("authority data root does not own the canonical store")
	}
	return root, nil
}

func loadLocalAuthorityKey(ctx context.Context, tx *sql.Tx, expectedOperatorID string) (localAuthorityKey, error) {
	var binding localAuthorityKey
	var activeCount int
	err := tx.QueryRowContext(ctx, `SELECT operator_id,install_id,store_identity,key_id,public_key_b64,public_key_fingerprint,status,blob_rel_path,blob_sha256,algorithm_suite,enrollment_nonce,created_at,ledger_sequence,blob_size,(SELECT COUNT(*) FROM authority_keys WHERE status='active') FROM authority_keys WHERE status='active' ORDER BY ledger_sequence DESC LIMIT 1`).Scan(
		&binding.operatorID, &binding.installID, &binding.storeIdentity, &binding.keyID,
		&binding.publicKeyB64, &binding.publicKeyFingerprint, &binding.status, &binding.blobRelativePath,
		&binding.blobSHA256, &binding.algorithmSuite, &binding.enrollmentNonce,
		&binding.createdAt, &binding.ledgerSequence, &binding.blobSize, &activeCount,
	)
	if err != nil || activeCount != 1 {
		return localAuthorityKey{}, errors.New("authority requires exactly one active local key")
	}
	if binding.operatorID != expectedOperatorID {
		return localAuthorityKey{}, errors.New("authority key does not match configured operator")
	}
	return binding, nil
}

func readLocalAuthorityKeyBlob(root string, binding localAuthorityKey) ([]byte, error) {
	expected := "authority/keys/" + strings.TrimPrefix(binding.publicKeyFingerprint, "sha256:") + ".blob"
	portable := strings.ReplaceAll(binding.blobRelativePath, `\`, "/")
	if portable != expected {
		return nil, errors.New("authority key blob path is invalid")
	}
	target := filepath.Join(root, filepath.FromSlash(portable))
	for _, candidate := range []string{filepath.Join(root, "authority"), filepath.Join(root, "authority", "keys"), target} {
		info, err := os.Lstat(candidate)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("authority key blob is missing or has unsafe permissions")
		}
		if candidate == target && (!info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
			return nil, errors.New("authority key blob is missing or has unsafe permissions")
		}
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		return nil, errors.New("authority key blob is missing or has unsafe permissions")
	}
	digest := sha256.Sum256(raw)
	if int64(len(raw)) != binding.blobSize || hex.EncodeToString(digest[:]) != binding.blobSHA256 {
		return nil, errors.New("authority key blob digest mismatch")
	}
	return raw, nil
}
