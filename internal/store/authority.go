package store

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/artemus/imprint/internal/authority"
)

type AuthorityEnrollment struct {
	LedgerRow  authority.LedgerRow
	Checkpoint authority.Checkpoint
	Trust      authority.AuthorityTrustAnchor
}

// EnrollAuthority atomically activates a prepared first-trust enrollment. The
// terminal ceremony prepares the event, encrypted blob, and passphrase-bound
// private key; the store owns the durable database/filesystem commit boundary.
func (s *Store) EnrollAuthority(ctx context.Context, dataRoot string, event authority.GenesisEvent, privateKey ed25519.PrivateKey, blob []byte, now time.Time) (result AuthorityEnrollment, returned error) {
	if event.OperatorID != s.operatorID {
		return result, errors.New("authority enrollment does not match the configured operator")
	}
	root := filepath.Clean(dataRoot)
	relativeStore, err := filepath.Rel(root, s.path)
	if strings.TrimSpace(dataRoot) == "" || !filepath.IsAbs(root) || err != nil || relativeStore == ".." || strings.HasPrefix(relativeStore, ".."+string(filepath.Separator)) {
		return result, errors.New("authority enrollment data root does not own the canonical store")
	}
	var published authority.PublishedKey
	publishedActive := false
	err = s.AuthorityTransaction(ctx, func(tx *sql.Tx) error {
		var storeIdentity string
		if err := tx.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='store_identity'`).Scan(&storeIdentity); err != nil {
			return err
		}
		if event.StoreIdentity != storeIdentity {
			return errors.New("authority enrollment does not match the canonical store")
		}
		var enrolled bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM authority_ledger LIMIT 1)`).Scan(&enrolled); err != nil {
			return err
		}
		if enrolled {
			return errors.New("authority is already enrolled")
		}
		var authoritativeRows int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM node_versions WHERE authority_tier IN ('captured_judgment','ratified_knowledge'))+(SELECT COUNT(*) FROM edge_versions WHERE authority_tier IN ('captured_judgment','ratified_knowledge'))`).Scan(&authoritativeRows); err != nil {
			return err
		}
		if authoritativeRows != 0 {
			return errors.New("store has authority-bearing data but no verifiable authority ledger")
		}
		row, err := authority.InsertGenesis(ctx, tx, event, privateKey)
		if err != nil {
			return err
		}
		chain, err := authority.LoadVerifiedChain(ctx, tx, event.OperatorID, event.StoreIdentity)
		if err != nil {
			return err
		}
		checkpoint, err := authority.SignCheckpoint(chain, event.KeyID, privateKey, nil, now, authority.MaxCheckpointAge)
		if err != nil {
			return err
		}
		var recoveryKeyID, recoveryPublicKeyB64 *string
		if event.RecoveryBinding != nil {
			recoveryKeyID = &event.RecoveryBinding.KeyID
			recoveryPublicKeyB64 = &event.RecoveryBinding.PublicKeyB64
		}
		trust, err := authority.EstablishEnrollmentTrust(ctx, tx, chain, recoveryKeyID, recoveryPublicKeyB64, checkpoint, now)
		if err != nil {
			return err
		}
		published, err = authority.PublishKeyBlob(root, event, blob)
		if err != nil {
			return err
		}
		publishedActive = true
		if err := secureSQLite(s.path); err != nil {
			return err
		}
		result = AuthorityEnrollment{LedgerRow: row, Checkpoint: checkpoint, Trust: trust}
		return nil
	})
	if err != nil {
		if publishedActive {
			_, quarantineErr := published.Quarantine()
			if quarantineErr != nil {
				return AuthorityEnrollment{}, errors.Join(err, fmt.Errorf("quarantine uncommitted authority key: %w", quarantineErr))
			}
		}
		return AuthorityEnrollment{}, err
	}
	return result, nil
}
