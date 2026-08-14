package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/artemus/imprint/internal/authority"
)

func (s *Store) BuildAuthorityTransport(ctx context.Context, checkpoint authority.Checkpoint, now time.Time) (artifact authority.AuthorityTransportArtifact, returned error) {
	returned = s.AuthorityTransaction(ctx, func(tx *sql.Tx) error {
		anchor, err := authority.AssertAuthorityWritesAllowed(ctx, tx)
		if err != nil {
			return err
		}
		checkpointRaw, err := authority.CanonicalCheckpoint(checkpoint)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(checkpointRaw)
		if anchor.CheckpointSHA256 == nil || *anchor.CheckpointSHA256 != hex.EncodeToString(digest[:]) {
			return errors.New("authority transport checkpoint is not the locally pinned checkpoint")
		}
		rows, err := authority.LoadLedgerRows(ctx, tx)
		if err != nil {
			return err
		}
		checkpointRows, err := tx.QueryContext(ctx, `SELECT checkpoint_json FROM authority_checkpoint_pins ORDER BY accepted_at,rowid`)
		if err != nil {
			return err
		}
		defer checkpointRows.Close()
		history := []authority.Checkpoint{}
		for checkpointRows.Next() {
			var raw string
			if err := checkpointRows.Scan(&raw); err != nil {
				return err
			}
			item, err := authority.DecodeCanonicalCheckpoint([]byte(raw))
			if err != nil {
				return err
			}
			history = append(history, item)
		}
		if err := checkpointRows.Err(); err != nil {
			return err
		}
		artifact, err = authority.BuildAuthorityTransport(rows, history, checkpoint, now)
		return err
	})
	return artifact, returned
}
