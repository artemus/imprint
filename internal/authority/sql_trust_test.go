package authority

import (
	"context"
	"testing"
	"time"
)

func TestEstablishEnrollmentTrustPersistsCheckpointPin(t *testing.T) {
	db, genesis, privateKey := approvalDatabase(t)
	defer db.Close()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := LoadVerifiedChain(ctx, tx, genesis.OperatorID, genesis.StoreIdentity)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 15, 0, 0, time.UTC)
	checkpoint, err := SignCheckpoint(chain, genesis.KeyID, privateKey, nil, now, MaxCheckpointAge)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := EstablishEnrollmentTrust(ctx, tx, chain, nil, nil, checkpoint, now)
	if err != nil {
		t.Fatal(err)
	}
	if anchor.Checkpoint == nil || anchor.CheckpointSHA256 == nil || anchor.PinnedHeadSHA256 != chain.HeadSHA256 || anchor.UpdatedAt != "2026-08-14T12:15:00.000000Z" {
		t.Fatalf("anchor=%#v", anchor)
	}
	if _, err := AssertAuthorityWritesAllowed(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var pins int
	if err := db.QueryRow(`SELECT COUNT(*) FROM authority_checkpoint_pins WHERE operation_digest='trust-bootstrap'`).Scan(&pins); err != nil || pins != 1 {
		t.Fatalf("pins=%d err=%v", pins, err)
	}
	tx, _ = db.BeginTx(ctx, nil)
	if _, err := EstablishEnrollmentTrust(ctx, tx, chain, nil, nil, checkpoint, now); err == nil {
		t.Fatal("established local trust twice")
	}
	_ = tx.Rollback()
}

func TestAuthorityWritesRequireUnblockedTrust(t *testing.T) {
	db, _, _ := approvalDatabase(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := AssertAuthorityWritesAllowed(ctx, db); err == nil {
		t.Fatal("allowed writes without local trust")
	}
}
