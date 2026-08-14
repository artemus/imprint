package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/artemus/imprint/internal/authority"
	"github.com/artemus/imprint/internal/identity"
	"github.com/artemus/imprint/internal/store"
)

func TestAuthorityCheckpointCeremonyUnlocksAndPins(t *testing.T) {
	_, configPath, operatorRoot := enrollmentTestRuntime(t)
	operatorID, err := identity.LoadOrCreate(operatorRoot)
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(operatorRoot, "imprint.db"), operatorID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	storeIdentity, err := database.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 15, 0, 0, time.UTC)
	plan, err := authority.PrepareEnrollmentWithoutRecovery(operatorID, storeIdentity, "fixture-passphrase", now, bytes.NewReader(deterministicEnrollmentRandom()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.EnrollAuthority(context.Background(), operatorRoot, plan.Event, plan.PrivateKey, plan.KeyBlob, now); err != nil {
		t.Fatal(err)
	}
	plan.Clear()
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	console := &enrollmentConsole{secrets: []string{"fixture-passphrase"}}
	var stdout, stderr bytes.Buffer
	code := runAuthorityCheckpoint(context.Background(), configPath, time.Hour, strings.NewReader(""), &stdout, &stderr, console, now.Add(time.Minute))
	if code != 0 || !console.required || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var checkpoint authority.Checkpoint
	if err := json.Unmarshal(stdout.Bytes(), &checkpoint); err != nil || checkpoint.PriorCheckpointSHA256 == nil || checkpoint.ExpiresAt != "2026-08-14T13:16:00.000000Z" {
		t.Fatalf("checkpoint=%#v err=%v", checkpoint, err)
	}
	database, err = store.Open(filepath.Join(operatorRoot, "imprint.db"), operatorID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var anchor *authority.AuthorityTrustAnchor
	if err := database.AuthorityTransaction(context.Background(), func(tx *sql.Tx) error {
		anchor, err = authority.LoadTrustAnchor(context.Background(), tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if anchor == nil || anchor.CheckpointSHA256 == nil || anchor.Checkpoint == nil || anchor.Checkpoint.SignatureB64 != checkpoint.SignatureB64 {
		t.Fatalf("anchor=%#v", anchor)
	}
}

func TestCheckpointTTLValidation(t *testing.T) {
	for _, seconds := range []int{-1, 0, 86401} {
		if _, err := checkpointTTL(seconds); err == nil {
			t.Fatalf("accepted ttl=%d", seconds)
		}
	}
	if ttl, err := checkpointTTL(3600); err != nil || ttl != time.Hour {
		t.Fatalf("ttl=%v err=%v", ttl, err)
	}
}
