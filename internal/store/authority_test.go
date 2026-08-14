package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/artemus/imprint/internal/authority"
	"github.com/artemus/imprint/internal/urn"
)

func TestEnrollAuthorityCommitsGenesisTrustAndPublishedKey(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	database, err := Open(filepath.Join(root, "canonical", "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	event, privateKey, blob := storeEnrollmentFixture(t, database, operator)
	now := time.Date(2026, 8, 14, 12, 15, 0, 0, time.UTC)
	result, err := database.EnrollAuthority(context.Background(), root, event, privateKey, blob, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.LedgerRow.EventSHA256 == "" || result.Trust.CheckpointSHA256 == nil || result.Checkpoint.Sequence != 1 {
		t.Fatalf("result=%#v", result)
	}
	var ledger, anchors, pins int
	if err := database.db.QueryRow(`SELECT (SELECT COUNT(*) FROM authority_ledger),(SELECT COUNT(*) FROM authority_trust_anchor),(SELECT COUNT(*) FROM authority_checkpoint_pins)`).Scan(&ledger, &anchors, &pins); err != nil {
		t.Fatal(err)
	}
	if ledger != 1 || anchors != 1 || pins != 1 {
		t.Fatalf("ledger=%d anchors=%d pins=%d", ledger, anchors, pins)
	}
	if raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(event.BlobRelativePath))); err != nil || !bytes.Equal(raw, blob) {
		t.Fatalf("published err=%v", err)
	}
}

func TestEnrollAuthorityRollsBackDatabaseWhenPublicationConflicts(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	database, err := Open(filepath.Join(root, "canonical", "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	event, privateKey, blob := storeEnrollmentFixture(t, database, operator)
	target := filepath.Join(root, filepath.FromSlash(event.BlobRelativePath))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.EnrollAuthority(context.Background(), root, event, privateKey, blob, time.Date(2026, 8, 14, 12, 15, 0, 0, time.UTC)); err == nil {
		t.Fatal("enrolled over an existing key artifact")
	}
	var ledger, anchors int
	if err := database.db.QueryRow(`SELECT (SELECT COUNT(*) FROM authority_ledger),(SELECT COUNT(*) FROM authority_trust_anchor)`).Scan(&ledger, &anchors); err != nil || ledger != 0 || anchors != 0 {
		t.Fatalf("ledger=%d anchors=%d err=%v", ledger, anchors, err)
	}
}

func TestEnrollAuthorityQuarantinesPublishedKeyWhenCommitFails(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	database, err := Open(filepath.Join(root, "canonical", "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.db.Exec(`
CREATE TABLE authority_commit_guard(id TEXT PRIMARY KEY);
CREATE TABLE authority_commit_failure(id TEXT REFERENCES authority_commit_guard(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER authority_test_deferred_failure AFTER INSERT ON authority_checkpoint_pins
BEGIN INSERT INTO authority_commit_failure VALUES('missing'); END;
`); err != nil {
		t.Fatal(err)
	}
	event, privateKey, blob := storeEnrollmentFixture(t, database, operator)
	if _, err := database.EnrollAuthority(context.Background(), root, event, privateKey, blob, time.Date(2026, 8, 14, 12, 15, 0, 0, time.UTC)); err == nil {
		t.Fatal("accepted enrollment whose SQLite commit failed")
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(event.BlobRelativePath))); !os.IsNotExist(err) {
		t.Fatalf("uncommitted key remained active: %v", err)
	}
	quarantined, err := filepath.Glob(filepath.Join(root, "authority", "quarantine", "orphan-*.blob"))
	if err != nil || len(quarantined) != 1 {
		t.Fatalf("quarantined=%v err=%v", quarantined, err)
	}
	if raw, err := os.ReadFile(quarantined[0]); err != nil || !bytes.Equal(raw, blob) {
		t.Fatalf("quarantine err=%v", err)
	}
	var ledger, anchors int
	if err := database.db.QueryRow(`SELECT (SELECT COUNT(*) FROM authority_ledger),(SELECT COUNT(*) FROM authority_trust_anchor)`).Scan(&ledger, &anchors); err != nil || ledger != 0 || anchors != 0 {
		t.Fatalf("ledger=%d anchors=%d err=%v", ledger, anchors, err)
	}
}

func storeEnrollmentFixture(t *testing.T, database *Store, operator string) (authority.GenesisEvent, ed25519.PrivateKey, []byte) {
	t.Helper()
	key, err := authority.GenerateKey(bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	var storeIdentity string
	if err := database.db.QueryRow(`SELECT value FROM meta WHERE key='store_identity'`).Scan(&storeIdentity); err != nil {
		t.Fatal(err)
	}
	created := "2026-08-14T12:00:00.000000Z"
	publicB64 := base64.StdEncoding.EncodeToString(key.PublicKey)
	event := authority.GenesisEvent{
		ContractVersion: authority.GenesisEventVersion, DomainSeparator: authority.LedgerDomain,
		Sequence: 1, EventID: "urn:imprint:authority-event:fixture", EventType: "enrollment",
		OperatorID: operator, InstallID: "urn:imprint:installation:fixture", StoreIdentity: storeIdentity,
		KeyID: key.KeyID, PublicKeyB64: publicB64, PublicKeyFingerprint: key.Fingerprint,
		AlgorithmSuite: authority.AlgorithmSuite, EnrollmentNonce: "fixture-enrollment-nonce",
		BlobRelativePath: "authority/keys/" + key.Fingerprint[len("sha256:"):] + ".blob",
		Status:           "active", CreatedAt: created,
	}
	aad := authority.KeyAAD{
		OperatorID: operator, InstallID: event.InstallID, StoreIdentity: storeIdentity,
		KeyID: key.KeyID, PublicKeyB64: publicB64, PublicKeyFingerprint: key.Fingerprint,
		CreatedAt: created, AlgorithmSuite: authority.AlgorithmSuite,
		LedgerSequence: 1, EnrollmentNonce: event.EnrollmentNonce,
	}
	blob, err := authority.EncryptPrivateKey(key.PrivateKey, "fixture-passphrase", aad, bytes.NewReader(make([]byte, 44)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(blob)
	event.BlobSHA256, event.BlobSize = hex.EncodeToString(digest[:]), int64(len(blob))
	return event, key.PrivateKey, blob
}
