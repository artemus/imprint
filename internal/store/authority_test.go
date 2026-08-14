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
	"strings"
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

func TestCreateAuthorityCheckpointUnlocksSignsAndPins(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	database, err := Open(filepath.Join(root, "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	event, privateKey, blob := storeEnrollmentFixture(t, database, operator)
	now := time.Date(2026, 8, 14, 12, 15, 0, 0, time.UTC)
	if _, err := database.EnrollAuthority(context.Background(), root, event, privateKey, blob, now); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := database.CreateAuthorityCheckpoint(context.Background(), root, "fixture-passphrase", now.Add(time.Minute), authority.MaxCheckpointAge)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Sequence != 1 || checkpoint.PriorCheckpointSHA256 == nil {
		t.Fatalf("checkpoint=%#v", checkpoint)
	}
	anchor, err := authority.LoadTrustAnchor(context.Background(), database.db)
	if err != nil || anchor == nil || anchor.CheckpointSHA256 == nil {
		t.Fatalf("anchor=%#v err=%v", anchor, err)
	}
	raw, _ := authority.CanonicalCheckpoint(checkpoint)
	verified, err := authority.VerifyCheckpoint(mustStoreChain(t, database, operator), raw, now.Add(time.Minute), authority.MaxCheckpointAge, true)
	if err != nil || verified.CheckpointSHA256 != *anchor.CheckpointSHA256 {
		t.Fatalf("verified=%#v anchor=%#v err=%v", verified, anchor, err)
	}
	var pins int
	if err := database.db.QueryRow(`SELECT COUNT(*) FROM authority_checkpoint_pins`).Scan(&pins); err != nil || pins != 2 {
		t.Fatalf("pins=%d err=%v", pins, err)
	}
}

func TestCreateAuthorityCheckpointWrongPassphraseDoesNotAdvanceAnchor(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	database, err := Open(filepath.Join(root, "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	event, privateKey, blob := storeEnrollmentFixture(t, database, operator)
	now := time.Date(2026, 8, 14, 12, 15, 0, 0, time.UTC)
	if _, err := database.EnrollAuthority(context.Background(), root, event, privateKey, blob, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateAuthorityCheckpoint(context.Background(), root, "wrong-passphrase", now.Add(time.Minute), authority.MaxCheckpointAge); err == nil {
		t.Fatal("checkpoint accepted the wrong passphrase")
	}
	var pins int
	if err := database.db.QueryRow(`SELECT COUNT(*) FROM authority_checkpoint_pins`).Scan(&pins); err != nil || pins != 1 {
		t.Fatalf("pins=%d err=%v", pins, err)
	}
}

func TestCreateAuthorityCheckpointBlockedByRecoveryJournal(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	database, err := Open(filepath.Join(root, "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	event, privateKey, blob := storeEnrollmentFixture(t, database, operator)
	now := time.Date(2026, 8, 14, 12, 15, 0, 0, time.UTC)
	if _, err := database.EnrollAuthority(context.Background(), root, event, privateKey, blob, now); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(filepath.Dir(root), "offline", "recovery.json")
	if _, err := authority.CreateRecoveryPublicationJournal(root, destination, "urn:imprint:authority-key:recovery", event.BlobSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateAuthorityCheckpoint(context.Background(), root, "fixture-passphrase", now.Add(time.Minute), authority.MaxCheckpointAge); err == nil || !strings.Contains(err.Error(), "unfinished recovery publication") {
		t.Fatalf("err=%v", err)
	}
	var pins int
	if err := database.db.QueryRow(`SELECT COUNT(*) FROM authority_checkpoint_pins`).Scan(&pins); err != nil || pins != 1 {
		t.Fatalf("pins=%d err=%v", pins, err)
	}
}

func TestReconcileAuthorityKeysQuarantinesOnlyUnreferencedFiles(t *testing.T) {
	root, database, event, _ := enrolledStoreFixture(t)
	defer database.Close()
	orphan := filepath.Join(root, "authority", "keys", "unreferenced.blob")
	if err := os.WriteFile(orphan, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := database.ReconcileAuthorityKeys(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if result.QuarantinedOrphans != 1 || result.ActiveBindings != 1 {
		t.Fatalf("result=%#v", result)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(event.BlobRelativePath))); err != nil {
		t.Fatal("referenced key was moved:", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan remained active: %v", err)
	}
	quarantined, err := filepath.Glob(filepath.Join(root, "authority", "quarantine", "orphan-*.blob"))
	if err != nil || len(quarantined) != 1 {
		t.Fatalf("quarantined=%v err=%v", quarantined, err)
	}
}

func TestReconcileAuthorityKeysFailsBeforeMovingOrphansOnCommittedCorruption(t *testing.T) {
	root, database, _, _ := enrolledStoreFixture(t)
	defer database.Close()
	orphan := filepath.Join(root, "authority", "keys", "unreferenced.blob")
	if err := os.WriteFile(orphan, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`UPDATE authority_keys SET blob_sha256=?`, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReconcileAuthorityKeys(context.Background(), root); err == nil || !strings.Contains(err.Error(), "materialization disagrees") {
		t.Fatalf("err=%v", err)
	}
	if raw, err := os.ReadFile(orphan); err != nil || string(raw) != "orphan" {
		t.Fatalf("orphan moved before corruption was reported: %q err=%v", raw, err)
	}
}

func TestBuildAuthorityTransportUsesPinnedCheckpointHistory(t *testing.T) {
	root, database, _, now := enrolledStoreFixture(t)
	defer database.Close()
	checkpoint, err := database.CreateAuthorityCheckpoint(context.Background(), root, "fixture-passphrase", now.Add(time.Minute), authority.MaxCheckpointAge)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := database.BuildAuthorityTransport(context.Background(), checkpoint, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := authority.VerifyAuthorityTransport(artifact.Bytes, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Transport.CheckpointHistory) != 2 || verified.Checkpoint.CheckpointSHA256 == "" || artifact.SHA256 == "" {
		t.Fatalf("artifact=%#v verified=%#v", artifact, verified)
	}
	stale := checkpoint
	stale.SignatureB64 = strings.Repeat("A", 88)
	if _, err := database.BuildAuthorityTransport(context.Background(), stale, now.Add(time.Minute)); err == nil {
		t.Fatal("built transport from a checkpoint other than the local pin")
	}
}

func enrolledStoreFixture(t *testing.T) (string, *Store, authority.GenesisEvent, time.Time) {
	t.Helper()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	database, err := Open(filepath.Join(root, "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	event, privateKey, blob := storeEnrollmentFixture(t, database, operator)
	now := time.Date(2026, 8, 14, 12, 15, 0, 0, time.UTC)
	if _, err := database.EnrollAuthority(context.Background(), root, event, privateKey, blob, now); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return root, database, event, now
}

func mustStoreChain(t *testing.T, database *Store, operator string) authority.VerifiedChain {
	t.Helper()
	tx, err := database.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	identity, err := database.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	chain, err := authority.LoadVerifiedChain(context.Background(), tx, operator, identity)
	if err != nil {
		t.Fatal(err)
	}
	return chain
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

func TestEnrollAuthorityRejectsLegacyAuthorityWithoutLedger(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	database, err := Open(filepath.Join(root, "canonical", "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.db.Exec(`
INSERT INTO events VALUES('event','capture',?,'2026-08-14T12:00:00Z','2026-08-14T12:00:00Z','{}','hash',NULL,'verified');
INSERT INTO nodes VALUES('node','judgment',?,'event');
INSERT INTO node_versions VALUES('version','node','{}','hash','captured','captured_judgment','{}','[]','2026-08-14T12:00:00Z',NULL,'2026-08-14T12:00:00Z',NULL,'event',NULL);
`, operator, operator); err != nil {
		t.Fatal(err)
	}
	event, privateKey, blob := storeEnrollmentFixture(t, database, operator)
	if _, err := database.EnrollAuthority(context.Background(), root, event, privateKey, blob, time.Now()); err == nil || err.Error() != "store has authority-bearing data but no verifiable authority ledger" {
		t.Fatalf("err=%v", err)
	}
	var ledger int
	if err := database.db.QueryRow(`SELECT COUNT(*) FROM authority_ledger`).Scan(&ledger); err != nil || ledger != 0 {
		t.Fatalf("ledger=%d err=%v", ledger, err)
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

func TestEnrollAuthorityWithRecoveryPublishesBundleBeforeActivation(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	dataRoot := filepath.Join(root, "data")
	destination := filepath.Join(root, "offline", "recovery.json")
	operator, _ := urn.New("operator")
	database, err := Open(filepath.Join(dataRoot, "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	plan, now := storeRecoveryEnrollmentFixture(t, database, operator)
	defer plan.Clear()
	result, err := database.EnrollAuthorityWithRecovery(
		context.Background(), dataRoot, plan.Event, plan.PrivateKey, plan.KeyBlob,
		RecoveryEnrollmentPublication{Destination: destination, EncryptedRecoveryKey: plan.EncryptedRecoveryKey}, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.RecoveryBundle == nil || result.Trust.RecoveryKeyID == nil || *result.Trust.RecoveryKeyID != plan.Event.RecoveryBinding.KeyID {
		t.Fatalf("result=%#v", result)
	}
	raw, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := authority.VerifyRecoveryBundle(raw, now, true)
	if err != nil || verified.Manifest.RecoveryKeyID != plan.Event.RecoveryBinding.KeyID {
		t.Fatalf("verified=%#v err=%v", verified, err)
	}
	if journal, err := authority.LoadRecoveryPublicationJournal(dataRoot); err != nil || journal != nil {
		t.Fatalf("journal=%#v err=%v", journal, err)
	}
}

func TestRecoveryEnrollmentRetainsJournalAndBundleWhenCommitFails(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	dataRoot := filepath.Join(root, "data")
	destination := filepath.Join(root, "offline", "recovery.json")
	operator, _ := urn.New("operator")
	database, err := Open(filepath.Join(dataRoot, "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.db.Exec(`
CREATE TABLE recovery_commit_guard(id TEXT PRIMARY KEY);
CREATE TABLE recovery_commit_failure(id TEXT REFERENCES recovery_commit_guard(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER recovery_test_deferred_failure AFTER INSERT ON authority_checkpoint_pins
BEGIN INSERT INTO recovery_commit_failure VALUES('missing'); END;
`); err != nil {
		t.Fatal(err)
	}
	plan, now := storeRecoveryEnrollmentFixture(t, database, operator)
	defer plan.Clear()
	if _, err := database.EnrollAuthorityWithRecovery(
		context.Background(), dataRoot, plan.Event, plan.PrivateKey, plan.KeyBlob,
		RecoveryEnrollmentPublication{Destination: destination, EncryptedRecoveryKey: plan.EncryptedRecoveryKey}, now,
	); err == nil {
		t.Fatal("accepted recovery enrollment whose SQLite commit failed")
	}
	journal, err := authority.LoadRecoveryPublicationJournal(dataRoot)
	if err != nil || journal == nil || journal.Destination != destination {
		t.Fatalf("journal=%#v err=%v", journal, err)
	}
	if raw, err := os.ReadFile(destination); err != nil {
		t.Fatal("external recovery bundle was not retained:", err)
	} else if _, err := authority.VerifyRecoveryBundle(raw, now, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataRoot, filepath.FromSlash(plan.Event.BlobRelativePath))); !os.IsNotExist(err) {
		t.Fatalf("uncommitted machine key remained active: %v", err)
	}
	quarantined, _ := filepath.Glob(filepath.Join(dataRoot, "authority", "quarantine", "orphan-*.blob"))
	if len(quarantined) != 1 {
		t.Fatalf("quarantined=%v", quarantined)
	}
	var ledger, keys, anchors, pins int
	if err := database.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM authority_ledger),
		(SELECT COUNT(*) FROM authority_keys),
		(SELECT COUNT(*) FROM authority_trust_anchor),
		(SELECT COUNT(*) FROM authority_checkpoint_pins)`,
	).Scan(&ledger, &keys, &anchors, &pins); err != nil {
		t.Fatal(err)
	}
	if ledger != 0 || keys != 0 || anchors != 0 || pins != 0 {
		t.Fatalf("ledger=%d keys=%d anchors=%d pins=%d", ledger, keys, anchors, pins)
	}
}

func storeRecoveryEnrollmentFixture(t *testing.T, database *Store, operator string) (authority.RecoveryEnrollmentPlan, time.Time) {
	t.Helper()
	storeIdentity, err := database.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	randomBytes := make([]byte, 264)
	for index := range randomBytes {
		randomBytes[index] = byte(index)
	}
	now := time.Date(2026, 8, 14, 12, 15, 0, 0, time.UTC)
	plan, err := authority.PrepareEnrollmentWithRecovery(
		operator, storeIdentity, "authority-passphrase", "recovery-passphrase",
		now, bytes.NewReader(randomBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan, now
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
