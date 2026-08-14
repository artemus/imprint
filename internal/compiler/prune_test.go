package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/spool"
	"github.com/artemus/imprint/internal/urn"
)

func TestPruneAcknowledgedRequiresExactOldCommitProof(t *testing.T) {
	root := resolvedTemp(t)
	clock := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	envelope := pruneEnvelope(t)
	path, err := spool.Write(root, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAcknowledgement(root, path, envelope, "captured"); err != nil {
		t.Fatal(err)
	}
	setAcknowledgedAt(t, ackPath(root, envelope), clock.Add(-31*24*time.Hour))

	counts, err := PruneAcknowledged(root, envelope.NodeID, 30, clock)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Deleted != 1 || counts.AcknowledgementsDeleted != 1 || counts.Invalid != 0 {
		t.Fatalf("counts=%#v", counts)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("source still exists: %v", err)
	}
}

func TestPruneRejectsTamperedSourceAndCleansLegacyAcknowledgement(t *testing.T) {
	root := resolvedTemp(t)
	clock := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	envelope := pruneEnvelope(t)
	path, _ := spool.Write(root, envelope)
	if err := writeAcknowledgement(root, path, envelope, "captured"); err != nil {
		t.Fatal(err)
	}
	setAcknowledgedAt(t, ackPath(root, envelope), clock.Add(-31*24*time.Hour))
	if err := os.WriteFile(path, append([]byte(" "), mustCanonical(t, envelope)...), 0o600); err != nil {
		t.Fatal(err)
	}
	counts, err := PruneAcknowledged(root, envelope.NodeID, 30, clock)
	if err != nil || counts.Invalid != 1 || counts.Deleted != 0 {
		t.Fatalf("counts=%#v err=%v", counts, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("tampered source was removed: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	counts, err = PruneAcknowledged(root, envelope.NodeID, 30, clock)
	if err != nil || counts.AlreadyPruned != 1 || counts.AcknowledgementsDeleted != 1 {
		t.Fatalf("legacy counts=%#v err=%v", counts, err)
	}
}

func TestPruneQuarantineDeletesOnlyClosedOldReceipts(t *testing.T) {
	root := resolvedTemp(t)
	directory := filepath.Join(root, "quarantine")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	old := map[string]any{"quarantine_schema_version": "1.0.0", "receipt_id": "old", "error_type": "ValidationError", "content_included": false, "recorded_at": clock.Add(-31 * 24 * time.Hour).Format(time.RFC3339Nano)}
	invalid := map[string]any{"quarantine_schema_version": "1.0.0", "receipt_id": "invalid", "error_type": "ValidationError", "content_included": true, "recorded_at": clock.Add(-31 * 24 * time.Hour).Format(time.RFC3339Nano)}
	for name, value := range map[string]any{"old.json": old, "invalid.json": invalid} {
		raw, _ := canonical.JSON(value)
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := PruneAcknowledged(root, "primary", 30, clock)
	if err != nil || counts.QuarantineDeleted != 1 || counts.Invalid != 1 {
		t.Fatalf("counts=%#v err=%v", counts, err)
	}
	if _, err := os.Stat(filepath.Join(directory, "invalid.json")); err != nil {
		t.Fatalf("invalid receipt was removed: %v", err)
	}
}

func pruneEnvelope(t *testing.T) capture.Envelope {
	t.Helper()
	operatorID, _ := urn.New("operator")
	sessionID, _ := urn.New("session")
	envelope, err := capture.Build(capture.BuildOptions{OperatorID: operatorID, SessionID: sessionID, NodeID: "primary", CaseDescription: "Review", RawOperatorText: "No, keep the source.", CallType: "correct", CaptureMechanism: "explicit_cli", CapturedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func resolvedTemp(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func setAcknowledgedAt(t *testing.T, path string, value time.Time) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ack map[string]any
	if err := json.Unmarshal(raw, &ack); err != nil {
		t.Fatal(err)
	}
	ack["acknowledged_at"] = value.Format(time.RFC3339Nano)
	raw, _ = canonical.JSON(ack)
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := canonical.JSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}
