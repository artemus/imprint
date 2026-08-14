package retrieve

import (
	"context"
	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/store"
	"github.com/artemus/imprint/internal/urn"
	"path/filepath"
	"testing"
)

func TestFromStoreProjectsEvidenceAndCase(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	session, _ := urn.New("session")
	value, err := capture.Build(capture.BuildOptions{OperatorID: operator, SessionID: session, NodeID: "primary", CaseDescription: "Reviewing sources", RawOperatorText: "No, include the failed source.", CallType: "correct", CaptureMechanism: "explicit_cli", CapturedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(root, "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err = database.ApplyCapture(context.Background(), value, "direct"); err != nil {
		t.Fatal(err)
	}
	records, snapshot, err := FromStore(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot == "" || len(records) != 1 {
		t.Fatalf("snapshot=%q records=%#v", snapshot, records)
	}
	if !records[0].ProvenanceComplete || len(records[0].CaseReferents) != 1 {
		t.Fatalf("record=%#v", records[0])
	}
}
