package compiler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/spool"
	"github.com/artemus/imprint/internal/store"
	"github.com/artemus/imprint/internal/urn"
)

func TestCompileCommitsAndAcknowledgesSpool(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	session, _ := urn.New("session")
	value, err := capture.Build(capture.BuildOptions{OperatorID: operator, SessionID: session, NodeID: "primary", CaseDescription: "Reviewed", RawOperatorText: "Approved. Ship it.", CallType: "accept", CaptureMechanism: "explicit_cli", CapturedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	path, err := spool.Write(root, value)
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(root, "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	counts, err := Compile(context.Background(), root, database)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Captured != 1 || counts.Quarantined != 0 {
		t.Fatalf("counts=%#v", counts)
	}
	if _, err = os.Stat(ackPath(root, value)); err != nil {
		t.Fatal(err)
	}
	counts, err = Compile(context.Background(), root, database)
	if err != nil {
		t.Fatal(err)
	}
	if counts != (Counts{}) {
		t.Fatalf("second counts=%#v", counts)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("compiler removed immutable source")
	}
}

func TestCompileQuarantinesMalformedInput(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	operator, _ := urn.New("operator")
	directory := filepath.Join(root, "spool", "primary")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "bad.json"), []byte(`{"bad":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(root, "imprint.db"), operator, "primary")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	counts, err := Compile(context.Background(), root, database)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Quarantined != 1 {
		t.Fatalf("counts=%#v", counts)
	}
}
