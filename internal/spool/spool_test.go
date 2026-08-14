package spool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/urn"
)

func TestWriteIsIdempotentAndRejectsConflict(t *testing.T) {
	operator, _ := urn.New("operator")
	session, _ := urn.New("session")
	value, err := capture.Build(capture.BuildOptions{OperatorID: operator, SessionID: session, NodeID: "primary", CaseDescription: "Reviewed a draft", RawOperatorText: "No, use the compact draft.", CallType: "correct", CaptureMechanism: "explicit_cli", CapturedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	first, err := Write(root, value)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Write(root, value)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("idempotent path changed")
	}
	raw, _ := os.ReadFile(first)
	if !strings.HasSuffix(string(raw), "\n") {
		t.Fatal("spool lacks newline")
	}
	value.Case.Description = "different"
	if _, err := Write(root, value); err == nil || !strings.Contains(err.Error(), "different bytes") {
		t.Fatalf("unexpected conflict: %v", err)
	}
}
