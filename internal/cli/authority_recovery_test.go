package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/artemus/imprint/internal/authority"
)

func TestRecoveryReconcileClearsOnlyConfirmedJournal(t *testing.T) {
	temporary, configPath, operatorRoot := enrollmentTestRuntime(t)
	destination := filepath.Join(temporary, "offline", "recovery.json")
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("retained bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := authority.CreateRecoveryPublicationJournal(operatorRoot, destination, "urn:imprint:authority-key:recovery", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	console := &enrollmentConsole{lines: []string{"ABANDON INTERRUPTED RECOVERY"}}
	var stdout, stderr bytes.Buffer
	if code := runAuthorityRecoveryReconcile(configPath, strings.NewReader(""), &stdout, &stderr, console); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(console.writes.String(), journal.OperationID) || !strings.Contains(stdout.String(), `"retained_destination":"`+destination+`"`) {
		t.Fatalf("ceremony=%s stdout=%s", console.writes.String(), stdout.String())
	}
	if loaded, err := authority.LoadRecoveryPublicationJournal(operatorRoot); err != nil || loaded != nil {
		t.Fatalf("journal=%#v err=%v", loaded, err)
	}
	if raw, err := os.ReadFile(destination); err != nil || string(raw) != "retained bundle" {
		t.Fatalf("retained bundle changed: %q err=%v", raw, err)
	}
}

func TestRecoveryReconcileKeepsJournalWithoutExactConfirmation(t *testing.T) {
	temporary, configPath, operatorRoot := enrollmentTestRuntime(t)
	destination := filepath.Join(temporary, "offline", "recovery.json")
	if _, err := authority.CreateRecoveryPublicationJournal(operatorRoot, destination, "urn:imprint:authority-key:recovery", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	console := &enrollmentConsole{lines: []string{"ABANDON"}}
	var stdout, stderr bytes.Buffer
	if code := runAuthorityRecoveryReconcile(configPath, strings.NewReader(""), &stdout, &stderr, console); code != 2 || !strings.Contains(stderr.String(), "was not confirmed") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if loaded, err := authority.LoadRecoveryPublicationJournal(operatorRoot); err != nil || loaded == nil {
		t.Fatalf("journal=%#v err=%v", loaded, err)
	}
}
