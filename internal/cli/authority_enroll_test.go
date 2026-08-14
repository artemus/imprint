package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/artemus/imprint/internal/urn"
)

type enrollmentConsole struct {
	lines, secrets []string
	writes         strings.Builder
	required       bool
}

func (console *enrollmentConsole) RequireNative(io.Reader) error {
	console.required = true
	return nil
}
func (console *enrollmentConsole) Write(value string) error {
	console.writes.WriteString(value)
	return nil
}
func (console *enrollmentConsole) ReadLine(string) (string, error) {
	value := console.lines[0]
	console.lines = console.lines[1:]
	return value, nil
}
func (console *enrollmentConsole) ReadSecret(string) (string, error) {
	value := console.secrets[0]
	console.secrets = console.secrets[1:]
	return value, nil
}

func TestAuthorityEnrollmentCeremonyCommitsOnlyAfterExactConfirmation(t *testing.T) {
	temporary, _ := filepath.EvalSymlinks(t.TempDir())
	dataRoot := filepath.Join(temporary, "data")
	operatorRoot := filepath.Join(dataRoot, "default")
	if err := os.MkdirAll(operatorRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	operatorID, _ := urn.New("operator")
	identityJSON := `{"identity_schema_version":"1.0.0","operator_id":"` + operatorID + `"}`
	if err := os.WriteFile(filepath.Join(operatorRoot, "identity.json"), []byte(identityJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(temporary, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"data_root":"`+dataRoot+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	console := &enrollmentConsole{
		lines:   []string{"ENROLL DECLINE-RECOVERY"},
		secrets: []string{"fixture-passphrase", "fixture-passphrase"},
	}
	var stdout, stderr bytes.Buffer
	random := bytes.NewReader(make([]byte, 32+32+32+16+32+12))
	code := runAuthorityEnrollmentWithoutRecovery(
		context.Background(), configPath, strings.NewReader(""), &stdout, &stderr,
		console, time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC), random,
	)
	if code != 0 || !console.required || !strings.Contains(stdout.String(), `"recovery":"explicitly_declined"`) || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(console.writes.String(), "Installation: urn:imprint:installation:") {
		t.Fatalf("ceremony=%s", console.writes.String())
	}
	if _, err := os.Stat(filepath.Join(operatorRoot, "imprint.db")); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityEnrollmentCeremonyRejectsWrongConfirmation(t *testing.T) {
	temporary, _ := filepath.EvalSymlinks(t.TempDir())
	dataRoot := filepath.Join(temporary, "data")
	configPath := filepath.Join(temporary, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"data_root":"`+dataRoot+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	console := &enrollmentConsole{lines: []string{"ENROLL"}}
	var stdout, stderr bytes.Buffer
	code := runAuthorityEnrollmentWithoutRecovery(
		context.Background(), configPath, strings.NewReader(""), &stdout, &stderr,
		console, time.Now(), bytes.NewReader(make([]byte, 32)),
	)
	if code != 2 || !strings.Contains(stderr.String(), "authority enrollment was not confirmed") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}
