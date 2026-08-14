package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/artemus/imprint/internal/authority"
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

func TestRecoveryEnrollmentCeremonyConfirmsExactGenesisAndPublishesBundle(t *testing.T) {
	temporary, configPath, operatorRoot := enrollmentTestRuntime(t)
	destination := filepath.Join(temporary, "offline", "recovery.json")
	console := &enrollmentConsole{
		lines:   []string{"ENROLL WITH-RECOVERY", "BIND INITIAL AUTHORITY"},
		secrets: []string{"authority-passphrase", "authority-passphrase", "recovery-passphrase", "recovery-passphrase"},
	}
	var stdout, stderr bytes.Buffer
	code := runAuthorityEnrollmentWithRecovery(
		context.Background(), configPath, destination, strings.NewReader(""), &stdout, &stderr,
		console, time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC), bytes.NewReader(deterministicEnrollmentRandom()),
	)
	if code != 0 || !console.required || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var response struct {
		Recovery       string `json:"recovery"`
		RecoveryBundle struct {
			Path         string `json:"path"`
			BundleSHA256 string `json:"bundle_sha256"`
		} `json:"recovery_bundle"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := authority.VerifyRecoveryBundle(raw, time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC), true)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(verified.Ledger[0].EventJSON))
	ceremony := console.writes.String()
	if response.Recovery != "created" || response.RecoveryBundle.Path != destination || response.RecoveryBundle.BundleSHA256 == "" {
		t.Fatalf("response=%#v", response)
	}
	if !strings.Contains(ceremony, verified.Ledger[0].EventJSON) || !strings.Contains(ceremony, "Transition SHA-256: "+hex.EncodeToString(digest[:])) {
		t.Fatalf("ceremony did not bind exact genesis: %s", ceremony)
	}
	if _, err := os.Stat(filepath.Join(operatorRoot, "authority", "recovery-publication.json")); !os.IsNotExist(err) {
		t.Fatalf("publication journal remained after activation: %v", err)
	}
}

func TestRecoveryEnrollmentCeremonyRejectsWrongBindingConfirmation(t *testing.T) {
	temporary, configPath, _ := enrollmentTestRuntime(t)
	destination := filepath.Join(temporary, "offline", "recovery.json")
	console := &enrollmentConsole{
		lines:   []string{"ENROLL WITH-RECOVERY", "BIND SOMETHING ELSE"},
		secrets: []string{"authority-passphrase", "authority-passphrase", "recovery-passphrase", "recovery-passphrase"},
	}
	var stdout, stderr bytes.Buffer
	code := runAuthorityEnrollmentWithRecovery(
		context.Background(), configPath, destination, strings.NewReader(""), &stdout, &stderr,
		console, time.Now(), bytes.NewReader(deterministicEnrollmentRandom()),
	)
	if code != 2 || !strings.Contains(stderr.String(), "initial authority and recovery binding was not confirmed") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("recovery bundle was published without exact confirmation: %v", err)
	}
}

func enrollmentTestRuntime(t *testing.T) (temporary, configPath, operatorRoot string) {
	t.Helper()
	temporary, _ = filepath.EvalSymlinks(t.TempDir())
	dataRoot := filepath.Join(temporary, "data")
	operatorRoot = filepath.Join(dataRoot, "default")
	if err := os.MkdirAll(operatorRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	operatorID, _ := urn.New("operator")
	identityJSON := `{"identity_schema_version":"1.0.0","operator_id":"` + operatorID + `"}`
	if err := os.WriteFile(filepath.Join(operatorRoot, "identity.json"), []byte(identityJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath = filepath.Join(temporary, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"data_root":"`+dataRoot+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return temporary, configPath, operatorRoot
}

func deterministicEnrollmentRandom() []byte {
	result := make([]byte, 264)
	for index := range result {
		result[index] = byte(index)
	}
	return result
}
