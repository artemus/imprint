package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/urn"
)

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "3.2.0-dev") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"nope"}, &stdout, &stderr); code != 2 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestCaptureQueuesCompatibleEnvelope(t *testing.T) {
	temporary, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dataRoot := filepath.Join(temporary, "data")
	operatorID, _ := urn.New("operator")
	sessionID, _ := urn.New("session")
	operatorRoot := filepath.Join(dataRoot, "default")
	if err := os.MkdirAll(operatorRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := `{"identity_schema_version":"1.0.0","operator_id":"` + operatorID + `"}`
	if err := os.WriteFile(filepath.Join(operatorRoot, "identity.json"), []byte(identity), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(temporary, "config.json")
	configRaw := `{"data_root":"` + dataRoot + `"}`
	if err := os.WriteFile(configPath, []byte(configRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	envelope, err := capture.Build(capture.BuildOptions{OperatorID: operatorID, SessionID: sessionID, NodeID: "primary", CaseDescription: "Reviewed output", RawOperatorText: "No, use the compact version.", CallType: "correct", CaptureMechanism: "explicit_cli", CapturedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(temporary, "event.json")
	raw, _ := json.Marshal(envelope)
	if err := os.WriteFile(eventPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--config", configPath, "capture", "--event", eventPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"queued"`) {
		t.Fatalf("stdout=%s", stdout.String())
	}
	entries, err := os.ReadDir(filepath.Join(operatorRoot, "spool", "primary"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d", len(entries))
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"--config", configPath, "compile", "--once"}, &stdout, &stderr); code != 0 {
		t.Fatalf("compile code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"captured":1`) {
		t.Fatalf("compile stdout=%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(operatorRoot, "imprint.db")); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{{"whoami"}, {"health", "--deep"}, {"log", "--date", strings.Split(envelope.CapturedAt, "T")[0]}} {
		stdout.Reset()
		stderr.Reset()
		arguments := append([]string{"--config", configPath}, command...)
		if code := Run(arguments, &stdout, &stderr); code != 0 {
			t.Fatalf("%v code=%d stderr=%s", command, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"status":`) {
			t.Fatalf("%v stdout=%s", command, stdout.String())
		}
	}
}
