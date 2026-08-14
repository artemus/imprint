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
	if code := Run([]string{"version"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "3.2.0-dev") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"nope"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
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
	if code := Run([]string{"--config", configPath, "capture", "--event", eventPath}, strings.NewReader(""), &stdout, &stderr); code != 0 {
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
	if code := Run([]string{"--config", configPath, "compile", "--once"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
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
		if code := Run(arguments, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("%v code=%d stderr=%s", command, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"status":`) {
			t.Fatalf("%v stdout=%s", command, stdout.String())
		}
	}
}

func TestStopHookPersistsBeforeReturningQueued(t *testing.T) {
	temporary, _ := filepath.EvalSymlinks(t.TempDir())
	dataRoot := filepath.Join(temporary, "data")
	configPath := filepath.Join(temporary, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"data_root":"`+dataRoot+`","operator_slug":"hook-test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	event := `{"hook_event_name":"Stop","session_id":"native-private-id","operator_text":"No, use the compact version instead.","case_description":"Reviewing a draft"}`
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--config", configPath, "hook", "stop-capture"}, strings.NewReader(event), &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"canonical_status":"compiled"`) {
		t.Fatalf("stdout=%s", stdout.String())
	}
	root := filepath.Join(dataRoot, "hook-test")
	entries, err := filepath.Glob(filepath.Join(root, "spool", "primary", "*.json"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	key, err := os.ReadFile(filepath.Join(root, "session-map.key"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(key), "native-private-id") {
		t.Fatal("native session id persisted")
	}
}

func TestRepeatedStopFailureDoesNotLoop(t *testing.T) {
	var stdout, stderr bytes.Buffer
	event := `{"hook_schema_version":"9.0.0","stop_hook_active":true}`
	if code := Run([]string{"hook", "stop-capture"}, strings.NewReader(event), &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stdout.String(), `"failure_policy":"fail_closed"`) {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestStopHookMinesTranscript(t *testing.T) {
	temporary, _ := filepath.EvalSymlinks(t.TempDir())
	configPath := filepath.Join(temporary, "config.json")
	dataRoot := filepath.Join(temporary, "data")
	if err := os.WriteFile(configPath, []byte(`{"data_root":"`+dataRoot+`","operator_slug":"transcript-test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	transcriptPath := filepath.Join(temporary, "transcript.jsonl")
	transcriptRaw := "{\"type\":\"assistant\",\"message\":{\"content\":\"I omitted a source.\"}}\n{\"type\":\"user\",\"message\":{\"content\":\"No, explicitly report every failed source.\"}}\n"
	if err := os.WriteFile(transcriptPath, []byte(transcriptRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	event := `{"hook_event_name":"Stop","session_id":"native","transcript_path":"` + transcriptPath + `"}`
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--config", configPath, "hook", "stop-capture"}, strings.NewReader(event), &stdout, &stderr); code != 0 {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	spools, _ := filepath.Glob(filepath.Join(dataRoot, "transcript-test", "spool", "primary", "*.json"))
	if len(spools) != 1 {
		t.Fatalf("spools=%v", spools)
	}
	raw, err := os.ReadFile(spools[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "explicitly report every failed source") || !strings.Contains(string(raw), "I omitted a source") {
		t.Fatalf("spool=%s", raw)
	}
}
