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
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"--config", configPath, "spool", "prune", "--retention-days", "36500"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("spool prune code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"retained":1`) || !strings.Contains(stdout.String(), `"deleted":0`) {
		t.Fatalf("spool prune stdout=%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(operatorRoot, "imprint.db")); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"--config", configPath, "store", "recover"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("store recover code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"clean"`) || !strings.Contains(stdout.String(), `"integrity":"ok"`) {
		t.Fatalf("store recover stdout=%s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"--config", configPath, "derive", "--capture", eventPath}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("derive capture code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"queued"`) || !strings.Contains(stdout.String(), `"producer":"imprint-reference-deriver"`) {
		t.Fatalf("derive capture stdout=%s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"--config", configPath, "derive", "--pending"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("derive pending code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"applied":1`) {
		t.Fatalf("derive pending stdout=%s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"--config", configPath, "derive", "--pending"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("derive replay code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"skipped":1`) {
		t.Fatalf("derive replay stdout=%s", stdout.String())
	}
	exportPath := filepath.Join(temporary, "imprint.md")
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"--config", configPath, "export", "--format", "markdown", "--output", exportPath}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("export code=%d stderr=%s", code, stderr.String())
	}
	markdown, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markdown), "# Imprint") || !strings.Contains(string(markdown), envelope.Verdict.RawOperatorText) {
		t.Fatalf("markdown=%s", markdown)
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
	stdout.Reset()
	stderr.Reset()
	retrieveArgs := []string{"--config", configPath, "retrieve", "--session", "test-session"}
	if code := Run(retrieveArgs, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("retrieve stderr=%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"delivered"`) {
		t.Fatalf("retrieve stdout=%s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run(retrieveArgs, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("repeat stderr=%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"already_delivered"`) {
		t.Fatalf("repeat stdout=%s", stdout.String())
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

func TestReadHooksDeliverOnceRefreshAndSelectDomain(t *testing.T) {
	temporary, _ := filepath.EvalSymlinks(t.TempDir())
	configPath := filepath.Join(temporary, "config.json")
	dataRoot := filepath.Join(temporary, "data")
	configuration := map[string]any{
		"data_root":     dataRoot,
		"operator_slug": "read-hooks",
		"domains": []map[string]any{{
			"domain_id": "research", "public_label": "Research",
			"safe_paths": []string{"Projects/Research"}, "keywords": []string{"sources"},
		}},
	}
	raw, _ := json.Marshal(configuration)
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	runHook := func(action, event string) map[string]any {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"--config", configPath, "hook", action}, strings.NewReader(event), &stdout, &stderr); code != 0 {
			t.Fatalf("%s code=%d stdout=%s stderr=%s", action, code, stdout.String(), stderr.String())
		}
		var response map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
			t.Fatalf("%s invalid response %q: %v", action, stdout.String(), err)
		}
		return response
	}

	sessionEvent := `{"hook_event_name":"SessionStart","session_id":"native-read-session"}`
	if response := runHook("session-start", sessionEvent); response["status"] != "delivered" {
		t.Fatalf("first session response=%#v", response)
	}
	if response := runHook("session-start", sessionEvent); response["status"] != "already_delivered" {
		t.Fatalf("repeat session response=%#v", response)
	}
	compactEvent := `{"hook_event_name":"SessionStart","session_id":"native-read-session","source":"compact"}`
	if response := runHook("session-start", compactEvent); response["status"] != "delivered" {
		t.Fatalf("compact session response=%#v", response)
	}

	domainEvent := `{"hook_event_name":"UserPromptSubmit","session_id":"native-domain-session","cwd":"Projects/Research/Now","prompt":"Review these sources"}`
	response := runHook("user-prompt-submit", domainEvent)
	if response["status"] != "delivered" || response["domain_id"] != "research" || response["selection_method"] != "path" {
		t.Fatalf("domain response=%#v", response)
	}
	if response := runHook("user-prompt-submit", domainEvent); response["status"] != "already_delivered" {
		t.Fatalf("repeat domain response=%#v", response)
	}
	unmatched := `{"hook_event_name":"UserPromptSubmit","session_id":"native-unmatched-session","cwd":"Projects/Other","prompt":"Unrelated work"}`
	if response := runHook("user-prompt-submit", unmatched); response["status"] != "skipped" || response["reason"] != "domain_no_match" {
		t.Fatalf("unmatched response=%#v", response)
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
