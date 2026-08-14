package capture

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/artemus/imprint/internal/urn"
)

func validOptions(t *testing.T) BuildOptions {
	t.Helper()
	operator, _ := urn.New("operator")
	session, _ := urn.New("session")
	reason := "it is easier to scan"
	return BuildOptions{OperatorID: operator, SessionID: session, NodeID: "node-alpha", CaseDescription: "A synthetic draft used the first layout.", RawOperatorText: "Use the second layout instead because it is easier to scan.", CallType: "correct", CaptureMechanism: "explicit_cli", CapturedBy: "test-hook/3.0.0", Reason: &reason, ReasonStatus: "supplied", Chosen: []AlternativeInput{{Description: "second layout"}}, Rejected: []AlternativeInput{{Description: "first layout"}}}
}

func TestBuildCompleteEnvelope(t *testing.T) {
	value, err := Build(validOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(value.Alternatives) != 2 || value.Alternatives[0].Disposition != "chosen" || value.Provenance.Model != nil {
		t.Fatalf("unexpected envelope: %#v", value)
	}
	if value.Evidence[0].Content != value.Verdict.RawOperatorText {
		t.Fatal("verbatim evidence lost")
	}
}

func TestReasonAndTamperValidation(t *testing.T) {
	options := validOptions(t)
	options.Reason = nil
	if _, err := Build(options); err == nil || !strings.Contains(err.Error(), "cannot be null") {
		t.Fatalf("unexpected error: %v", err)
	}
	value, err := Build(validOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	value.Evidence[0].Content = "tampered"
	if err := value.Validate(); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNamespacedExtensionAndStrictDecode(t *testing.T) {
	options := validOptions(t)
	options.Extensions = map[string]Extension{"org.example.synthetic": {SchemaVersion: "1.0.0", Payload: json.RawMessage(`{"flag":true}`)}}
	value, err := Build(options)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(value)
	if _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["extra"] = "closed"
	raw, _ = json.Marshal(object)
	if _, err := Decode(raw); err == nil {
		t.Fatal("accepted unknown top-level field")
	}
}

func TestOversizedInputRejected(t *testing.T) {
	options := validOptions(t)
	options.RawOperatorText = strings.Repeat("x", maxTextBytes+1)
	if _, err := Build(options); err == nil || !strings.Contains(err.Error(), "oversized") {
		t.Fatalf("unexpected error: %v", err)
	}
}
