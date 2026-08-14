package proposal

import (
	"encoding/json"
	"testing"

	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/urn"
)

func TestFromCapturePreservesMissingReasonAndCannotEscalate(t *testing.T) {
	operatorID, _ := urn.New("operator")
	sessionID, _ := urn.New("session")
	envelope, err := capture.Build(capture.BuildOptions{OperatorID: operatorID, SessionID: sessionID, NodeID: "primary", CaseDescription: "Review", RawOperatorText: "No, use the compact form.", CallType: "correct", CaptureMechanism: "explicit_cli", CapturedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	value, err := FromCapture(envelope, "imprint-reference-deriver")
	if err != nil {
		t.Fatal(err)
	}
	if value.Type != "correction_without_reason" || value.Payload["reason"] != nil || value.Provenance.AuthorityTier != "observed_candidate" {
		t.Fatalf("proposal=%#v", value)
	}
	raw, _ := json.Marshal(value)
	var generic map[string]any
	_ = json.Unmarshal(raw, &generic)
	generic["payload"].(map[string]any)["database_path"] = "/tmp/imprint.db"
	malicious, _ := json.Marshal(generic)
	if _, err := Decode(malicious); err == nil {
		t.Fatal("accepted proposal with database path authority")
	}
	generic["payload"] = map[string]any{"reason": nil, "reason_status": "absent", "transition": "ratified"}
	malicious, _ = json.Marshal(generic)
	if _, err := Decode(malicious); err == nil {
		t.Fatal("accepted ratification transition in proposal payload")
	}
}
