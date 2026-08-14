package authority

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPrepareMutationFreezesExactCanonicalInputs(t *testing.T) {
	execution := map[string]any{"event_id": "urn:imprint:event:fixture", "sequence": 2}
	_, executionSHA, err := canonicalJSONDigest(execution)
	if err != nil {
		t.Fatal(err)
	}
	challenge := fixtureChallenge(t)
	challenge.ExecutionFieldsSHA256 = executionSHA
	request := RequestFromChallenge(challenge)
	now := time.Date(2026, 8, 14, 12, 0, 0, 123456789, time.UTC)
	prepared, err := PrepareMutation(
		"proposal-accept", request,
		map[string]any{"proposal_id": challenge.ProposalIDs[0]},
		map[string]any{"head": challenge.PriorStateSHA256}, execution,
		challenge.OperatorID, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Status != "pending" || prepared.CreatedAt != "2026-08-14T12:00:00.123456Z" || prepared.ExpiresAt != "2026-08-15T12:00:00.123456Z" {
		t.Fatalf("prepared=%#v", prepared)
	}
	loadedRequest, loadedExecution, err := prepared.Verify(
		"proposal-accept", challenge.OperatorID,
		map[string]any{"proposal_id": challenge.ProposalIDs[0]},
		map[string]any{"head": challenge.PriorStateSHA256}, now.Add(time.Hour),
	)
	if err != nil || !loadedRequest.Matches(challenge) {
		t.Fatalf("request=%#v err=%v", loadedRequest, err)
	}
	var loaded map[string]any
	if err := json.Unmarshal(loadedExecution, &loaded); err != nil || loaded["event_id"] != execution["event_id"] {
		t.Fatalf("execution=%s err=%v", loadedExecution, err)
	}

	tampered := prepared
	tampered.ExecutionFieldsJSON = `{"event_id":"forged","sequence":2}`
	if _, _, err = tampered.Verify("proposal-accept", challenge.OperatorID, map[string]any{"proposal_id": challenge.ProposalIDs[0]}, map[string]any{"head": challenge.PriorStateSHA256}, now.Add(time.Hour)); err == nil {
		t.Fatal("accepted modified prepared execution fields")
	}
	if _, _, err = prepared.Verify("proposal-accept", challenge.OperatorID, map[string]any{"proposal_id": "other"}, map[string]any{"head": challenge.PriorStateSHA256}, now.Add(time.Hour)); err == nil {
		t.Fatal("accepted changed prepared intent")
	}
	if _, _, err = prepared.Verify("proposal-accept", challenge.OperatorID, map[string]any{"proposal_id": challenge.ProposalIDs[0]}, map[string]any{"head": challenge.PriorStateSHA256}, now.Add(PreparedMutationTTL)); err == nil {
		t.Fatal("accepted expired prepared mutation")
	}
}

func TestChallengeRequestMatchesEverySignedMutationField(t *testing.T) {
	challenge := fixtureChallenge(t)
	request := RequestFromChallenge(challenge)
	if !request.Matches(challenge) {
		t.Fatal("exact request did not match challenge")
	}
	request.Scope = []string{"other"}
	if request.Matches(challenge) {
		t.Fatal("changed request scope matched challenge")
	}
	request = RequestFromChallenge(challenge)
	request.PayloadSHA256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if request.Matches(challenge) {
		t.Fatal("changed payload matched challenge")
	}
}

func TestPrepareMutationRejectsExecutionDigestMismatch(t *testing.T) {
	request := RequestFromChallenge(fixtureChallenge(t))
	if _, err := PrepareMutation("proposal-accept", request, map[string]any{}, map[string]any{}, map[string]any{}, "operator", time.Now()); err == nil {
		t.Fatal("accepted execution fields not bound by request")
	}
}
