package authority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const PreparedMutationTTL = 24 * time.Hour

type ChallengeRequest struct {
	OperationID           string   `json:"operation_id"`
	Purpose               string   `json:"purpose"`
	PayloadSHA256         string   `json:"payload_sha256"`
	PriorStateSHA256      string   `json:"prior_state_sha256"`
	ExecutionFieldsSHA256 string   `json:"execution_fields_sha256"`
	AuthorityTransition   string   `json:"authority_transition"`
	SubjectIDs            []string `json:"subject_ids"`
	SourceIDs             []string `json:"source_ids"`
	TargetIDs             []string `json:"target_ids"`
	ProposalIDs           []string `json:"proposal_ids"`
	ResultVersionIDs      []string `json:"result_version_ids"`
	Scope                 []string `json:"scope"`
	FieldPaths            []string `json:"field_paths"`
}

type PreparedMutation struct {
	OperationID, CommandName, OperatorID       string
	RequestJSON, RequestSHA256                 string
	IntentJSON, IntentSHA256                   string
	PriorStateJSON, PriorStateSHA256           string
	ExecutionFieldsJSON, ExecutionFieldsSHA256 string
	CreatedAt, ExpiresAt, Status               string
	ExecutedAt, ProvenanceID                   *string
}

var challengeRequestFields = []string{"operation_id", "purpose", "payload_sha256", "prior_state_sha256", "execution_fields_sha256", "authority_transition", "subject_ids", "source_ids", "target_ids", "proposal_ids", "result_version_ids", "scope", "field_paths"}

func (request ChallengeRequest) Validate() error {
	if request.OperationID == "" || request.Purpose == "" || request.AuthorityTransition == "" {
		return errors.New("authority request contains an empty required field")
	}
	for _, digest := range []string{request.PayloadSHA256, request.PriorStateSHA256, request.ExecutionFieldsSHA256} {
		if !lowercaseSHA256.MatchString(digest) {
			return errors.New("authority request digest must be lowercase SHA-256")
		}
	}
	for _, values := range [][]string{request.SubjectIDs, request.SourceIDs, request.TargetIDs, request.ProposalIDs, request.ResultVersionIDs, request.Scope, request.FieldPaths} {
		if !uniqueNonempty(values) {
			return errors.New("authority request contains an invalid string list")
		}
	}
	return nil
}

func RequestFromChallenge(challenge Challenge) ChallengeRequest {
	return ChallengeRequest{
		OperationID: challenge.OperationID, Purpose: challenge.Purpose,
		PayloadSHA256: challenge.PayloadSHA256, PriorStateSHA256: challenge.PriorStateSHA256,
		ExecutionFieldsSHA256: challenge.ExecutionFieldsSHA256,
		AuthorityTransition:   challenge.AuthorityTransition,
		SubjectIDs:            nonNilStrings(challenge.SubjectIDs), SourceIDs: nonNilStrings(challenge.SourceIDs),
		TargetIDs: nonNilStrings(challenge.TargetIDs), ProposalIDs: nonNilStrings(challenge.ProposalIDs),
		ResultVersionIDs: nonNilStrings(challenge.ResultVersionIDs), Scope: nonNilStrings(challenge.Scope),
		FieldPaths: nonNilStrings(challenge.FieldPaths),
	}
}

func (request ChallengeRequest) Matches(challenge Challenge) bool {
	if request.Validate() != nil || challenge.Validate() != nil {
		return false
	}
	left, leftErr := canonicalContract(normalizedRequest(request))
	right, rightErr := canonicalContract(RequestFromChallenge(challenge))
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func PrepareMutation(commandName string, request ChallengeRequest, intent, priorState, executionFields any, operatorID string, now time.Time) (PreparedMutation, error) {
	if err := request.Validate(); err != nil {
		return PreparedMutation{}, err
	}
	if commandName == "" {
		return PreparedMutation{}, errors.New("prepared mutation command is required")
	}
	executionJSON, executionSHA, err := canonicalJSONDigest(executionFields)
	if err != nil {
		return PreparedMutation{}, err
	}
	if request.ExecutionFieldsSHA256 != executionSHA {
		return PreparedMutation{}, errors.New("prepared mutation execution-fields digest mismatch")
	}
	requestJSON, requestSHA, err := canonicalJSONDigest(normalizedRequest(request))
	if err != nil {
		return PreparedMutation{}, err
	}
	intentJSON, intentSHA, err := canonicalJSONDigest(intent)
	if err != nil {
		return PreparedMutation{}, err
	}
	priorJSON, priorSHA, err := canonicalJSONDigest(priorState)
	if err != nil {
		return PreparedMutation{}, err
	}
	return PreparedMutation{
		OperationID: request.OperationID, CommandName: commandName, OperatorID: operatorID,
		RequestJSON: requestJSON, RequestSHA256: requestSHA,
		IntentJSON: intentJSON, IntentSHA256: intentSHA,
		PriorStateJSON: priorJSON, PriorStateSHA256: priorSHA,
		ExecutionFieldsJSON: executionJSON, ExecutionFieldsSHA256: executionSHA,
		CreatedAt: utcText(now), ExpiresAt: utcText(now.Add(PreparedMutationTTL)), Status: "pending",
	}, nil
}

func (prepared PreparedMutation) Verify(commandName, operatorID string, intent, priorState any, now time.Time) (ChallengeRequest, json.RawMessage, error) {
	if prepared.Status != "pending" {
		return ChallengeRequest{}, nil, errors.New("prepared mutation is not pending")
	}
	if prepared.CommandName != commandName || prepared.OperatorID != operatorID {
		return ChallengeRequest{}, nil, errors.New("authority token is for another command or operator")
	}
	expires, err := utcTimestamp(prepared.ExpiresAt)
	if err != nil || !now.UTC().Before(expires) {
		return ChallengeRequest{}, nil, errors.New("prepared mutation has expired")
	}
	intentJSON, _, err := canonicalJSONDigest(intent)
	if err != nil {
		return ChallengeRequest{}, nil, err
	}
	priorJSON, _, err := canonicalJSONDigest(priorState)
	if err != nil {
		return ChallengeRequest{}, nil, err
	}
	if intentJSON != prepared.IntentJSON || priorJSON != prepared.PriorStateJSON {
		return ChallengeRequest{}, nil, errors.New("prepared mutation intent or prior state changed")
	}
	for _, binding := range [][2]string{
		{prepared.RequestJSON, prepared.RequestSHA256}, {prepared.IntentJSON, prepared.IntentSHA256},
		{prepared.PriorStateJSON, prepared.PriorStateSHA256},
		{prepared.ExecutionFieldsJSON, prepared.ExecutionFieldsSHA256},
	} {
		if sha256Text(binding[0]) != binding[1] {
			return ChallengeRequest{}, nil, errors.New("prepared mutation stored digest mismatch")
		}
	}
	var request ChallengeRequest
	if decodeExactObject([]byte(prepared.RequestJSON), &request, challengeRequestFields) != nil || request.Validate() != nil {
		return ChallengeRequest{}, nil, errors.New("prepared mutation storage is corrupt")
	}
	var execution json.RawMessage
	if json.Unmarshal([]byte(prepared.ExecutionFieldsJSON), &execution) != nil {
		return ChallengeRequest{}, nil, errors.New("prepared mutation storage is corrupt")
	}
	if request.ExecutionFieldsSHA256 != prepared.ExecutionFieldsSHA256 {
		return ChallengeRequest{}, nil, errors.New("signed request does not bind prepared execution fields")
	}
	return request, execution, nil
}

func normalizedRequest(request ChallengeRequest) ChallengeRequest {
	request.SubjectIDs = nonNilStrings(request.SubjectIDs)
	request.SourceIDs = nonNilStrings(request.SourceIDs)
	request.TargetIDs = nonNilStrings(request.TargetIDs)
	request.ProposalIDs = nonNilStrings(request.ProposalIDs)
	request.ResultVersionIDs = nonNilStrings(request.ResultVersionIDs)
	request.Scope = nonNilStrings(request.Scope)
	request.FieldPaths = nonNilStrings(request.FieldPaths)
	return request
}

func nonNilStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}

func canonicalJSONDigest(value any) (string, string, error) {
	encoded, err := canonicalContract(value)
	if err != nil {
		return "", "", err
	}
	text := string(encoded)
	return text, sha256Text(text), nil
}

func sha256Text(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func utcText(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000Z")
}
