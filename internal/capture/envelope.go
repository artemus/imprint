package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/artemus/imprint/internal/urn"
)

const (
	RecordSchemaVersion = "3.0.0"
	MaxEventBytes       = 1024 * 1024
	maxTextBytes        = 256 * 1024
)

var nodeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type Envelope struct {
	RecordSchemaVersion string               `json:"record_schema_version"`
	InputEventID        string               `json:"input_event_id"`
	OperatorID          string               `json:"operator_id"`
	SessionID           string               `json:"session_id"`
	NodeID              string               `json:"node_id"`
	CapturedAt          string               `json:"captured_at"`
	CaptureMechanism    string               `json:"capture_mechanism"`
	Case                Case                 `json:"case"`
	Verdict             Verdict              `json:"verdict"`
	Alternatives        []Alternative        `json:"alternatives"`
	Evidence            []Evidence           `json:"evidence"`
	Provenance          Provenance           `json:"provenance"`
	Extensions          map[string]Extension `json:"extensions"`
}

type Case struct {
	ID           string   `json:"case_id"`
	Description  string   `json:"description"`
	ArtifactRefs []string `json:"artifact_refs"`
	SourceRefs   []string `json:"source_refs"`
}

type Verdict struct {
	ID                     string   `json:"verdict_id"`
	RawOperatorText        string   `json:"raw_operator_text"`
	Call                   Call     `json:"call"`
	ChosenAlternativeIDs   []string `json:"chosen_alternative_ids"`
	RejectedAlternativeIDs []string `json:"rejected_alternative_ids"`
	Reason                 *string  `json:"reason"`
	ReasonStatus           string   `json:"reason_status"`
}

type Call struct {
	ID   string `json:"call_id"`
	Type string `json:"call_type"`
}
type Alternative struct {
	ID          string `json:"alternative_id"`
	Description string `json:"description"`
	Disposition string `json:"disposition"`
}
type Evidence struct {
	ID            string `json:"evidence_id"`
	Kind          string `json:"kind"`
	Content       string `json:"content"`
	SHA256        string `json:"content_sha256"`
	SourceLocator string `json:"source_locator"`
}
type Provenance struct {
	Status        string   `json:"status"`
	AuthorityTier string   `json:"authority_tier"`
	ActorClass    string   `json:"actor_class"`
	ActorID       string   `json:"actor_id"`
	CapturedBy    string   `json:"captured_by"`
	Model         *string  `json:"model"`
	EvidenceIDs   []string `json:"evidence_ids"`
}
type Extension struct {
	SchemaVersion string          `json:"schema_version"`
	Payload       json.RawMessage `json:"payload"`
}

type AlternativeInput struct{ ID, Description string }
type EvidenceInput struct{ ID, Kind, Content, SourceLocator string }
type BuildOptions struct {
	OperatorID, SessionID, NodeID, CaseDescription, RawOperatorText string
	CallType, CaptureMechanism, CapturedBy                          string
	Reason                                                          *string
	ReasonStatus                                                    string
	Chosen, Rejected                                                []AlternativeInput
	ArtifactRefs                                                    []string
	ContextualEvidence                                              []EvidenceInput
	InputEventID, CapturedAt                                        string
	Extensions                                                      map[string]Extension
}

func Build(options BuildOptions) (Envelope, error) {
	reasonStatus := options.ReasonStatus
	if reasonStatus == "" {
		if options.Reason == nil {
			reasonStatus = "absent"
		} else {
			reasonStatus = "supplied"
		}
	}
	if options.Reason == nil && (reasonStatus == "supplied" || reasonStatus == "later_added") {
		return Envelope{}, errors.New("a supplied/later_added reason cannot be null")
	}
	if options.Reason != nil && reasonStatus != "supplied" && reasonStatus != "later_added" {
		return Envelope{}, errors.New("reason text requires supplied or later_added status")
	}
	inputEventID, err := optionalURN(options.InputEventID, "event")
	if err != nil {
		return Envelope{}, err
	}
	caseID, err := urn.New("case")
	if err != nil {
		return Envelope{}, err
	}
	verdictID, err := urn.New("verdict")
	if err != nil {
		return Envelope{}, err
	}
	callID, err := urn.New("call")
	if err != nil {
		return Envelope{}, err
	}
	capturedAt := options.CapturedAt
	if capturedAt == "" {
		capturedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	chosen, chosenIDs, err := buildAlternatives(options.Chosen, "chosen")
	if err != nil {
		return Envelope{}, err
	}
	rejected, rejectedIDs, err := buildAlternatives(options.Rejected, "rejected")
	if err != nil {
		return Envelope{}, err
	}
	verbatimID, err := urn.New("evidence")
	if err != nil {
		return Envelope{}, err
	}
	evidence := []Evidence{{ID: verbatimID, Kind: "operator_verbatim", Content: options.RawOperatorText, SHA256: digest(options.RawOperatorText), SourceLocator: "capture:" + options.SessionID}}
	for _, input := range options.ContextualEvidence {
		id, err := optionalURN(input.ID, "evidence")
		if err != nil {
			return Envelope{}, err
		}
		kind := input.Kind
		if kind == "" {
			kind = "context"
		}
		evidence = append(evidence, Evidence{ID: id, Kind: kind, Content: input.Content, SHA256: digest(input.Content), SourceLocator: input.SourceLocator})
	}
	evidenceIDs := make([]string, len(evidence))
	for index := range evidence {
		evidenceIDs[index] = evidence[index].ID
	}
	extensions := options.Extensions
	if extensions == nil {
		extensions = map[string]Extension{}
	}
	envelope := Envelope{
		RecordSchemaVersion: RecordSchemaVersion, InputEventID: inputEventID,
		OperatorID: options.OperatorID, SessionID: options.SessionID, NodeID: options.NodeID,
		CapturedAt: capturedAt, CaptureMechanism: options.CaptureMechanism,
		Case:         Case{ID: caseID, Description: options.CaseDescription, ArtifactRefs: nonNil(options.ArtifactRefs), SourceRefs: evidenceIDs},
		Verdict:      Verdict{ID: verdictID, RawOperatorText: options.RawOperatorText, Call: Call{ID: callID, Type: options.CallType}, ChosenAlternativeIDs: chosenIDs, RejectedAlternativeIDs: rejectedIDs, Reason: options.Reason, ReasonStatus: reasonStatus},
		Alternatives: append(chosen, rejected...), Evidence: evidence,
		Provenance: Provenance{Status: "captured", AuthorityTier: "observed_candidate", ActorClass: "software", ActorID: options.CapturedBy, CapturedBy: options.CapturedBy, Model: nil, EvidenceIDs: evidenceIDs},
		Extensions: extensions,
	}
	return envelope, envelope.Validate()
}

func Decode(raw []byte) (Envelope, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var value Envelope
	if err := decoder.Decode(&value); err != nil {
		return Envelope{}, fmt.Errorf("decode capture envelope: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Envelope{}, errors.New("capture envelope contains trailing JSON")
	}
	if err := value.Validate(); err != nil {
		return Envelope{}, err
	}
	return value, nil
}

func (e Envelope) Validate() error {
	if e.RecordSchemaVersion != RecordSchemaVersion {
		return errors.New("unsupported record schema version")
	}
	for _, item := range []struct{ value, kind, field string }{{e.InputEventID, "event", "input_event_id"}, {e.OperatorID, "operator", "operator_id"}, {e.SessionID, "session", "session_id"}, {e.Case.ID, "case", "case.case_id"}, {e.Verdict.ID, "verdict", "verdict.verdict_id"}, {e.Verdict.Call.ID, "call", "call.call_id"}} {
		if err := urn.Require(item.value, item.kind); err != nil {
			return fmt.Errorf("%s %w", item.field, err)
		}
	}
	if !nodeIDPattern.MatchString(e.NodeID) {
		return errors.New("unsafe node_id")
	}
	if !oneOf(e.CaptureMechanism, "claude_code_stop_hook", "explicit_cli", "approved_import") {
		return errors.New("invalid capture_mechanism")
	}
	instant, err := time.Parse(time.RFC3339Nano, e.CapturedAt)
	_, offset := instant.Zone()
	if err != nil || offset != 0 {
		return errors.New("captured_at must be UTC RFC3339")
	}
	for field, value := range map[string]string{"case.description": e.Case.Description, "verdict.raw_operator_text": e.Verdict.RawOperatorText, "provenance.captured_by": e.Provenance.CapturedBy} {
		if err := validText(value, field); err != nil {
			return err
		}
	}
	if !oneOf(e.Verdict.Call.Type, "accept", "reject", "correct", "prefer", "refuse") {
		return errors.New("invalid call_type")
	}
	if !oneOf(e.Verdict.ReasonStatus, "absent", "pending", "supplied", "later_added") {
		return errors.New("invalid reason_status")
	}
	if e.Verdict.Reason == nil && (e.Verdict.ReasonStatus == "supplied" || e.Verdict.ReasonStatus == "later_added") {
		return errors.New("reason status fabricates a missing reason")
	}
	if e.Verdict.Reason != nil {
		if err := validText(*e.Verdict.Reason, "verdict.reason"); err != nil {
			return err
		}
		if e.Verdict.ReasonStatus != "supplied" && e.Verdict.ReasonStatus != "later_added" {
			return errors.New("reason and reason_status disagree")
		}
	}
	byAlternative := map[string]string{}
	for _, item := range e.Alternatives {
		if err := urn.Require(item.ID, "alternative"); err != nil {
			return fmt.Errorf("alternative.alternative_id %w", err)
		}
		if err := validText(item.Description, "alternative.description"); err != nil {
			return err
		}
		if !oneOf(item.Disposition, "chosen", "rejected") || byAlternative[item.ID] != "" {
			return errors.New("invalid or duplicate alternative")
		}
		byAlternative[item.ID] = item.Disposition
	}
	seenAlternative := map[string]bool{}
	for _, group := range []struct {
		ids                []string
		disposition, field string
	}{{e.Verdict.ChosenAlternativeIDs, "chosen", "chosen_alternative_ids"}, {e.Verdict.RejectedAlternativeIDs, "rejected", "rejected_alternative_ids"}} {
		for _, id := range group.ids {
			if seenAlternative[id] || byAlternative[id] != group.disposition {
				return fmt.Errorf("verdict.%s does not match alternatives", group.field)
			}
			seenAlternative[id] = true
		}
	}
	if len(seenAlternative) != len(byAlternative) {
		return errors.New("unreferenced alternative")
	}
	if len(e.Evidence) == 0 {
		return errors.New("evidence must be a non-empty list")
	}
	evidenceIDs := map[string]bool{}
	hasVerbatim := false
	for _, item := range e.Evidence {
		if err := urn.Require(item.ID, "evidence"); err != nil {
			return fmt.Errorf("evidence.evidence_id %w", err)
		}
		if evidenceIDs[item.ID] || !oneOf(item.Kind, "operator_verbatim", "artifact", "context") {
			return errors.New("invalid or duplicate evidence")
		}
		if err := validText(item.Content, "evidence.content"); err != nil {
			return err
		}
		if len(item.SHA256) != 64 {
			return errors.New("invalid evidence hash")
		}
		if _, err := hex.DecodeString(item.SHA256); err != nil {
			return errors.New("invalid evidence hash")
		}
		if digest(item.Content) != item.SHA256 {
			return errors.New("evidence hash mismatch")
		}
		if err := validText(item.SourceLocator, "evidence.source_locator"); err != nil {
			return err
		}
		evidenceIDs[item.ID] = true
		hasVerbatim = hasVerbatim || (item.Kind == "operator_verbatim" && item.Content == e.Verdict.RawOperatorText)
	}
	for _, id := range e.Case.SourceRefs {
		if !evidenceIDs[id] {
			return errors.New("case.source_refs contains an unknown evidence ID")
		}
	}
	if !hasVerbatim {
		return errors.New("verbatim operator evidence is missing")
	}
	if e.Provenance.Status != "captured" || e.Provenance.AuthorityTier != "observed_candidate" || e.Provenance.ActorClass != "software" || e.Provenance.Model != nil {
		return errors.New("raw recorder capture must remain a non-authoritative candidate")
	}
	if e.Provenance.ActorID != e.Provenance.CapturedBy || !sameSet(e.Provenance.EvidenceIDs, evidenceIDs) {
		return errors.New("provenance references are incomplete")
	}
	for namespace, extension := range e.Extensions {
		if !strings.Contains(namespace, ".") || extension.SchemaVersion == "" || len(extension.Payload) == 0 || !json.Valid(extension.Payload) {
			return errors.New("invalid extension namespace or value")
		}
	}
	encoded, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(encoded) > MaxEventBytes {
		return errors.New("capture envelope is oversized")
	}
	return nil
}

func buildAlternatives(inputs []AlternativeInput, disposition string) ([]Alternative, []string, error) {
	items := make([]Alternative, 0, len(inputs))
	ids := make([]string, 0, len(inputs))
	for _, input := range inputs {
		id, err := optionalURN(input.ID, "alternative")
		if err != nil {
			return nil, nil, err
		}
		items = append(items, Alternative{ID: id, Description: input.Description, Disposition: disposition})
		ids = append(ids, id)
	}
	return items, ids, nil
}

func optionalURN(value, kind string) (string, error) {
	if value == "" {
		return urn.New(kind)
	}
	if err := urn.Require(value, kind); err != nil {
		return "", err
	}
	return value, nil
}
func validText(value, field string) error {
	if !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must be a non-empty string", field)
	}
	if len([]byte(value)) > maxTextBytes {
		return fmt.Errorf("%s is oversized", field)
	}
	return nil
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
func sameSet(values []string, expected map[string]bool) bool {
	if len(values) != len(expected) {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !expected[value] || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
func nonNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}
