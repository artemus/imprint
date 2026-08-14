// Package proposal validates non-authoritative derivation candidates.
package proposal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/capture"
	"github.com/artemus/imprint/internal/urn"
)

var forbiddenKey = regexp.MustCompile(`(?i)(?:^|_)(?:sql|query|path|database|db|command|writer|purge|migration)(?:$|_)`)
var sqlTransition = regexp.MustCompile(`(?i)\b(?:insert|update|delete|drop|alter)\s+(?:into|table|from|\w+)`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type References struct {
	CaseID      string   `json:"case_id"`
	VerdictID   string   `json:"verdict_id"`
	EvidenceIDs []string `json:"evidence_ids"`
}
type Provenance struct {
	Status           string  `json:"status"`
	AuthorityTier    string  `json:"authority_tier"`
	Proposer         string  `json:"proposer"`
	Model            *string `json:"model"`
	PromptRecipeHash *string `json:"prompt_recipe_hash"`
}
type Proposal struct {
	RecordSchemaVersion string         `json:"record_schema_version"`
	ID                  string         `json:"proposal_id"`
	SourceInputEventID  string         `json:"source_input_event_id"`
	Type                string         `json:"proposal_type"`
	ProposedTransition  string         `json:"proposed_transition"`
	References          References     `json:"references"`
	Payload             map[string]any `json:"payload"`
	Provenance          Provenance     `json:"provenance"`
	Extensions          map[string]any `json:"extensions"`
}

func Decode(raw []byte) (Proposal, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var value Proposal
	if err := decoder.Decode(&value); err != nil {
		return Proposal{}, fmt.Errorf("decode proposal: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Proposal{}, errors.New("proposal contains trailing JSON")
	}
	return value, value.Validate()
}

func (p Proposal) Validate() error {
	if p.RecordSchemaVersion != capture.RecordSchemaVersion {
		return errors.New("unsupported proposal schema version")
	}
	for _, item := range []struct{ value, kind string }{{p.ID, "proposal"}, {p.SourceInputEventID, "event"}, {p.References.CaseID, "case"}, {p.References.VerdictID, "verdict"}} {
		if err := urn.Require(item.value, item.kind); err != nil {
			return err
		}
	}
	if !oneOf(p.Type, "correction_with_reason", "correction_without_reason", "preference", "standard", "approval", "refusal", "reason_addition", "non_feedback") {
		return errors.New("unknown proposal type")
	}
	if !oneOf(p.ProposedTransition, "extract", "infer", "route") {
		return errors.New("unknown or forbidden proposal transition")
	}
	if (p.Type == "non_feedback") != (p.ProposedTransition == "route") {
		return errors.New("proposal type and route transition disagree")
	}
	if len(p.References.EvidenceIDs) == 0 {
		return errors.New("proposal requires evidence references")
	}
	for _, id := range p.References.EvidenceIDs {
		if err := urn.Require(id, "evidence"); err != nil {
			return err
		}
	}
	if p.Payload == nil || p.Extensions == nil {
		return errors.New("proposal payload and extensions must be objects")
	}
	reason, hasReason := p.Payload["reason"]
	status, _ := p.Payload["reason_status"].(string)
	if reason == nil {
		hasReason = false
	}
	if !hasReason && (status == "supplied" || status == "later_added") {
		return errors.New("proposal fabricates WHY status")
	}
	if hasReason {
		text, ok := reason.(string)
		if !ok || strings.TrimSpace(text) == "" || (status != "supplied" && status != "later_added") {
			return errors.New("proposal reason and status disagree")
		}
	}
	if p.Type == "correction_with_reason" && !hasReason {
		return errors.New("correction_with_reason requires source reason")
	}
	if p.Type == "correction_without_reason" && hasReason {
		return errors.New("correction_without_reason cannot invent a reason")
	}
	if !oneOf(p.Provenance.Status, "extracted", "inferred") || !oneOf(p.Provenance.AuthorityTier, "inferred_candidate", "observed_candidate") {
		return errors.New("proposal provenance escalates authority")
	}
	if strings.TrimSpace(p.Provenance.Proposer) == "" {
		return errors.New("proposal proposer is required")
	}
	if p.Provenance.Model == nil && p.Provenance.PromptRecipeHash != nil {
		return errors.New("prompt hash without a model is invalid")
	}
	if p.Provenance.Model != nil {
		if strings.TrimSpace(*p.Provenance.Model) == "" || p.Provenance.PromptRecipeHash == nil || !sha256Pattern.MatchString(*p.Provenance.PromptRecipeHash) {
			return errors.New("model proposal requires model identity and prompt recipe SHA-256")
		}
	}
	encoded, err := canonical.JSON(p)
	if err != nil {
		return err
	}
	var generic any
	if json.Unmarshal(encoded, &generic) != nil || scanAuthority(generic) != nil {
		return errors.New("proposal contains forbidden authority field, transition, SQL, or path")
	}
	if len(encoded) > capture.MaxEventBytes {
		return errors.New("proposal is oversized")
	}
	return nil
}

func FromCapture(envelope capture.Envelope, proposer string) (Proposal, error) {
	typeName := map[string]string{"correct": "correction_without_reason", "prefer": "preference", "accept": "approval", "reject": "refusal", "refuse": "refusal"}[envelope.Verdict.Call.Type]
	if envelope.Verdict.Call.Type == "correct" && envelope.Verdict.Reason != nil {
		typeName = "correction_with_reason"
	}
	transition := "extract"
	if typeName == "" {
		typeName, transition = "non_feedback", "route"
	}
	id, err := urn.New("proposal")
	if err != nil {
		return Proposal{}, err
	}
	chosen := append([]string{}, envelope.Verdict.ChosenAlternativeIDs...)
	rejected := append([]string{}, envelope.Verdict.RejectedAlternativeIDs...)
	evidence := append([]string{}, envelope.Provenance.EvidenceIDs...)
	var reason any
	if envelope.Verdict.Reason != nil {
		reason = *envelope.Verdict.Reason
	}
	value := Proposal{
		RecordSchemaVersion: capture.RecordSchemaVersion, ID: id,
		SourceInputEventID: envelope.InputEventID, Type: typeName, ProposedTransition: transition,
		References: References{CaseID: envelope.Case.ID, VerdictID: envelope.Verdict.ID, EvidenceIDs: evidence},
		Payload:    map[string]any{"call_type": envelope.Verdict.Call.Type, "reason": reason, "reason_status": envelope.Verdict.ReasonStatus, "chosen_alternative_ids": chosen, "rejected_alternative_ids": rejected},
		Provenance: Provenance{Status: "extracted", AuthorityTier: "observed_candidate", Proposer: proposer}, Extensions: map[string]any{},
	}
	return value, value.Validate()
}

func scanAuthority(value any) error {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if forbiddenKey.MatchString(key) {
				return errors.New("forbidden key")
			}
			if err := scanAuthority(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range item {
			if err := scanAuthority(child); err != nil {
				return err
			}
		}
	case string:
		lowered := strings.ToLower(strings.TrimSpace(item))
		if oneOf(lowered, "captured", "ratified", "purged", "purge", "migrated", "migration", "tombstoned") || sqlTransition.MatchString(lowered) || strings.HasPrefix(item, "/") || strings.HasPrefix(item, `\\`) || regexp.MustCompile(`^[A-Za-z]:[\\/]`).MatchString(item) || strings.Contains(item, "../") || strings.Contains(item, `..\`) {
			return errors.New("forbidden value")
		}
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
