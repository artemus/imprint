package retrieve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/artemus/imprint/internal/store"
)

var judgmentTypes = stringSet("Verdict", "Principle", "Belief", "Value", "Rule", "Pattern", "IngestedItem")
var declaredTypes = stringSet("Customer", "Segment", "Problem", "Desire", "Situation", "Claim", "Promise", "Expectation", "Mechanism", "RequiredBehavior", "Offer", "Price", "Channel", "Objection", "Proof", "Intervention")
var observedTypes = stringSet("SupportAction", "Purchase", "Usage", "Result", "Refund", "Retention", "Referral", "Observation", "Outcome")

func FromStore(ctx context.Context, database *store.Store) ([]Record, string, error) {
	state, err := database.RetrievalState(ctx)
	if err != nil {
		return nil, "", err
	}
	snapshotRaw := fmt.Sprintf("%s:%d", state.Identity, state.Generation)
	sum := sha256.Sum256([]byte(snapshotRaw))
	snapshotID := hex.EncodeToString(sum[:])
	evidenceNodes := map[string]bool{}
	caseText := map[string]string{}
	for _, node := range state.Nodes {
		if node.NodeType == "Evidence" {
			evidenceNodes[node.NodeID] = true
		}
		if node.NodeType == "Case" {
			if text := nodeText(node.NodeType, node.Payload); text != "" {
				caseText[node.NodeID] = text
			}
		}
	}
	cases := map[string][]string{}
	linkedEvidence := map[string]map[string]bool{}
	for _, edge := range state.Edges {
		if edge.EdgeType == "verdict_about_case" {
			cases[edge.SourceID] = append(cases[edge.SourceID], edge.TargetID)
		}
		if edge.EdgeType == "supported_by" {
			if linkedEvidence[edge.SourceID] == nil {
				linkedEvidence[edge.SourceID] = map[string]bool{}
			}
			linkedEvidence[edge.SourceID][edge.TargetID] = true
		}
	}
	records := []Record{}
	for _, node := range state.Nodes {
		if node.OperatorID == "" || (!judgmentTypes[node.NodeType] && !declaredTypes[node.NodeType] && !observedTypes[node.NodeType] && node.NodeType != "SelfModelAssertion") {
			continue
		}
		text := nodeText(node.NodeType, node.Payload)
		if strings.TrimSpace(text) == "" {
			continue
		}
		evidence := unique(node.Evidence)
		sort.Strings(evidence)
		complete := len(evidence) > 0
		for _, id := range evidence {
			if !evidenceNodes[id] && !state.SourceReceipts[id] {
				complete = false
			}
		}
		if node.NodeType == "Verdict" {
			for _, id := range evidence {
				if !linkedEvidence[node.NodeID][id] {
					complete = false
				}
			}
		}
		caseIDs := unique(cases[node.NodeID])
		sort.Strings(caseIDs)
		referents := []string{}
		for _, id := range caseIDs {
			if value := caseText[id]; value != "" {
				referents = append(referents, value)
			}
		}
		partition := partitionFor(node.NodeType)
		domain, _ := node.Payload["domain_id"].(string)
		section := "general"
		if domain != "" {
			section = "domain"
		} else if node.NodeType == "Belief" || node.NodeType == "Value" || node.NodeType == "SelfModelAssertion" {
			section = "core"
		}
		imported, _ := node.Payload["imported_selected"].(bool)
		pinned, _ := node.Payload["pinned"].(bool)
		recurrence := intValue(node.Payload["recurrence_count"])
		receipts := []string{}
		for _, id := range evidence {
			if state.SourceReceipts[id] {
				receipts = append(receipts, id)
			}
		}
		records = append(records, Record{RecordID: node.NodeID, Text: text, Section: section, ProvenanceStatus: node.ProvenanceStatus, AuthorityTier: node.AuthorityTier, EvidenceIDs: evidence, CaseIDs: caseIDs, CaseReferents: referents, SourceReceiptIDs: receipts, DomainID: domain, Pinned: pinned, RecurrenceCount: recurrence, ValidFrom: node.ValidFrom, Current: true, ValidUntil: node.ValidTo, ProvenanceComplete: complete && (node.ProvenanceStatus != "captured" || partition == "business_declared" || len(caseIDs) > 0), ImportedSelected: imported, OntologyPartition: partition, OntologyType: node.NodeType, OntologyPath: pathFor(node.NodeType, node.Payload, partition), Confidence: confidence(node.Payload), Disclosure: disclosure(node.ProvenanceStatus, node.AuthorityTier)})
	}
	return records, snapshotID, nil
}

func partitionFor(nodeType string) string {
	if nodeType == "SelfModelAssertion" {
		return "self_model"
	}
	if declaredTypes[nodeType] {
		return "business_declared"
	}
	if observedTypes[nodeType] {
		return "business_observed"
	}
	return "judgment"
}
func pathFor(nodeType string, payload map[string]any, partition string) []string {
	if nodeType == "SelfModelAssertion" {
		values := []string{"operator", "self_model"}
		for _, key := range []string{"function_class", "subtype", "dimension"} {
			if value, ok := payload[key].(string); ok && value != "" {
				values = append(values, value)
			}
		}
		return values
	}
	if partition == "business_declared" || partition == "business_observed" {
		mode, _ := payload["evidence_mode"].(string)
		if mode == "" {
			mode = "unclassified"
		}
		return []string{"business_world", mode, nodeType}
	}
	return []string{"judgment", nodeType}
}
func nodeText(nodeType string, payload map[string]any) string {
	for _, key := range []string{"statement", "raw_operator_text", "description", "content", "text", "name", "definition", "action", "metric", "status", "referred_party", "candidate_move"} {
		if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	if (nodeType == "Price" || nodeType == "Purchase" || nodeType == "Refund") && payload["amount"] != nil {
		return strings.TrimSpace(fmt.Sprintf("%s: %v %v", nodeType, payload["amount"], payload["currency"]))
	}
	if nodeType == "Result" && payload["value"] != nil {
		return strings.TrimSpace(fmt.Sprintf("%v: %v %v", payload["metric"], payload["value"], payload["unit"]))
	}
	return ""
}
func confidence(payload map[string]any) *float64 {
	value, ok := payload["confidence"].(map[string]any)
	if !ok {
		return nil
	}
	score, ok := value["score"].(float64)
	if !ok || score < 0 || score > 1 {
		return nil
	}
	return &score
}
func disclosure(status, tier string) string {
	if tier == "imported_floor" {
		return "approved_import_not_operator_judgment"
	}
	return map[string]string{"captured": "operator_captured", "ratified": "operator_ratified", "extracted": "source_extracted_not_operator_ratified", "inferred": "model_inference_not_operator_authority"}[status]
}
func stringSet(values ...string) map[string]bool {
	result := map[string]bool{}
	for _, value := range values {
		result[value] = true
	}
	return result
}
func intValue(value any) int {
	if number, ok := value.(float64); ok {
		return int(number)
	}
	return 0
}
