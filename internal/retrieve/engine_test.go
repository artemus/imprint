package retrieve

import (
	"strings"
	"testing"
)

func record(id, text string) Record {
	return Record{RecordID: id, Text: text, Section: "general", ProvenanceStatus: "captured", AuthorityTier: "captured_judgment", EvidenceIDs: []string{"e-" + id}, CaseIDs: []string{"c-" + id}, Current: true, ProvenanceComplete: true, OntologyPartition: "judgment", OntologyType: "Verdict", ValidFrom: "2026-01-02T00:00:00Z", Disclosure: "operator_captured"}
}
func TestCompactRetrievalRanksAndBudgets(t *testing.T) {
	a := record("a", "Café launch")
	a.CaseReferents = []string{"Reviewing launch"}
	b := record("b", "Other")
	result, err := Retrieve([]Record{b, a}, "CAFE", "", nil, Config{Budget: 4096, OutputFormat: "compact"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SelectedIDs) != 2 || result.SelectedIDs[0] != "a" {
		t.Fatalf("ids=%v", result.SelectedIDs)
	}
	if !strings.Contains(string(result.Payload), "Case: Reviewing launch") {
		t.Fatalf("payload=%s", result.Payload)
	}
	if tokens := Tokenize("Café"); len(tokens) != 1 || tokens[0] != "cafe" {
		t.Fatalf("tokens=%v", tokens)
	}
}
func TestEligibilityFailsClosed(t *testing.T) {
	bad := record("bad", "value")
	bad.AuthorityTier = "observed_candidate"
	result, err := Retrieve([]Record{bad}, "", "", nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Payload) != 0 {
		t.Fatalf("payload=%s", result.Payload)
	}
	if _, err = Retrieve(nil, "", "", nil, Config{Budget: 40 * 1024}); err == nil {
		t.Fatal("accepted implicit high budget")
	}
}
func TestDomainDoesNotEscape(t *testing.T) {
	good := record("good", "domain")
	good.Section = "domain"
	good.DomainID = "alpha"
	escape := record("escape", "domain")
	escape.DomainID = "alpha"
	result, err := Retrieve([]Record{good, escape}, "", "alpha", nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SelectedIDs) != 1 || result.SelectedIDs[0] != "good" {
		t.Fatalf("ids=%v", result.SelectedIDs)
	}
}
