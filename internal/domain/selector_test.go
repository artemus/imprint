package domain

import (
	"github.com/artemus/imprint/internal/config"
	"testing"
)

func TestSelectionOrderAndTies(t *testing.T) {
	rules := []config.Domain{{ID: "research", PublicLabel: "Research", SafePaths: []string{"Projects/Research"}, Keywords: []string{"failed sources"}}, {ID: "sales", PublicLabel: "Sales", SafePaths: []string{"Projects/Sales"}, Keywords: []string{"pipeline"}}}
	if got := Select(rules, "", "Projects/Research/Now", ""); got.ID != "research" || got.Method != "path" {
		t.Fatalf("got=%#v", got)
	}
	if got := Select(rules, "", "", "review failed sources"); got.ID != "research" || got.Method != "keyword" {
		t.Fatalf("got=%#v", got)
	}
	if got := Select(rules, "missing", "", ""); got.Diagnostic != "domain_explicit_invalid" {
		t.Fatalf("got=%#v", got)
	}
}
func TestUnsafePathAndKeywordTieDoNotSelect(t *testing.T) {
	rules := []config.Domain{{ID: "a", PublicLabel: "A", Keywords: []string{"shared"}}, {ID: "b", PublicLabel: "B", Keywords: []string{"shared"}}}
	if got := Select(rules, "", "Projects/../A", ""); got.ID != "" {
		t.Fatalf("got=%#v", got)
	}
	if got := Select(rules, "", "", "shared"); got.Diagnostic != "domain_keyword_tie" {
		t.Fatalf("got=%#v", got)
	}
}
