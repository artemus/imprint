package projection

import (
	"strings"
	"testing"

	"github.com/artemus/imprint/internal/store"
)

func TestMarkdownIsDeterministicAndIncludesEvidenceAndLinks(t *testing.T) {
	snapshot := store.ProjectionSnapshot{
		Nodes: []store.ProjectionNode{
			{NodeID: "verdict", NodeType: "Verdict", Payload: map[string]any{"raw_operator_text": "Keep the exact source."}, ProvenanceStatus: "ratified", AuthorityTier: "ratified_knowledge", Evidence: []string{"evidence-1"}, ValidFrom: "2026-08-14T00:00:00Z"},
			{NodeID: "case", NodeType: "Case", Payload: map[string]any{"description": "Source review"}, ProvenanceStatus: "captured", AuthorityTier: "observed_candidate", ValidFrom: "2026-08-14T00:00:00Z"},
		},
		Edges: []store.ProjectionEdge{{EdgeID: "edge", EdgeType: "verdict_about_case", SourceID: "verdict", TargetID: "case"}},
	}
	one, two := Markdown(snapshot), Markdown(snapshot)
	if one != two {
		t.Fatal("projection is not deterministic")
	}
	for _, expected := range []string{"## Case", "## Verdict", "Keep the exact source.", "Evidence: evidence-1", "Supporting Case/Verdict: case", "valid 2026-08-14T00:00:00Z..current"} {
		if !strings.Contains(one, expected) {
			t.Fatalf("missing %q in:\n%s", expected, one)
		}
	}
}
