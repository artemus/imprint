// Package projection renders disposable views of canonical state.
package projection

import (
	"fmt"
	"sort"
	"strings"

	"github.com/artemus/imprint/internal/store"
)

func Markdown(snapshot store.ProjectionSnapshot) string {
	lines := []string{"# Imprint", "", "> Generated view. Use the CLI to change canonical state.", ""}
	related := map[string][]store.ProjectionEdge{}
	for _, edge := range snapshot.Edges {
		related[edge.SourceID] = append(related[edge.SourceID], edge)
		related[edge.TargetID] = append(related[edge.TargetID], edge)
	}
	grouped := map[string][]store.ProjectionNode{}
	types := []string{}
	for _, node := range snapshot.Nodes {
		if _, known := grouped[node.NodeType]; !known {
			types = append(types, node.NodeType)
		}
		grouped[node.NodeType] = append(grouped[node.NodeType], node)
	}
	sort.Strings(types)
	for _, nodeType := range types {
		lines = append(lines, "## "+nodeType, "")
		for _, node := range grouped[nodeType] {
			label := projectionLabel(node)
			domain := projectionString(node.Payload["domain_id"])
			if domain == "" {
				domain = "general"
			}
			validTo := node.ValidTo
			if validTo == "" {
				validTo = "current"
			}
			lines = append(lines, fmt.Sprintf("- **%s** [%s · %s · valid %s..%s · domain %s] %s", node.NodeID, node.ProvenanceStatus, node.AuthorityTier, node.ValidFrom, validTo, domain, label))
			if len(node.Evidence) > 0 {
				lines = append(lines, "  - Evidence: "+strings.Join(node.Evidence, ", "))
			}
			cases, revisions := projectionLinks(node.NodeID, related[node.NodeID])
			if len(cases) > 0 {
				lines = append(lines, "  - Supporting Case/Verdict: "+strings.Join(cases, ", "))
			}
			if len(revisions) > 0 {
				lines = append(lines, "  - Revision links: "+strings.Join(revisions, ", "))
			}
			lines = append(lines, fmt.Sprintf("  - History: `imprint history '%s'`", node.NodeID))
		}
		lines = append(lines, "")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
}

func projectionLabel(node store.ProjectionNode) string {
	for _, key := range []string{"statement", "principle", "raw_operator_text", "description", "call_type", "text"} {
		if value := projectionString(node.Payload[key]); value != "" {
			return value
		}
	}
	return node.NodeID
}

func projectionLinks(nodeID string, edges []store.ProjectionEdge) ([]string, []string) {
	cases, revisions := map[string]bool{}, map[string]bool{}
	for _, edge := range edges {
		other := edge.SourceID
		if other == nodeID {
			other = edge.TargetID
		}
		if edge.EdgeType == "verdict_about_case" {
			cases[other] = true
		}
		if edge.EdgeType == "contradicts" || edge.EdgeType == "supersedes" || edge.EdgeType == "weakens" || edge.EdgeType == "extends" {
			revisions[edge.EdgeType+":"+other] = true
		}
	}
	return sortedKeys(cases), sortedKeys(revisions)
}

func sortedKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func projectionString(value any) string {
	text, _ := value.(string)
	return text
}
