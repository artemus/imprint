// Package domain deterministically selects a configured retrieval partition.
package domain

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/artemus/imprint/internal/config"
	"github.com/artemus/imprint/internal/retrieve"
)

type Selection struct{ ID, Method, Diagnostic string }

func Select(rules []config.Domain, explicit, path, prompt string) Selection {
	known := map[string]config.Domain{}
	for _, rule := range rules {
		known[rule.ID] = rule
	}
	if explicit != "" {
		if _, ok := known[explicit]; !ok {
			return Selection{Method: "explicit", Diagnostic: "domain_explicit_invalid"}
		}
		return Selection{ID: explicit, Method: "explicit"}
	}
	if path != "" {
		target := pathParts(path)
		type score struct {
			value int
			id    string
		}
		scores := []score{}
		if len(target) > 0 {
			for _, rule := range rules {
				best := 0
				for _, prefix := range rule.SafePaths {
					parts := pathParts(prefix)
					if len(parts) > 0 && len(parts) <= len(target) && equal(parts, target[:len(parts)]) && len(parts) > best {
						best = len(parts)
					}
				}
				if best > 0 {
					scores = append(scores, score{best, rule.ID})
				}
			}
		}
		if len(scores) > 0 {
			sort.Slice(scores, func(i, j int) bool {
				if scores[i].value != scores[j].value {
					return scores[i].value > scores[j].value
				}
				return scores[i].id < scores[j].id
			})
			high := scores[0].value
			winners := []string{}
			for _, item := range scores {
				if item.value == high {
					winners = append(winners, item.id)
				}
			}
			if len(winners) == 1 {
				return Selection{ID: winners[0], Method: "path"}
			}
			return Selection{Method: "path", Diagnostic: "domain_path_tie"}
		}
	}
	query := stringSet(retrieve.Tokenize(prompt))
	type keywordScore struct {
		value int
		id    string
	}
	scores := []keywordScore{}
	for _, rule := range rules {
		terms := map[string]bool{}
		for _, keyword := range rule.Keywords {
			for _, token := range retrieve.Tokenize(keyword) {
				terms[token] = true
			}
		}
		count := 0
		for token := range query {
			if terms[token] {
				count++
			}
		}
		if count > 0 {
			scores = append(scores, keywordScore{count, rule.ID})
		}
	}
	if len(scores) > 0 {
		sort.Slice(scores, func(i, j int) bool {
			if scores[i].value != scores[j].value {
				return scores[i].value > scores[j].value
			}
			return scores[i].id < scores[j].id
		})
		high := scores[0].value
		winners := []string{}
		for _, item := range scores {
			if item.value == high {
				winners = append(winners, item.id)
			}
		}
		if len(winners) == 1 {
			return Selection{ID: winners[0], Method: "keyword"}
		}
		return Selection{Method: "keyword", Diagnostic: "domain_keyword_tie"}
	}
	return Selection{Method: "none", Diagnostic: "domain_no_match"}
}
func pathParts(value string) []string {
	value = strings.Trim(strings.ReplaceAll(value, "\\", "/"), "/")
	if value == "" || strings.ContainsRune(value, '\x00') {
		return nil
	}
	raw := strings.Split(filepath.ToSlash(value), "/")
	result := []string{}
	for _, part := range raw {
		if part == "" {
			continue
		}
		part = strings.ToLower(part)
		if part == "." || part == ".." {
			return nil
		}
		result = append(result, part)
	}
	return result
}
func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
func stringSet(values []string) map[string]bool {
	result := map[string]bool{}
	for _, value := range values {
		result[value] = true
	}
	return result
}
