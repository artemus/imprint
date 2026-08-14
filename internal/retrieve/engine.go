// Package retrieve compiles provenance-gated context under an exact byte budget.
package retrieve

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/artemus/imprint/internal/canonical"
)

const TokenizerVersion = "lexical-v1"
const JudgmentPartition = "judgment"

var tokenPattern = regexp.MustCompile(`[a-z0-9]+(?:['-][a-z0-9]+)*`)
var partitions = map[string]bool{"judgment": true, "self_model": true, "business_declared": true, "business_observed": true}

type Record struct {
	RecordID, Text, Section, ProvenanceStatus, AuthorityTier string
	EvidenceIDs, CaseIDs, CaseReferents, SourceReceiptIDs    []string
	DomainID                                                 string
	Pinned                                                   bool
	RecurrenceCount                                          int
	ValidFrom                                                string
	Current                                                  bool
	Rejected, Tombstoned                                     bool
	ValidUntil                                               string
	ProvenanceComplete, ImportedSelected                     bool
	OntologyPartition, OntologyType                          string
	OntologyPath                                             []string
	Confidence                                               *float64
	Disclosure                                               string
}
type Config struct {
	Budget                      int
	AllowHigher                 bool
	AuthorityMode, OutputFormat string
}
type Result struct {
	Payload                                                 []byte
	SelectedIDs                                             []string
	EligibleCount, OmittedCount, SelectedBytes, BudgetBytes int
	SectionBytes                                            map[string]int
	TokenizerVersion, AuthorityMode                         string
	RequestedPartitions                                     []string
	SelectedByPartition                                     map[string][]string
}

func Tokenize(value string) []string {
	normalized := cases.Fold().String(norm.NFKD.String(value))
	ascii := strings.Builder{}
	for _, character := range normalized {
		if character < 128 {
			ascii.WriteRune(character)
		}
	}
	return tokenPattern.FindAllString(ascii.String(), -1)
}
func lexicalScore(query, text string) int {
	tokens := Tokenize(query)
	known := map[string]bool{}
	for _, token := range Tokenize(text) {
		known[token] = true
	}
	score := 0
	for _, token := range tokens {
		if known[token] {
			score++
		}
	}
	return score
}

func Retrieve(records []Record, query, selectedDomain string, requested []string, config Config) (Result, error) {
	if config.Budget == 0 {
		config.Budget = 32 * 1024
	}
	if config.AuthorityMode == "" {
		config.AuthorityMode = "authoritative"
	}
	if config.OutputFormat == "" {
		config.OutputFormat = "audit"
	}
	if config.Budget <= 0 {
		return Result{}, errors.New("retrieval budget must be positive")
	}
	if config.Budget > 32*1024 && !config.AllowHigher {
		return Result{}, errors.New("higher retrieval budget requires explicit opt-in")
	}
	if config.Budget > 128*1024 {
		return Result{}, errors.New("retrieval budget exceeds explicit hard bound")
	}
	if config.AuthorityMode != "authoritative" && config.AuthorityMode != "analytical" {
		return Result{}, errors.New("unsupported retrieval authority mode")
	}
	if config.OutputFormat != "compact" && config.OutputFormat != "audit" {
		return Result{}, errors.New("unsupported retrieval output format")
	}
	requested = unique(requested)
	if config.AuthorityMode == "analytical" && len(requested) == 0 {
		return Result{}, errors.New("analytical retrieval requires explicit ontology partitions")
	}
	for _, item := range requested {
		if !partitions[item] {
			return Result{}, fmt.Errorf("unsupported ontology partition %q", item)
		}
	}
	filtered := []Record{}
	for _, record := range records {
		if eligible(record, selectedDomain, config.AuthorityMode) && (len(requested) == 0 || contains(requested, record.OntologyPartition)) {
			filtered = append(filtered, record)
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool { return less(filtered[i], filtered[j], query, selectedDomain) })
	limits := sectionLimits(config.Budget)
	sectionBytes := map[string]int{"core": 0, "general": 0, "domain": 0}
	selected := []Record{}
	carry := 0
	for _, section := range []string{"core", "general", "domain"} {
		available := limits[section] + carry
		for _, record := range filtered {
			if record.Section != section {
				continue
			}
			rendered, _ := render(record, config.OutputFormat)
			if len(rendered) <= available-sectionBytes[section] {
				selected = append(selected, record)
				sectionBytes[section] += len(rendered)
			}
		}
		carry = available - sectionBytes[section]
	}
	var payload bytes.Buffer
	ids := []string{}
	byPartition := map[string][]string{}
	for _, record := range selected {
		rendered, _ := render(record, config.OutputFormat)
		payload.Write(rendered)
		ids = append(ids, record.RecordID)
		byPartition[record.OntologyPartition] = append(byPartition[record.OntologyPartition], record.RecordID)
	}
	return Result{Payload: payload.Bytes(), SelectedIDs: ids, EligibleCount: len(filtered), OmittedCount: len(filtered) - len(ids), SelectedBytes: payload.Len(), BudgetBytes: config.Budget, SectionBytes: sectionBytes, TokenizerVersion: TokenizerVersion, AuthorityMode: config.AuthorityMode, RequestedPartitions: requested, SelectedByPartition: byPartition}, nil
}

func eligible(r Record, domain, mode string) bool {
	if !r.Current || r.Rejected || r.Tombstoned || r.ValidUntil != "" || !r.ProvenanceComplete || len(r.EvidenceIDs) == 0 {
		return false
	}
	statuses := map[string]bool{"captured": true, "extracted": true, "ratified": true}
	tiers := map[string]bool{"captured_judgment": true, "ratified_knowledge": true, "imported_floor": true}
	if mode == "analytical" {
		statuses["inferred"] = true
		tiers["inferred_candidate"] = true
		tiers["observed_candidate"] = true
	}
	if !statuses[r.ProvenanceStatus] || !tiers[r.AuthorityTier] {
		return false
	}
	if r.AuthorityTier == "captured_judgment" && r.ProvenanceStatus != "captured" {
		return false
	}
	if r.ProvenanceStatus == "captured" && r.OntologyPartition != "business_declared" && len(r.CaseIDs) == 0 {
		return false
	}
	if r.AuthorityTier == "ratified_knowledge" && r.ProvenanceStatus != "ratified" {
		return false
	}
	if r.AuthorityTier == "imported_floor" && !r.ImportedSelected {
		return false
	}
	if r.ProvenanceStatus == "inferred" && r.AuthorityTier != "inferred_candidate" {
		return false
	}
	if r.AuthorityTier == "observed_candidate" && r.ProvenanceStatus != "extracted" {
		return false
	}
	if r.OntologyPartition == "self_model" && mode == "authoritative" && (r.OntologyType != "SelfModelAssertion" || r.ProvenanceStatus != "ratified") {
		return false
	}
	if r.Section == "domain" && (domain == "" || r.DomainID != domain) {
		return false
	}
	if r.DomainID != "" && r.Section != "domain" {
		return false
	}
	return true
}

func less(a, b Record, query, domain string) bool {
	ai, bi := boolRank(a.Pinned), boolRank(b.Pinned)
	if ai != bi {
		return ai < bi
	}
	ai, bi = boolRank(domain != "" && a.DomainID == domain), boolRank(domain != "" && b.DomainID == domain)
	if ai != bi {
		return ai < bi
	}
	as, bs := lexicalScore(query, a.Text), lexicalScore(query, b.Text)
	if as != bs {
		return as > bs
	}
	authority := func(r Record) int {
		if r.ProvenanceStatus == "captured" || r.ProvenanceStatus == "ratified" {
			return 0
		}
		if r.ProvenanceStatus == "extracted" {
			return 1
		}
		return 9
	}
	if authority(a) != authority(b) {
		return authority(a) < authority(b)
	}
	tier := func(value string) int {
		if value == "captured_judgment" || value == "ratified_knowledge" {
			return 0
		}
		if value == "imported_floor" {
			return 2
		}
		return 9
	}
	if tier(a.AuthorityTier) != tier(b.AuthorityTier) {
		return tier(a.AuthorityTier) < tier(b.AuthorityTier)
	}
	if a.RecurrenceCount != b.RecurrenceCount {
		return a.RecurrenceCount > b.RecurrenceCount
	}
	ad, bd := dayBucket(a.ValidFrom), dayBucket(b.ValidFrom)
	if ad != bd {
		return ad > bd
	}
	return a.RecordID < b.RecordID
}
func render(r Record, format string) ([]byte, error) {
	if format == "compact" {
		authority := r.ProvenanceStatus
		if r.AuthorityTier == "imported_floor" {
			authority = "imported"
		}
		kind := r.OntologyType
		if kind == "" || kind == "LegacyRecord" {
			kind = "Judgment"
		}
		line := "- " + kind + " (" + authority + "): " + oneLine(r.Text)
		if len(r.CaseReferents) > 0 {
			values := make([]string, len(r.CaseReferents))
			for i, value := range r.CaseReferents {
				values[i] = oneLine(value)
			}
			line += " | Case: " + strings.Join(values, " / ")
		}
		return []byte(line + "\n"), nil
	}
	authority := r.ProvenanceStatus
	if r.AuthorityTier == "imported_floor" {
		authority = "imported_floor"
	}
	value := map[string]any{"authority": authority, "case_ids": nonNil(r.CaseIDs), "case_referents": nonNil(r.CaseReferents), "evidence_ids": nonNil(r.EvidenceIDs), "ontology": map[string]any{"confidence": r.Confidence, "disclosure": r.Disclosure, "partition": r.OntologyPartition, "path": nonNil(r.OntologyPath), "type": r.OntologyType}, "record_id": r.RecordID, "source_receipt_ids": nonNil(r.SourceReceiptIDs), "text": r.Text}
	encoded, err := canonical.JSON(value)
	return append(encoded, '\n'), err
}
func sectionLimits(total int) map[string]int {
	unit, remainder := total/4, total%4
	result := map[string]int{"core": unit, "general": unit * 2, "domain": unit}
	names := []string{"core", "general", "domain"}
	for index := 0; index < remainder && index < len(names); index++ {
		result[names[index]]++
	}
	return result
}
func dayBucket(value string) int64 {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		parsed, _ = time.Parse(time.RFC3339Nano, value)
	}
	if parsed.IsZero() {
		return 0
	}
	return parsed.Unix() / 86400
}
func boolRank(value bool) int {
	if value {
		return 0
	}
	return 1
}
func oneLine(value string) string { return strings.Join(strings.Fields(value), " ") }
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func unique(values []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
func nonNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}
