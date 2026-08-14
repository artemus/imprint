// Package capture witnesses explicit operator judgment before interpretation.
package capture

import (
	"math"
	"regexp"
	"strings"
)

type Detection struct {
	IsFeedback bool    `json:"is_feedback"`
	Route      string  `json:"route"`
	CallType   string  `json:"call_type,omitempty"`
	Marker     string  `json:"marker,omitempty"`
	Confidence float64 `json:"confidence"`
}

type rule struct {
	route, callType, marker string
	pattern                 *regexp.Regexp
}

func insensitive(pattern string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + pattern) }

var rules = []rule{
	{"refusal", "reject", "rejection", insensitive(`\b(i reject|reject (this|that|it))\b`)},
	{"refusal", "refuse", "refusal", insensitive(`\b(do not|don't|won't)\s+(use|include|change|send|publish|do|make)|\b(i refuse|no thanks|stop (using|doing))\b`)},
	{"preference", "prefer", "preference", insensitive(`\b(i prefer|my preference is|favor .+ over|(i'd|i would) rather\s+(use|keep|remove|restore|change|make|publish|send|write))\b`)},
	{"approval", "accept", "approval", insensitive(`(^|[.!?]\s*)(approved|ship it)([.!?]|$)|\b(that's right|that is right|(this|that|it) is exactly right|(this|that|it) looks good|this is the one[.!?]*$)\b`)},
	{"standard", "correct", "standard", insensitive(`\b((always|never)\s+(use|include|remove|change|keep|do|say|write|preserve|avoid)|(we|you) must\s+(use|include|remove|change|keep|do|say|write|preserve|avoid)|(this|that) must\s+(be|use|include|keep|preserve|avoid))\b`)},
	{"correction", "correct", "direct", insensitive(`(^|[.!?]\s*)(no[,.:]|wrong\b|incorrect\b)|\b((this|that|it) is wrong|that's wrong|not .+[,;:]? (use|make|keep)|(use|make|keep|remove|restore|change)\s+.+\s+instead|instead[,;:]?\s+(use|make|keep|remove|restore|change)\b|change (it|that|this)|you (missed|changed|removed|added))\b`)},
	{"correction", "correct", "question_form", insensitive(`\b(why did you\s+(remove|change|add|omit|replace|rewrite)|shouldn't (it|this|that)|wouldn't (it|this|that) be|can you (change|restore|remove|keep)|could you (change|restore|remove|keep))\b`)},
	{"correction", "correct", "indirect", insensitive(`(^|[.!?]\s*)not quite\b|\b(this feels (too|like)|it would be better|what i (meant|was looking for)|this isn't landing|this is not landing)\b`)},
}

var (
	politeEdit  = insensitive(`\b(please|could you|would you)\b.*\b(change|use|make|keep|remove|restore|avoid|don't)\b`)
	weakReview  = insensitive(`(^|[.!?]\s*)perfect[.!?]*$|\b(needs? to|instead|the standard is|our rule is)\b`)
	normalWords = regexp.MustCompile(`[a-z0-9]+`)
)

func Detect(text, priorOperator, priorAssistant string) Detection {
	if strings.TrimSpace(text) == "" {
		return Detection{Route: "non_feedback", Confidence: 1}
	}
	for _, item := range rules {
		if item.pattern.MatchString(text) {
			return Detection{true, item.route, item.callType, item.marker, .99}
		}
	}
	if priorAssistant != "" && politeEdit.MatchString(text) {
		return Detection{true, "correction", "correct", "polite", .96}
	}
	if priorAssistant != "" && priorOperator != "" {
		current, prior := normalize(text), normalize(priorOperator)
		if current != "" && prior != "" {
			ratio, shared := similarity(prior, current), sharedWords(prior, current)
			if ratio >= .88 || (ratio >= .72 && shared >= .8) {
				confidence := math.Round(math.Max(ratio, shared)*1000) / 1000
				return Detection{true, "correction", "correct", "silent_reask", confidence}
			}
		}
	}
	if weakReview.MatchString(text) {
		return Detection{false, "review_candidate", "", "weak_lexical_hint", .55}
	}
	return Detection{Route: "non_feedback", Confidence: .99}
}

func normalize(value string) string {
	return strings.Join(normalWords.FindAllString(strings.ToLower(value), -1), " ")
}

func sharedWords(prior, current string) float64 {
	a, b := map[string]bool{}, map[string]bool{}
	for _, word := range strings.Fields(prior) {
		a[word] = true
	}
	for _, word := range strings.Fields(current) {
		b[word] = true
	}
	shared := 0
	for word := range a {
		if b[word] {
			shared++
		}
	}
	if len(a) == 0 {
		return 0
	}
	return float64(shared) / float64(len(a))
}

// similarity is Levenshtein ratio. The shared-word guard carries semantic
// reasks; this ratio covers punctuation and minor correction changes.
func similarity(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 && len(rb) == 0 {
		return 1
	}
	previous := make([]int, len(rb)+1)
	for j := range previous {
		previous[j] = j
	}
	for i, ca := range ra {
		current := make([]int, len(rb)+1)
		current[0] = i + 1
		for j, cb := range rb {
			cost := 0
			if ca != cb {
				cost = 1
			}
			current[j+1] = min(current[j]+1, previous[j+1]+1, previous[j]+cost)
		}
		previous = current
	}
	return 1 - float64(previous[len(rb)])/float64(max(len(ra), len(rb)))
}
