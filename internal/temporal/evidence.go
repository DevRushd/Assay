package temporal

import (
	"fmt"
	"sort"
	"strings"

	"github.com/use-assay/assay/internal/mechanics"
)

// What can change between two observations without the verdict changing.
//
// A capability bit moving changes the verdict; that is what Added, Removed and
// SeverityTransition report. But evidence can move while the verdict holds
// still — a domain goes dark and the toml claim is replaced by a fetch error,
// a transport failure text changes shape — and nothing else in this package
// sees that, because it compares bits and severities only.
//
// This is the class that produced the reproducibility problem in the
// attestation run's Finding 2 (#24): BERKSHIRE's evidence_hash commits to a
// DNS error naming one machine's resolver, so a verifier re-scanning anywhere
// else gets different bytes and no explanation. Detecting evidence-only
// change separates "the asset changed" from "our view of it changed", which a
// bare hash mismatch cannot do.

// EvidenceEvent classifies one difference between two evidence sets.
//
// Source-level rather than field-level on purpose: the question a consumer
// asks is "what did this source say before, and what does it say now", not
// "which bytes differ". A claim and its URL are one source's answer.
type EvidenceEvent struct {
	// Source is the evidence source the difference belongs to, e.g.
	// "stellar.toml" or "stellar.expert/directory".
	Source string `json:"source"`
	// Kind says what happened to that source's answer.
	Kind EvidenceChange `json:"kind"`
	// Before/After are the two claims, each attributed with its own URL and
	// the observation it came from. Both are set for Changed and
	// FailureTextChanged; only the relevant one for Added or Removed.
	Before EvidenceSide `json:"before,omitempty"`
	After  EvidenceSide `json:"after,omitempty"`
	// FailureText is the #24 signature, reported explicitly: the source was
	// already failing and only the wording of the failure moved. The verdict
	// is unchanged and so is the state of the world it describes — only the
	// transport's description of the failure changed, which is exactly what
	// breaks hash reproduction with no real change behind it.
	FailureText bool `json:"failure_text_only,omitempty"`
}

// EvidenceSide is one source's answer as one observation carried it.
type EvidenceSide struct {
	URL   string `json:"url"`
	Claim string `json:"claim"`
}

// String renders the event for logs and CLI output.
func (e EvidenceEvent) String() string {
	var b strings.Builder
	b.WriteString(e.Source)
	b.WriteString(": ")
	b.WriteString(string(e.Kind))
	if e.FailureText {
		b.WriteString(" (failure text only)")
	}
	return b.String()
}

// EvidenceChange is the kind of difference between a before and after answer.
type EvidenceChange string

const (
	// EvidenceAdded means a source answered in the later observation that had
	// not answered in the earlier one.
	EvidenceAdded EvidenceChange = "added"
	// EvidenceRemoved means a source stopped answering: it became unavailable
	// between the two observations. Distinguished from Changed because a
	// source going silent is a fact about our view, not about the asset.
	EvidenceRemoved EvidenceChange = "removed"
	// EvidenceChanged means a source that answered both times changed its
	// answer.
	EvidenceChanged EvidenceChange = "changed"
)

// EvidenceTransition compares the evidence sets of two observations and
// reports what moved between them.
//
// It is meaningful on a Valid transition — same verdict, changed evidence —
// and that is the case it exists for: the verifier's "hash mismatch with no
// explanation". It does not hide a verdict change: when base severity,
// mechanics or final severity moved, the result carries EvidenceVerdictChanged
// and no events, because "evidence-only" would be a lie. A comparison that
// could not be made returns Unknown or Missing with no events, exactly as the
// capability detectors do; a caller that reads only Events collapses "no
// difference" into "no answer", so it has to read State.
//
// Sources are keyed by Source string, and one entry per source is expected —
// the shape every check currently produces. If a source ever carries two
// entries, the first is compared first-wins and the rest are ignored; every
// check today emits at most one entry per source, so a second would be a new
// decision to make deliberately rather than something this comparison should
// guess at.
func EvidenceTransition(from, to Observation) EvidenceResult {
	// Order the pair by time, exactly as Between does.
	t := Between(from, to)
	r := EvidenceResult{State: t.State, Reason: t.Reason}
	if t.State != Valid {
		return r
	}

	// The verdict is the thing "evidence-only" is relative to. Any movement
	// there and the right answer is "the verdict changed", not a list.
	if t.BaseBefore != t.BaseAfter ||
		t.From.Mechanics != t.To.Mechanics ||
		t.SeverityBefore != t.SeverityAfter {
		r.VerdictChanged = true
		r.Reason = "the verdict changed between the two observations, so any " +
			"evidence differences are reported through the capability and " +
			"severity transitions rather than as evidence-only change."
		return r
	}

	r.Events = evidenceEvents(t.From.Evidence, t.To.Evidence)
	r.Unchanged = len(r.Events) == 0
	return r
}

// EvidenceResult is the comparison of two observations' evidence sets.
type EvidenceResult struct {
	// State is Valid only when the comparison could be made; Unknown and
	// Missing carry no events, for the same reason the capability detectors
	// carry no bits on those states.
	State  State  `json:"state"`
	Reason string `json:"reason,omitempty"`

	// VerdictChanged marks that severity or mechanics moved between the two
	// observations. Events is empty when set: the verdict is the story, and an
	// evidence diff beside it would read as the headline.
	VerdictChanged bool `json:"verdict_changed,omitempty"`
	// Events are the per-source differences, sorted by source for stable
	// output.
	Events []EvidenceEvent `json:"events,omitempty"`
	// Unchanged is true when the comparison was made and nothing differed. It
	// is a real answer, distinct from State != Valid, which is no answer.
	Unchanged bool `json:"unchanged,omitempty"`
}

// evidenceEvents diffs two evidence sets keyed by source. A source carrying
// more than one entry is compared first-wins; no check today emits two.
func evidenceEvents(from, to []mechanics.Evidence) []EvidenceEvent {
	index := func(evs []mechanics.Evidence) map[string]mechanics.Evidence {
		m := make(map[string]mechanics.Evidence, len(evs))
		for _, e := range evs {
			if _, dup := m[e.Source]; !dup {
				m[e.Source] = e
			}
		}
		return m
	}

	fromM := index(from)
	toM := index(to)

	var out []EvidenceEvent
	seen := map[string]bool{}
	for src, after := range toM {
		seen[src] = true
		before, ok := fromM[src]
		if !ok {
			out = append(out, EvidenceEvent{
				Source: src,
				Kind:   EvidenceAdded,
				After:  sideOf(after),
			})
			continue
		}
		switch {
		case before.Claim == after.Claim && before.URL == after.URL:
			// Same answer from the same source; nothing moved.
		case isFailure(before.Claim) && isFailure(after.Claim):
			// Both sides are transport or fetch failures. Nothing about the
			// asset is known to have changed; only our view of the failure
			// did. This is the #24 signature.
			out = append(out, EvidenceEvent{
				Source:      src,
				Kind:        EvidenceChanged,
				Before:      sideOf(before),
				After:       sideOf(after),
				FailureText: true,
			})
		default:
			out = append(out, EvidenceEvent{
				Source: src,
				Kind:   EvidenceChanged,
				Before: sideOf(before),
				After:  sideOf(after),
			})
		}
	}
	for src, before := range fromM {
		if seen[src] {
			continue
		}
		out = append(out, EvidenceEvent{
			Source: src,
			Kind:   EvidenceRemoved,
			Before: sideOf(before),
		})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out
}

// sideOf projects an Evidence into the comparison's own shape.
func sideOf(e mechanics.Evidence) EvidenceSide {
	return EvidenceSide{URL: e.URL, Claim: e.Claim}
}

// isFailure reports whether a claim is a recorded fetch failure rather than an
// answer from the source. Both checks that record failures prefix them this
// way: check_domain.go writes "not retrievable: <err>" and
// check_reputation.go writes the same prefix for an unreachable source.
//
// This is deliberately a prefix match on the codebase's own convention and
// deliberately narrow. Classifying arbitrary natural-language claims as
// failure or answer would be heuristics in a judgment path, which this package
// does not do.
func isFailure(claim string) bool {
	return strings.HasPrefix(claim, "not retrievable:")
}

// DescribeEvidenceEvent renders a human-readable sentence for one event, so a
// CLI or report can print what moved without re-deriving it.
func DescribeEvidenceEvent(e EvidenceEvent) string {
	var b strings.Builder
	switch e.Kind {
	case EvidenceAdded:
		fmt.Fprintf(&b, "%s answered where it had not before: %q", e.Source, e.After.Claim)
	case EvidenceRemoved:
		fmt.Fprintf(&b, "%s became unavailable between the two observations: %q", e.Source, e.Before.Claim)
	case EvidenceChanged:
		if e.FailureText {
			fmt.Fprintf(&b, "%s still fails, and only the failure text changed "+
				"(the reproducibility signature of #24): %q -> %q",
				e.Source, e.Before.Claim, e.After.Claim)
		} else {
			fmt.Fprintf(&b, "%s changed its answer: %q -> %q", e.Source, e.Before.Claim, e.After.Claim)
		}
	default:
		fmt.Fprintf(&b, "%s: %s", e.Source, e.Kind)
	}
	return b.String()
}
