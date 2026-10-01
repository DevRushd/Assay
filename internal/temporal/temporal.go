// Package temporal compares two observations of the same asset to answer what
// changed between them.
//
// Every check in internal/mechanics answers a prospective question: what can
// this issuer do to a trustline opened now. That is the right question for
// someone deciding whether to open one, and it is exactly what current issuer
// flags answer. It is the wrong question for a holder who already holds the
// asset and wants to know what moved since they last looked.
//
// Nothing here re-derives a verdict. An Observation carries the bitset and the
// severity a mechanics.Report already produced; this package only subtracts one
// observation from another. The comparison is a pure function over two
// observations — no storage, no I/O, no network. Where observations come from
// is a separate decision, written down in docs/transitions.md.
//
// Two distinctions are load-bearing, and the types enforce them rather than
// leaving them to prose:
//
//   - An empty difference is not the same as no answer. A comparison that was
//     made and found nothing returns State Valid with an empty bitset; a
//     comparison that could not be made returns State Unknown or Missing. A
//     consumer that reads only the bitset would collapse the two, so a caller
//     has to read State.
//   - A single observation yields no transition. That is State Missing, and it
//     is not "no change": there was never a second point to compare against.
//
// The representation was reviewed against internal/mechanics/mechanics.go. Every
// field of Observation is a copy of a field that file already defines on Report
// or Subject; no new severity semantics are introduced here. See
// docs/transitions.md for the mapping and the reasoning.
package temporal

import (
	"sort"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
)

// Observation is one asset's capability at one time.
//
// It is a value captured from a mechanics.Report rather than something this
// package fetches: the comparison has no source of its own, and an observation
// that could reach the network would make the transition it feeds
// non-deterministic.
type Observation struct {
	Asset mechanics.Asset `json:"asset"`
	// At is when the observation was taken. Two observations are comparable
	// only when their times are distinct; see Between.
	At time.Time `json:"at"`
	// Mechanics is the full mechanic bitset the report carried, not only the
	// capability bits. It is kept whole so that a later question about a bit
	// this package does not yet compare does not require the observation to be
	// re-taken.
	Mechanics mechanics.Mechanic `json:"mechanics"`
	// Base is capability-only severity, before reputation escalation.
	Base mechanics.Severity `json:"base_severity"`
	// Severity is the final severity the report produced.
	Severity mechanics.Severity `json:"severity"`
	// Undetermined reports that a source the observation depends on did not
	// answer, so the observation is a partial answer and nothing may be
	// concluded from what it omits.
	Undetermined bool `json:"undetermined"`
	// UndeterminedChecks names the checks that did not complete, so a consumer
	// can see which axis is missing rather than only that one is.
	UndeterminedChecks []string `json:"undetermined_checks,omitempty"`
	// Evidence is the attributed evidence the report carried, one entry per
	// consumed signal. It is kept so a later comparison can answer "did our
	// view of the asset change, or did the asset change" — the question a
	// verifier is left with when an evidence_hash matches no re-scan. See
	// EvidenceTransition in evidence.go.
	Evidence []mechanics.Evidence `json:"evidence,omitempty"`
}

// ObservationFromReport captures an Observation from a completed scan.
//
// It copies rather than references: a stored observation must not change when a
// later report is produced, or a transition would be computed against a moving
// target.
func ObservationFromReport(rep *mechanics.Report) Observation {
	return Observation{
		Asset:              rep.Asset,
		At:                 rep.ScannedAt.Time(),
		Mechanics:          rep.Mechanics,
		Base:               rep.Base,
		Severity:           rep.Severity,
		Undetermined:       rep.Undetermined,
		UndeterminedChecks: append([]string{}, rep.UndeterminedChecks...),
		Evidence:           append([]mechanics.Evidence{}, rep.Evidence...),
	}
}

// State says whether a transition could be derived at all.
//
// It is a separate axis from the difference itself, because "nothing changed"
// and "I cannot tell you" are different answers and must never render the same.
// That rule is repo-wide; it was stated first in docs/checks.md and is repeated
// here as a type rather than as a convention.
type State string

const (
	// Valid means two complete observations with distinct times. A Valid
	// transition may still carry an empty difference; that is "no change".
	Valid State = "valid"
	// Unknown means one or both observations are undetermined, so no transition
	// can be derived. It is not "no change": a source that did not answer could
	// have hidden exactly the change being asked about.
	Unknown State = "unknown"
	// Missing means fewer than two observations exist, so there is nothing to
	// compare. It is not "no change" either; there was no second point.
	Missing State = "missing"
)

// Transition is an ordered pair of observations and the difference derived
// between them.
//
// The pair is kept whole rather than reduced to the difference, because the
// difference alone cannot be audited: a consumer has to be able to see what each
// observation actually said, and a State of Unknown or Missing has to be
// explainable in terms of which input was incomplete.
type Transition struct {
	Asset mechanics.Asset `json:"asset"`
	From  Observation     `json:"from"`
	To    Observation     `json:"to"`
	State State           `json:"state"`
	// Reason explains a non-Valid state in plain language, so a reader is never
	// told "unknown" without being told what was missing.
	Reason string `json:"reason,omitempty"`

	// Added and Removed are the capability bits that appeared and disappeared
	// between the two observations. Reported-only bits, auth_immutable, and the
	// trustline bits are not capabilities and never appear in either; see
	// CapabilityMask.
	Added        mechanics.Mechanic `json:"added"`
	Removed      mechanics.Mechanic `json:"removed"`
	AddedNames   []string           `json:"added_names"`
	RemovedNames []string           `json:"removed_names"`

	// BaseBefore/BaseAfter and SeverityBefore/SeverityAfter carry the two
	// severity axes across the pair. Base is capability-only; Severity is after
	// reputation escalation. They are reported both ways so that a movement can
	// be attributed rather than merely observed.
	BaseBefore     mechanics.Severity `json:"base_before"`
	BaseAfter      mechanics.Severity `json:"base_after"`
	SeverityBefore mechanics.Severity `json:"severity_before"`
	SeverityAfter  mechanics.Severity `json:"severity_after"`
	// Attribution names which axis moved severity, if any.
	Attribution Attribution `json:"attribution"`
}

// Between derives the transition from one observation to the next.
//
// The pair is ordered by time, so a caller that passes the newest observation
// first still gets a difference in the right direction rather than an inverted
// one. Two observations at the same instant are not ordered and cannot define a
// change, so that is reported as Unknown rather than as "no change".
func Between(from, to Observation) Transition {
	t := Transition{Asset: to.Asset, From: from, To: to}

	if to.At.Before(from.At) {
		t.From, t.To = to, from
	}

	switch {
	case t.From.At.IsZero() || t.To.At.IsZero():
		t.State = Missing
		t.Reason = "fewer than two observations: a transition is the difference " +
			"between two points in time, and only one is present here. This is " +
			"not a no-change result."
		return t
	case t.From.At.Equal(t.To.At):
		t.State = Unknown
		t.Reason = "both observations carry the same timestamp, so neither is " +
			"later than the other and the direction of the change is undefined. " +
			"This is not a no-change result."
		return t
	case t.From.Undetermined || t.To.Undetermined:
		t.State = Unknown
		t.Reason = "an observation is undetermined because a source did not " +
			"answer, so what it omits must not be read as unchanged. " +
			undeterminedReason(t.From, t.To)
		return t
	}

	t.State = Valid
	before := t.From.Mechanics & CapabilityMask
	after := t.To.Mechanics & CapabilityMask
	t.Added = after &^ before
	t.Removed = before &^ after
	t.AddedNames = t.Added.Names()
	t.RemovedNames = t.Removed.Names()
	t.BaseBefore, t.BaseAfter = t.From.Base, t.To.Base
	t.SeverityBefore, t.SeverityAfter = t.From.Severity, t.To.Severity
	t.Attribution = attribution(t.From, t.To)
	return t
}

// Of derives the transition between the two most recent observations in a
// series, ordering the series by time first.
//
// Fewer than two observations is State Missing, so an asset that has only ever
// been seen once does not present as unchanged. This is the shape a caller has
// after reading history that turns out to contain a single entry, which is the
// difference between "we have looked twice and nothing moved" and "we have
// looked once".
func Of(observations []Observation) Transition {
	if len(observations) < 2 {
		var only Observation
		if len(observations) == 1 {
			only = observations[0]
		}
		return Between(only, Observation{})
	}

	ordered := append([]Observation(nil), observations...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].At.Before(ordered[j].At)
	})
	return Between(ordered[len(ordered)-2], ordered[len(ordered)-1])
}

// undeterminedReason names the incomplete side and the checks that did not
// complete, so the missing axis is visible rather than inferred.
func undeterminedReason(from, to Observation) string {
	side := func(o Observation) string {
		checks := "an unnamed check"
		if len(o.UndeterminedChecks) > 0 {
			checks = joinChecks(o.UndeterminedChecks)
		}
		return checks
	}
	switch {
	case from.Undetermined && to.Undetermined:
		return "Both observations are partial (" + side(from) + " and " +
			side(to) + " did not complete), so neither side is a full picture."
	case from.Undetermined:
		return "The earlier observation is partial (" + side(from) +
			" did not complete), so a bit absent there may only be unread."
	default:
		return "The later observation is partial (" + side(to) +
			" did not complete), so a bit absent there may only be unread."
	}
}

func joinChecks(checks []string) string {
	out := ""
	for i, c := range checks {
		switch {
		case i == 0:
			out = c
		case i == len(checks)-1:
			out += " and " + c
		default:
			out += ", " + c
		}
	}
	return out
}
