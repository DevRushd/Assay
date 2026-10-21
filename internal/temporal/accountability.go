package temporal

import "github.com/use-assay/assay/internal/mechanics"

// AccountabilityMovement is the accountability axis of a transition: whether
// the party publicly claiming an asset changed between two observations.
//
// Accountability is deliberately independent of severity: a verified domain
// does not make confiscation safer, and losing verification does not give an
// issuer a power it did not hold. That is why this is its own movement rather
// than folded into SeverityMovement. It is still a fact a holder may care about
// — "the issuer used to publish a claim naming this asset and no longer does" —
// and the evidence detectors cannot report it because accountability is not an
// Evidence entry.
//
// Like the other detectors it reports a State. A comparison that could not be
// made returns Unknown or Missing with no verdict, so a consumer cannot read an
// empty movement as "unchanged" when one side was partial.
type AccountabilityMovement struct {
	Before mechanics.Accountability `json:"before"`
	After  mechanics.Accountability `json:"after"`
	// Changed is meaningful only when State is Valid.
	Changed bool  `json:"changed"`
	State   State `json:"state"`
	// Reason explains a non-Valid state in plain language.
	Reason string `json:"reason,omitempty"`
}

// AccountabilityTransition derives the accountability movement between two
// observations. It is built on Between, so it inherits the same ordering and
// the same refusal to compare a partial observation.
func AccountabilityTransition(from, to Observation) AccountabilityMovement {
	t := Between(from, to)
	m := AccountabilityMovement{State: t.State, Reason: t.Reason}
	if t.State != Valid {
		return m
	}
	m.Before, m.After = t.From.Accountability, t.To.Accountability
	m.Changed = m.Before != m.After
	return m
}
