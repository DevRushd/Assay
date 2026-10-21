package mechanics

// State represents the overall verdict state of a report.
//
// It separates usable answers from incomplete or expired ones. Assay learned
// this lesson in three steps:
//  1. An unreachable source once rendered as a clean result (#23);
//  2. Clear doubled as not-evaluated (#32);
//  3. Stale is the third member: a verdict that was complete when made, but is
//     now older than the policy window (#57).
//
// Like Unevaluated, State is designed so that a program never has to parse
// prose or confuse "no answer" or "expired answer" with "safe answer".
type State string

const (
	// StateValid indicates a fresh, complete verdict: all checks completed and
	// the report is within its freshness policy window.
	StateValid State = "valid"

	// StateUnknown indicates a check could not conclude: either because a
	// source was unreachable (undetermined) or flags were never evaluated
	// (unevaluated).
	StateUnknown State = "unknown"

	// StateStale indicates the verdict was complete when made, but is now older
	// than the policy window. It cannot be attested as fresh or relied upon as
	// a current verdict.
	StateStale State = "stale"

	// Valid is an alias for StateValid matching the issue semantics.
	Valid = StateValid
	// Unknown is an alias for StateUnknown matching the issue semantics.
	Unknown = StateUnknown
	// Stale is an alias for StateStale matching the issue semantics.
	Stale = StateStale
)

// String returns the wire string representation of State.
func (s State) String() string {
	return string(s)
}
