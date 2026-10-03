package mechanics

import (
	"fmt"
	"time"
)

// DefaultFreshnessWindow is the 24-hour window from docs/freshness.md and
// the example gate contract (MAX_ATTESTATION_AGE).
const DefaultFreshnessWindow = 24 * time.Hour

// FreshnessEvaluator evaluates whether a report is fresh or stale relative to
// a policy window and reference time.
type FreshnessEvaluator struct {
	// Window is how old a verdict may be before it is considered stale.
	// A non-positive window means no freshness window is enforced.
	Window time.Duration

	// Now returns the reference time for freshness evaluation.
	// Defaults to time.Now().UTC if nil.
	Now func() time.Time
}

// NewFreshnessEvaluator returns an evaluator with the given policy window.
// A window <= 0 disables freshness checking (matching is_safe's max_age_secs = 0).
func NewFreshnessEvaluator(window time.Duration) *FreshnessEvaluator {
	return &FreshnessEvaluator{
		Window: window,
		Now:    func() time.Time { return time.Now().UTC() },
	}
}

// DefaultEvaluator returns an evaluator configured with DefaultFreshnessWindow (24h).
func DefaultEvaluator() *FreshnessEvaluator {
	return NewFreshnessEvaluator(DefaultFreshnessWindow)
}

// Evaluate evaluates rep's freshness as of the evaluator's reference time.
func (e *FreshnessEvaluator) Evaluate(rep *Report) *Report {
	now := time.Now().UTC()
	if e != nil && e.Now != nil {
		now = e.Now()
	}
	var window time.Duration
	if e != nil {
		window = e.Window
	}
	return EvaluateFreshness(rep, now, window)
}

// EvaluateFreshness evaluates a report against reference time asOf and policy window.
//
// Rules:
//   - An unknown/undetermined/unevaluated report cannot become stale:
//     staleness applies only to verdicts that were complete when made.
//   - If window <= 0, the freshness check is disabled.
//   - If asOf.Sub(rep.ScannedAt) > window, the report is marked Stale = true and State = StateStale.
//   - If within the window, Stale = false and State = StateValid.
func EvaluateFreshness(rep *Report, asOf time.Time, window time.Duration) *Report {
	if rep == nil {
		return nil
	}
	// A report that could not conclude remains unknown, never stale.
	if rep.Undetermined || rep.Base == Unevaluated || rep.Severity == Unevaluated {
		rep.State = StateUnknown
		rep.Stale = false
		rep.StaleReason = ""
		return rep
	}

	if window <= 0 {
		rep.Stale = false
		rep.State = StateValid
		rep.StaleReason = ""
		return rep
	}

	if rep.ScannedAt.IsZero() {
		rep.Stale = false
		rep.State = StateValid
		rep.StaleReason = ""
		return rep
	}

	age := asOf.Sub(rep.ScannedAt.Time())
	if age > window {
		rep.Stale = true
		rep.State = StateStale
		rep.StaleReason = fmt.Sprintf("verdict age %s exceeds policy window %s", age.Round(time.Second), window)
	} else {
		rep.Stale = false
		rep.State = StateValid
		rep.StaleReason = ""
	}
	return rep
}

// EvaluateFreshness updates the report's freshness state relative to asOf and window.
func (r *Report) EvaluateFreshness(asOf time.Time, window time.Duration) *Report {
	return EvaluateFreshness(r, asOf, window)
}

// MarkStale explicitly marks a report as stale with a reason.
func (r *Report) MarkStale(reason string) {
	if r.Undetermined || r.Base == Unevaluated || r.Severity == Unevaluated {
		// A check that could not conclude remains unknown, not stale.
		r.State = StateUnknown
		return
	}
	r.Stale = true
	r.State = StateStale
	r.StaleReason = reason
}

// IsStale reports whether the report has been determined to be stale.
func (r *Report) IsStale() bool {
	return r.Stale || r.State == StateStale
}

// IsValid reports whether the report is a fresh, complete verdict.
func (r *Report) IsValid() bool {
	return r.State == StateValid && !r.Stale && !r.Undetermined
}
