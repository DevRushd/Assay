package temporal_test

import (
	"testing"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/temporal"
)

// testIssuer is DOGE-GA22IDJN… from the eval set: the asset whose base severity
// is 0 and final severity is 4, used throughout these tests as the shape of a
// reputation-only move.
const testIssuer = "GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P"

func at(day int) time.Time { return time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC) }

// obs builds an observation with distinct times supplied by the caller. The
// severity arguments are passed separately from the bits so a test can express
// the DOGE shape — capability bits clear, final severity escalated — which is
// the case that has to survive any transition computation intact.
func obs(t time.Time, bits mechanics.Mechanic, base, sev mechanics.Severity) temporal.Observation {
	return temporal.Observation{
		Asset:     mechanics.Asset{Code: "DOGE", Issuer: testIssuer},
		At:        t,
		Mechanics: bits,
		Base:      base,
		Severity:  sev,
	}
}

// Between orders the pair by time rather than trusting argument order, so a
// caller reading history newest-first still gets a difference in the right
// direction. Getting this backwards would silently invert additions into
// removals, which is the worst possible way to be wrong about this question.
func TestBetweenOrdersThePairByTime(t *testing.T) {
	older := obs(at(1), 0, mechanics.Clear, mechanics.Clear)
	newer := obs(at(2), mechanics.MechClawbackEnabled, mechanics.High, mechanics.High)

	tr := temporal.Between(newer, older)

	if !tr.From.At.Equal(older.At) || !tr.To.At.Equal(newer.At) {
		t.Fatalf("pair not ordered by time: from=%v to=%v", tr.From.At, tr.To.At)
	}
	if tr.Added != mechanics.MechClawbackEnabled {
		t.Fatalf("a reversed pair inverted the direction: added=%v", tr.Added.Names())
	}
}

// A series of three must compare its two most recent observations, and a series
// with fewer than two must report Missing rather than silently comparing a
// single observation against itself and returning "no change".
func TestOfUsesTheTwoMostRecentObservations(t *testing.T) {
	first := obs(at(1), 0, mechanics.Clear, mechanics.Clear)
	second := obs(at(2), mechanics.MechAuthRevocable, mechanics.Medium, mechanics.Medium)
	third := obs(at(3), mechanics.MechAuthRevocable|mechanics.MechClawbackEnabled, mechanics.High, mechanics.High)

	tr := temporal.Of([]temporal.Observation{third, first, second})
	if tr.State != temporal.Valid {
		t.Fatalf("three complete observations produced state %q: %s", tr.State, tr.Reason)
	}
	if !tr.From.At.Equal(second.At) || !tr.To.At.Equal(third.At) {
		t.Fatalf("comparison did not use the two most recent: from=%v to=%v", tr.From.At, tr.To.At)
	}
}

// The distinction this whole package is built around: one observation is not a
// transition, and it is not a no-change result either.
func TestSingleObservationIsMissingNotUnchanged(t *testing.T) {
	tr := temporal.Of([]temporal.Observation{obs(at(1), 0, mechanics.Clear, mechanics.Clear)})
	if tr.State != temporal.Missing {
		t.Fatalf("a single observation produced state %q, want %q", tr.State, temporal.Missing)
	}
	if tr.Reason == "" {
		t.Fatal("missing state must carry a reason, or it is indistinguishable from a silent failure")
	}

	// And the derived detectors inherit that state rather than reporting an
	// empty difference, which is the bug the State field exists to prevent.
	if d := temporal.Added(tr.From, tr.To); d.State != temporal.Missing || d.Bits != 0 {
		t.Fatalf("added on a single observation = %+v, want missing with no bits", d)
	}
	if d := temporal.Removed(tr.From, tr.To); d.State != temporal.Missing || d.Bits != 0 {
		t.Fatalf("removed on a single observation = %+v, want missing with no bits", d)
	}
}

// ObservationFromReport must copy, not alias, the report it is built from.
func TestObservationFromReportCopies(t *testing.T) {
	rep := &mechanics.Report{
		Asset:              mechanics.Asset{Code: "DOGE", Issuer: testIssuer},
		Base:               mechanics.Clear,
		Severity:           mechanics.Critical,
		Mechanics:          mechanics.MechBlocklisted,
		Undetermined:       true,
		UndeterminedChecks: []string{"reputation"},
		ScannedAt:          mechanics.NewCanonicalTime(at(3)),
	}

	o := temporal.ObservationFromReport(rep)
	rep.UndeterminedChecks[0] = "mutated"
	rep.Mechanics = 0

	if o.UndeterminedChecks[0] != "reputation" {
		t.Fatal("observation aliased the report's undetermined checks")
	}
	if o.Mechanics != mechanics.MechBlocklisted {
		t.Fatal("observation is not a snapshot of the report it was built from")
	}
}
