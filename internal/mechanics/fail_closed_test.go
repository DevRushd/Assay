package mechanics_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
)

// These tests back docs/fail-closed.md (#108): every site claimed fail-closed
// there carries a named test, and the TestFailClosed* family below covers the
// claims that had no test naming them before. Each one feeds the failure the
// site is supposed to survive and asserts the output is no more permissive
// than the truth — not merely that the code runs.
//
// The rule every test here encodes: a failure must yield a result no more
// permissive than success would have. "We could not check" and "this is fine"
// are different answers and must never render the same.

// errCheck is a check whose Run always fails, standing in for any check that
// cannot reach a decision.
type errCheck struct{}

func (errCheck) ID() string       { return "failing-check" }
func (errCheck) Describe() string { return "always fails" }
func (errCheck) Run(context.Context, *mechanics.Subject) (mechanics.Finding, error) {
	return mechanics.Finding{}, errors.New("failing-check: source unreachable")
}

// TestFailClosedEngineCheckErrorProducesNoReport pins G5: a check error must
// abort the whole run. A report that dropped the failed check and aggregated
// the rest would read as complete to every consumer — the exact shape of the
// #23/#25 bugs one level down.
func TestFailClosedEngineCheckErrorProducesNoReport(t *testing.T) {
	eng := mechanics.Engine{Checks: []mechanics.Check{errCheck{}}}
	rep, err := eng.Run(context.Background(), subject(nil))
	if err == nil {
		t.Fatal("Engine.Run accepted a check error and produced a report")
	}
	if rep != nil {
		t.Fatalf("Run returned a report (%d findings) alongside the error; want nil on failure",
			len(rep.Findings))
	}
}

// TestFailClosedCapabilityOutageIsUnevaluatedNotClear re-states G4 through the
// report surface: with the flags unread, the report must not only refuse to
// say Clear, it must be non-attestable — the property attest.FromReport relies
// on. The severity findings below it must not have been averaged away into a
// number nobody measured.
func TestFailClosedCapabilityOutageIsUnevaluatedNotClear(t *testing.T) {
	rep := run(t, subject(func(s *mechanics.Subject) {
		s.Stat = nil // the flags were never read
	}))

	if !rep.Undetermined {
		t.Fatal("a report whose capability axis was never read is not marked undetermined")
	}
	if rep.Severity == mechanics.Clear {
		t.Fatal("report severity is Clear although the flags were never read")
	}
	var cap = mechanics.Clear
	for _, f := range rep.Findings {
		if f.Check == "capability" {
			cap = f.Severity
		}
	}
	if cap != mechanics.Unevaluated {
		t.Fatalf("capability finding severity = %v, want the Unevaluated sentinel", cap)
	}
}

// TestFailClosedTrustlineOutageIsUndetermined pins F7: a holder trustline
// fetch that fails must leave the holder-specific answer undetermined. It must
// not render as "no clawback on this trustline" — the permissive reading of
// nothing.
func TestFailClosedTrustlineOutageIsUndetermined(t *testing.T) {
	s := subject(func(s *mechanics.Subject) {
		s.Holder = testIssuer
		s.HolderTrustlineErr = "horizon: get /accounts/x: status 503"
		s.HolderAttemptedAt = time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	})
	eng := mechanics.Engine{Checks: append([]mechanics.Check{}, mechanics.NewEngine().Checks...)}
	eng.Checks = append(eng.Checks, mechanics.TrustlineCheck{})

	rep, err := eng.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !rep.Undetermined {
		t.Fatal("a trustline outage did not mark the report undetermined")
	}
	var trustline *mechanics.Finding
	for i := range rep.Findings {
		if rep.Findings[i].Check == "trustline" {
			trustline = &rep.Findings[i]
		}
	}
	if trustline == nil {
		t.Fatal("no trustline finding in the report")
	}
	if !trustline.Undetermined {
		t.Fatal("trustline finding is not undetermined; a fetch failure rendered as an answer")
	}
	if trustline.Mechanics&mechanics.MechTrustlineClawbackEnabled != 0 ||
		trustline.Mechanics&mechanics.MechTrustlineDeauthorized != 0 {
		t.Fatalf("trustline finding asserted mechanic bits %v from a failed fetch",
			trustline.Mechanics.Names())
	}
}

// TestFailClosedFlagDisagreementResolvesAgainstTheHolder re-states G8 as a
// fail-closed claim: when Horizon's two flag copies disagree, the resolved set
// must count a power as held if either copy reports it. Resolving to the
// quieter copy would let indexer lag lower a severity.
func TestFailClosedFlagDisagreementResolvesAgainstTheHolder(t *testing.T) {
	s := subject(func(s *mechanics.Subject) {
		// The asset record says the issuer can claw back; the account record
		// (stale or wrong) says nothing. The issuer can claw back.
		s.Stat.Flags = horizon.Flags{AuthClawbackEnabled: true}
		s.Issuer.Flags = horizon.Flags{}
	})
	rep := run(t, s)

	if rep.Base < mechanics.High {
		t.Fatalf("a clawback reported by either flag copy classified at %v; "+
			"disagreement must resolve against the holder, not in their favour", rep.Base)
	}
	if rep.Mechanics&mechanics.MechClawbackEnabled == 0 {
		t.Fatal("the clawback bit was dropped when resolving a flag disagreement")
	}
}
