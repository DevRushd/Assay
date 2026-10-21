package mechanics_test

// TestSeverityNeverBelowMaximumCapabilityFinding is the property test behind
// the severity model's central promise: aggregation may raise a level, and
// nothing it aggregates over may ever lower one (#35).
//
// The claim was previously supported by reading Engine.Run plus one
// example-based test per fixture. Fixtures cover the combinations somebody
// thought to write down; the promise is about every combination, including the
// ones that never appear in testdata. So this generates finding sets directly —
// varying severity, the escalation flag, mechanics, undetermined and
// accountability — and asserts the invariant over all of them.
//
// Both halves are here on purpose:
//
//   - "generated" runs a seeded pseudo-random generator over full finding sets.
//     The seed is fixed so a failure reproduces exactly, but nothing depends on
//     the seed: the properties must hold for every set the generator can
//     produce, or the test is wrong to pass.
//   - "exhaustive" walks every (capability severity, escalation severity) pair
//     in the whole severity domain. That is a small, finite space, so it is
//     enumerated rather than sampled — the one place sampling could miss a
//     combination is the one place the price of certainty is 36 runs.

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/use-assay/assay/internal/mechanics"
)

// severityDomain is every severity a finding may carry, in order, including
// Unevaluated. Unevaluated means "the issuer's flags were never read", so it is
// not a level in the ABI — but a finding can certainly carry it, and the
// aggregation rules have to hold for it rather than only for 0..4.
var severityDomain = []mechanics.Severity{
	mechanics.Clear,
	mechanics.Low,
	mechanics.Medium,
	mechanics.High,
	mechanics.Critical,
	mechanics.Unevaluated,
}

// capabilityBits and escalationBits split the mechanic bitset by what the
// escalation invariant allows a finding to set. An escalation finding may set
// any non-capability bit (blocklisted, domain_unverified, the trustline-scoped
// bits) and no capability bit; Engine.Run rejects the latter outright, so a
// generator that produced it would be testing the guard, not the aggregation.
var (
	capabilityBits = []mechanics.Mechanic{
		mechanics.MechAuthRequired,
		mechanics.MechAuthRevocable,
		mechanics.MechClawbackEnabled,
	}
	nonCapabilityBits = []mechanics.Mechanic{
		mechanics.MechFlagsLocked,
		mechanics.MechDomainUnverified,
		mechanics.MechBlocklisted,
		mechanics.MechTrustlineClawbackEnabled,
		mechanics.MechTrustlineDeauthorized,
	}
)

// fixedCheck is a Check with a hard-coded result, so the engine can be handed a
// generated set of findings. Generating Subjects instead would test the checks
// that produce findings; the subject here is the aggregation in Engine.Run.
type fixedCheck struct{ finding mechanics.Finding }

func (c fixedCheck) ID() string       { return c.finding.Check }
func (c fixedCheck) Describe() string { return c.finding.Title }
func (c fixedCheck) Run(context.Context, *mechanics.Subject) (mechanics.Finding, error) {
	return c.finding, nil
}

// runFindings runs the engine over exactly these findings, in order.
//
// The Subject is empty rather than nil: Engine.Run reads its ScannedAt, and a
// nil one would test the crash instead of the aggregation.
func runFindings(t *testing.T, findings []mechanics.Finding) *mechanics.Report {
	t.Helper()
	checks := make([]mechanics.Check, 0, len(findings))
	for _, f := range findings {
		checks = append(checks, fixedCheck{finding: f})
	}
	rep, err := (&mechanics.Engine{Checks: checks}).Run(context.Background(), &mechanics.Subject{})
	if err != nil {
		t.Fatalf("Run over generated findings: %v\nfindings: %s", err, describeFindings(findings))
	}
	if rep == nil {
		t.Fatal("Run returned a nil report with a nil error")
	}
	return rep
}

// assertMonotonicity states the invariant as five properties of the report,
// each phrased as something a consumer could rely on rather than as a
// re-implementation of Engine.Run's body.
func assertMonotonicity(t *testing.T, findings []mechanics.Finding, rep *mechanics.Report) {
	t.Helper()

	// maxCapability is the issue's phrase: the greatest severity any finding
	// that claims capability reached. Escalation findings are excluded because
	// reputation is not capability.
	var maxCapability, maxEscalation, maxAny mechanics.Severity
	unevaluated := false
	for _, f := range findings {
		if f.Severity > maxAny {
			maxAny = f.Severity
		}
		if f.Severity == mechanics.Unevaluated {
			unevaluated = true
		}
		if f.Escalation {
			if f.Severity > maxEscalation {
				maxEscalation = f.Severity
			}
		} else if f.Severity > maxCapability {
			maxCapability = f.Severity
		}
	}

	// 1. The final severity is never below the capability base. This is the
	//    promise in one line.
	if rep.Severity < rep.Base {
		t.Errorf("severity %v below base %v\nfindings: %s",
			rep.Severity, rep.Base, describeFindings(findings))
	}

	// 2. Nothing aggregated over was discounted: no finding outranks the
	//    report's final severity. A finding that was lowered, ignored, or
	//    averaged away would show up here.
	if rep.Severity < maxAny {
		t.Errorf("severity %v below finding severity %v: a finding was discounted\nfindings: %s",
			rep.Severity, maxAny, describeFindings(findings))
	}
	if rep.Severity < maxCapability {
		t.Errorf("severity %v below max capability severity %v\nfindings: %s",
			rep.Severity, maxCapability, describeFindings(findings))
	}

	// 3. The base is capability only: escalation contributes nothing to it.
	if rep.Base != maxCapability {
		t.Errorf("base %v != max capability severity %v\nfindings: %s",
			rep.Base, maxCapability, describeFindings(findings))
	}

	// 4. Final severity is base raised by escalation and nothing else, and
	//    Escalated means exactly that it was raised. Both directions matter:
	//    Escalated true with an unchanged level would claim reputation changed
	//    something it did not, and Escalated false after a raise would hide it.
	want := maxEscalation
	if maxCapability > want {
		want = maxCapability
	}
	if rep.Severity != want {
		t.Errorf("severity %v != max(base %v, escalation %v) = %v\nfindings: %s",
			rep.Severity, maxCapability, maxEscalation, want, describeFindings(findings))
	}
	if rep.Escalated != (rep.Severity > rep.Base) {
		t.Errorf("escalated %v but severity %v vs base %v\nfindings: %s",
			rep.Escalated, rep.Severity, rep.Base, describeFindings(findings))
	}

	// 5. Reputation that is not higher moves nothing. This is the sharpest
	//    form of "raise a level, never lower one": an escalation finding at or
	//    below the capability base must leave both severity and the escalated
	//    flag exactly where capability alone would put them.
	if maxEscalation <= maxCapability {
		if rep.Severity != maxCapability {
			t.Errorf("escalation at %v (not above base %v) moved severity to %v; "+
				"reputation must not lower a level\nfindings: %s",
				maxEscalation, maxCapability, rep.Severity, describeFindings(findings))
		}
		if rep.Escalated {
			t.Errorf("escalated is true although the highest escalation (%v) does not exceed "+
				"the capability base (%v)\nfindings: %s",
				maxEscalation, maxCapability, describeFindings(findings))
		}
	}

	// 6. An unread flag never renders as a permissive answer. A finding that
	//    could not be evaluated must leave the report unknown, whatever else
	//    the set contains, so that Clear is only ever reached by reading flags
	//    and finding none.
	if unevaluated && rep.State != mechanics.StateUnknown {
		t.Errorf("a finding is unevaluated but state is %q, not unknown\nfindings: %s",
			rep.State, describeFindings(findings))
	}
}

// TestSeverityNeverBelowMaximumCapabilityFinding is the property test itself.
func TestSeverityNeverBelowMaximumCapabilityFinding(t *testing.T) {
	t.Run("exhaustive/severity-pairs", func(t *testing.T) {
		// No findings at all, then every capability/escalation pair. Zero
		// findings is not a degenerate case to skip: an empty engine must
		// report clear rather than anything a consumer could read as a claim.
		rep := runFindings(t, nil)
		assertMonotonicity(t, nil, rep)
		if rep.Severity != mechanics.Clear || rep.Base != mechanics.Clear || rep.Escalated {
			t.Fatalf("empty finding set: base=%v severity=%v escalated=%v, want all clear",
				rep.Base, rep.Severity, rep.Escalated)
		}

		for _, capability := range severityDomain {
			for _, escalation := range severityDomain {
				findings := []mechanics.Finding{
					{
						Check:     "capability",
						Title:     "capability finding",
						Severity:  capability,
						Mechanics: mechanics.MechAuthRevocable,
					},
					{
						Check:      "reputation",
						Title:      "reputation escalation",
						Severity:   escalation,
						Escalation: true,
						Mechanics:  mechanics.MechBlocklisted,
					},
				}
				rep := runFindings(t, findings)
				assertMonotonicity(t, findings, rep)

				// The exhaustive half can state the outcome exactly, not just
				// bound it: the report is the capability severities plus any
				// escalation that is strictly higher.
				want := capability
				if escalation > want {
					want = escalation
				}
				if rep.Severity != want || rep.Base != capability {
					t.Errorf("capability %v + escalation %v: base=%v severity=%v, want base=%v severity=%v",
						capability, escalation, rep.Base, rep.Severity, capability, want)
				}
				if rep.Escalated != (escalation > capability) {
					t.Errorf("capability %v + escalation %v: escalated=%v, want %v",
						capability, escalation, rep.Escalated, escalation > capability)
				}
			}
		}
	})

	t.Run("generated/finding-sets", func(t *testing.T) {
		// Fixed seed: a failure is reproducible from this number alone. Note
		// the assertions do not depend on it — a set this generator can
		// produce is a set the invariant must hold for.
		rng := rand.New(rand.NewSource(0x35_2026))
		for i := 0; i < 2000; i++ {
			findings := generatedFindings(rng, 1+rng.Intn(8))
			rep := runFindings(t, findings)
			assertMonotonicity(t, findings, rep)
		}
	})
}

// generatedFindings builds a random set of findings: mixed severities, a
// capability or escalation label, mechanics, undetermined, and accountability.
//
// Escalation findings draw only from the non-capability bits, because an
// escalation that sets a capability bit is a hard error in Engine.Run and would
// make this test measure the guard instead of the aggregation. That guard has
// its own tests in escalation_test.go.
func generatedFindings(rng *rand.Rand, n int) []mechanics.Finding {
	findings := make([]mechanics.Finding, 0, n)
	for i := 0; i < n; i++ {
		escalation := rng.Intn(4) == 0
		f := mechanics.Finding{
			Check:      fmt.Sprintf("generated-%d", i),
			Title:      fmt.Sprintf("generated finding %d", i),
			Severity:   severityDomain[rng.Intn(len(severityDomain))],
			Escalation: escalation,
			Reasoning:  "generated; see monotonicity_test.go",
		}

		bits := nonCapabilityBits
		if !escalation {
			bits = append(append([]mechanics.Mechanic{}, capabilityBits...), nonCapabilityBits...)
		}
		for _, bit := range bits {
			if rng.Intn(100) < 35 {
				f.Mechanics |= bit
			}
		}

		f.Undetermined = rng.Intn(10) == 0

		// Accountability is varied deliberately: it is reported alongside
		// severity and must not influence it in any direction, so a set that
		// carries one is a set where a leak would be visible.
		switch rng.Intn(4) {
		case 0:
			a := mechanics.AccountabilityUnknown
			f.Accountability = &a
		case 1:
			a := mechanics.AccountabilityUnverified
			f.Accountability = &a
		case 2:
			a := mechanics.AccountabilityVerified
			f.Accountability = &a
		}

		findings = append(findings, f)
	}
	return findings
}

// describeFindings renders a generated set so a failure names the input that
// produced it, not just the seed.
func describeFindings(findings []mechanics.Finding) string {
	out := "["
	for i, f := range findings {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("{check:%s severity:%v escalation:%v mech:%v undetermined:%v}",
			f.Check, f.Severity, f.Escalation, f.Mechanics.Names(), f.Undetermined)
	}
	return out + "]"
}
