package mechanics_test

import (
	"context"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
)

// These tests drive internal/mechanics/testdata/synthetic-flag-disagreement/,
// a fixture with the issuer's account.json reporting auth_clawback_enabled
// while its asset.json does not. No such asset was observed: Horizon's two
// copies of the issuer flags agreed on every asset checked live (see
// testdata/PROVENANCE.md), which is why the disagreement path needs a
// constructed fixture — it cannot be captured from the network.
//
// The synthetic fixture is deliberately not added to TestEval: that set is
// labelled real captures only, and a synthetic subject would change what the
// eval measures.

// The fixture's disagreement: the account copy carries clawback, the asset
// record copy does not.
func loadDisagreement(t *testing.T) *mechanics.Subject {
	t.Helper()
	return loadSubject(t, "synthetic-flag-disagreement")
}

// capFinding isolates the capability finding from a report.
func capFinding(t *testing.T, rep *mechanics.Report) mechanics.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Check == "capability" {
			return f
		}
	}
	t.Fatalf("no capability finding in report: %+v", rep.Findings)
	return mechanics.Finding{}
}

// mutFinding isolates the mutability finding from a report. Since #171 the
// auth_immutable lock statement lives on the mutability finding, so the
// agreement tests below read it there rather than on the capability finding.
func mutFinding(t *testing.T, rep *mechanics.Report) mechanics.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Check == "mutability" {
			return f
		}
	}
	t.Fatalf("no mutability finding in report: %+v", rep.Findings)
	return mechanics.Finding{}
}

// runEngine is the same engine the live scanner runs.
func runEngine(t *testing.T, s *mechanics.Subject) *mechanics.Report {
	t.Helper()
	rep, err := mechanics.NewEngine().Run(context.Background(), s)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}
	return rep
}

// The acceptance rule, as a test: when the two flag sets differ, the resolved
// severity is the more dangerous of the two readings. The asset record alone
// says medium (revocable); the account alone says high (clawback). Resolving
// in the holder's favour would be a way for a stale copy to lower a severity,
// which is the one direction this project never resolves.
func TestDisagreementResolvesAgainstTheHolder(t *testing.T) {
	rep := runEngine(t, loadDisagreement(t))

	if rep.Base != mechanics.High {
		t.Fatalf("base severity = %v, want high: the account copy reports auth_clawback_enabled, "+
			"and the resolution must take the more dangerous of the two readings", rep.Base)
	}
	if rep.Mechanics&mechanics.ConfiscationMask == 0 {
		t.Fatal("resolved mechanics lost the clawback bit")
	}
}

// A disagreement must be reported explicitly in the reasoning, not silently
// resolved. A reader given only a severity cannot tell a clean read from a
// reconciled one.
func TestDisagreementIsStatedInTheReasoning(t *testing.T) {
	f := capFinding(t, runEngine(t, loadDisagreement(t)))

	if !strings.Contains(f.Reasoning, "disagree") {
		t.Fatalf("reasoning does not state the disagreement: %q", f.Reasoning)
	}
	for _, want := range []string{
		"auth_clawback_enabled",
		"asset record false",
		"issuer account true",
		"more dangerous",
	} {
		if !strings.Contains(f.Reasoning, want) {
			t.Errorf("reasoning missing %q: %q", want, f.Reasoning)
		}
	}
}

// Each source must be attributed with its own URL, so the reader can re-fetch
// both copies and settle the disagreement themselves. One entry citing two
// facts would not be checkable.
func TestDisagreementAttributesEachSourceWithItsOwnURL(t *testing.T) {
	s := loadDisagreement(t)
	f := capFinding(t, runEngine(t, s))

	iss := s.Asset.Issuer
	want := map[string]string{
		"https://horizon.stellar.org/assets?asset_code=USDC&asset_issuer=" + iss: "issuer flags: ",
		"https://horizon.stellar.org/accounts/" + iss:                            "issuer account flags: ",
	}
	seen := map[string]bool{}
	for _, e := range f.Evidence {
		prefix, ok := want[e.URL]
		if !ok {
			continue
		}
		if !strings.Contains(e.Claim, prefix) ||
			!strings.Contains(e.Claim, "auth_clawback_enabled=") {
			t.Errorf("evidence at %s does not carry that source's own flag summary: %q", e.URL, e.Claim)
		}
		seen[e.URL] = true
	}
	for url := range want {
		if !seen[url] {
			t.Errorf("no evidence entry for %s; both copies must be cited on disagreement", url)
		}
	}
	if len(f.Evidence) != 2 {
		t.Errorf("evidence entries = %d, want exactly the two disagreeing sources: %+v",
			len(f.Evidence), f.Evidence)
	}
}

// The second source is cited only when it disagrees. Attaching it to every
// report would change the evidence_hash of every attestation already written
// for an asset whose two copies agree — which is all of them. This is the
// no-regression half of the acceptance criteria: existing eval subjects keep
// their current severities and their single evidence entry.
func TestAgreedSourcesKeepSeverityAndOneEvidenceEntry(t *testing.T) {
	for _, dir := range []string{
		"aqua-clear-verified", "shx-clear-flagslocked", "usdc-revocable-regulated",
		"berkshire-clawback-scam", "doge-noflags-scam",
	} {
		t.Run(dir, func(t *testing.T) {
			s := loadSubject(t, dir)
			rep := runEngine(t, s)
			f := capFinding(t, rep)

			if len(f.Evidence) != 1 {
				t.Fatalf("agreeing sources produced %d evidence entries, want 1 (a second entry "+
					"would change every existing evidence_hash): %+v", len(f.Evidence), f.Evidence)
			}
			if strings.Contains(f.Reasoning, "disagree") {
				t.Fatalf("reasoning reports a disagreement the fixture does not contain: %q", f.Reasoning)
			}
		})
	}
}

// auth_immutable is not a power over a holder, so it is not resolved against
// the holder like the power flags are. It is claimed only when both copies
// agree it is set: asserting a lock one source contradicts would hand the
// reader a reassurance the evidence does not support. Since #171 the lock
// statement itself lives on the mutability finding — which now reads the same
// reconciled flag set the capability check resolves severity from — so the
// agreement rule is asserted there.
func TestAuthImmutableIsClaimedOnlyWhenBothSourcesAgree(t *testing.T) {
	t.Run("both agree it is set, so the lock is stated", func(t *testing.T) {
		s := loadDisagreement(t)
		s.Stat.Flags.AuthImmutable = true
		s.Issuer.Flags.AuthImmutable = true

		f := mutFinding(t, runEngine(t, s))
		if !strings.Contains(f.Reasoning, "locked (auth_immutable is set)") {
			t.Fatalf("auth_immutable agreed by both sources but the lock is not stated: %q", f.Reasoning)
		}
	})

	for _, tc := range []struct {
		name string
		set  func(*mechanics.Subject)
	}{
		{"asset record only", func(s *mechanics.Subject) {
			s.Stat.Flags.AuthImmutable, s.Issuer.Flags.AuthImmutable = true, false
		}},
		{"account only", func(s *mechanics.Subject) {
			s.Stat.Flags.AuthImmutable, s.Issuer.Flags.AuthImmutable = false, true
		}},
	} {
		t.Run("disagreement, so no lock is claimed: "+tc.name, func(t *testing.T) {
			s := loadDisagreement(t)
			tc.set(s)

			f := mutFinding(t, runEngine(t, s))
			if strings.Contains(f.Reasoning, "locked (auth_immutable is set)") {
				t.Fatalf("lock asserted although %s contradicts it: %q", tc.name, f.Reasoning)
			}
			// The cautious reading, whatever the clawback branch: the flags are
			// not locked, so they may change.
			if !strings.Contains(f.Reasoning, "not locked") {
				t.Fatalf("disagreed lock did not keep the cautious reading: %q", f.Reasoning)
			}
		})
	}
}

// The resolution is deterministic and never in the holder's favour. Each power
// flag is held by exactly one copy, in each direction; the resolved severity
// must be the higher of what the two copies report alone, in every case.
func TestResolutionNeverSitsBelowEitherSource(t *testing.T) {
	flags := func(f horizon.Flags) func(*mechanics.Subject) {
		return func(s *mechanics.Subject) { s.Stat.Flags = f }
	}
	cases := []struct {
		name        string
		assetCopy   horizon.Flags
		accountCopy horizon.Flags
	}{
		{"revocable on the asset record only",
			horizon.Flags{AuthRevocable: true}, horizon.Flags{}},
		{"revocable on the account only",
			horizon.Flags{}, horizon.Flags{AuthRevocable: true}},
		{"clawback on the asset record only",
			horizon.Flags{AuthClawbackEnabled: true}, horizon.Flags{}},
		{"clawback on the account only",
			horizon.Flags{}, horizon.Flags{AuthClawbackEnabled: true}},
		{"required on the asset record, revocable on the account",
			horizon.Flags{AuthRequired: true}, horizon.Flags{AuthRevocable: true}},
		{"clawback on the asset record, revocable on the account",
			horizon.Flags{AuthClawbackEnabled: true}, horizon.Flags{AuthRevocable: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := loadDisagreement(t)
			// Start from a level field: both copies empty, then set each side.
			s.Stat.Flags, s.Issuer.Flags = horizon.Flags{}, horizon.Flags{}
			flags(tc.assetCopy)(s)
			s.Issuer.Flags = tc.accountCopy

			f := capFinding(t, runEngine(t, s))
			want := severityOf(tc.assetCopy)
			if acct := severityOf(tc.accountCopy); acct > want {
				want = acct
			}
			if f.Severity != want {
				t.Fatalf("resolved severity = %v, want %v (the more dangerous of "+
					"asset copy %v and account copy %v)", f.Severity, want,
					severityOf(tc.assetCopy), severityOf(tc.accountCopy))
			}
		})
	}
}

// severityOf is the level CapabilityCheck assigns a flag set on its own.
func severityOf(f horizon.Flags) mechanics.Severity {
	s := mechanics.Clear
	if f.AuthRequired {
		s = mechanics.Low
	}
	if f.AuthRevocable {
		s = mechanics.Medium
	}
	if f.AuthClawbackEnabled {
		s = mechanics.High
	}
	return s
}

// The disagreement text and resolution must be stable across runs: same input,
// same output, no map iteration or time dependence.
func TestDisagreementReportIsStableAcrossRuns(t *testing.T) {
	first := capFinding(t, runEngine(t, loadDisagreement(t)))
	second := capFinding(t, runEngine(t, loadDisagreement(t)))

	if first.Reasoning != second.Reasoning {
		t.Fatalf("reasoning not stable between runs:\n%q\n%q", first.Reasoning, second.Reasoning)
	}
	if len(first.Evidence) != len(second.Evidence) {
		t.Fatalf("evidence count not stable: %d then %d", len(first.Evidence), len(second.Evidence))
	}
}

// An issuer account that did not resolve must not be read as agreement. The
// asset record's flags stand alone and the report does not claim a comparison
// that never happened — the yFLR case from the attestation run, where Horizon
// serves the /assets record but the /accounts record is gone.
func TestIssuerWithoutAccountKeepsTheAssetRecordFlags(t *testing.T) {
	s := loadDisagreement(t)
	s.Issuer = nil

	f := capFinding(t, runEngine(t, s))

	if f.Severity != mechanics.Medium {
		t.Fatalf("severity = %v, want medium: with no account copy the asset record is the only read", f.Severity)
	}
	if strings.Contains(f.Reasoning, "disagree") {
		t.Fatalf("a missing account was rendered as a disagreement: %q", f.Reasoning)
	}
	if len(f.Evidence) != 1 {
		t.Fatalf("evidence entries = %d, want 1: there is only one source to cite", len(f.Evidence))
	}
}
