package mechanics_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// escalationCapabilityViolations returns one description for every finding
// marked Escalation that sets a capability bit. Empty output means the
// invariant holds.
//
// The deployed gate masks CapabilityMask out of the report bitset and trusts
// what it sees as "the power the issuer holds on the ledger". Reputation
// escalation raises severity and sets blocklisted (bit 5); if it ever set bits
// 0-2, a masked consumer would see a power the issuer does not hold. This
// helper is the assertion the invariant is checked with, and the negative test
// below proves it actually fires on a violation.
func escalationCapabilityViolations(findings []mechanics.Finding) []string {
	var out []string
	for _, f := range findings {
		if f.Escalation && f.Mechanics&mechanics.CapabilityMask != 0 {
			out = append(out, fmt.Sprintf(
				"escalation finding %q sets capability bits %v",
				f.Check, (f.Mechanics&mechanics.CapabilityMask).Names()))
		}
	}
	return out
}

// TestEscalationNeverSetsCapabilityBits asserts the invariant behind the
// gate's correctness: a finding with Escalation == true contributes no
// capability bit (CapabilityMask, bits 0-2) to the report. It runs over every
// eval fixture — the two escalating ones prove the invariant under escalation,
// the other three prove it does not accidentally pass only because nothing
// escalated — and over hand-built subjects with reputation escalations.
//
// Bit positions are ABI: auth_required 1<<0, auth_revocable 1<<1,
// auth_clawback_enabled 1<<2. See docs/contract-interface.md and
// docs/severity-model.md.
func TestEscalationNeverSetsCapabilityBits(t *testing.T) {
	eng := mechanics.NewEngine()

	// Every eval fixture, escalating or not.
	fixtures := []string{
		"aqua-clear-verified",
		"shx-clear-flagslocked",
		"usdc-revocable-regulated",
		"berkshire-clawback-scam",
		"doge-noflags-scam",
	}
	for _, dir := range fixtures {
		t.Run("fixture/"+dir, func(t *testing.T) {
			rep, err := eng.Run(context.Background(), loadSubject(t, dir))
			if err != nil {
				t.Fatal(err)
			}
			// Engine.Run also guards this at runtime; assert it anyway so the
			// test fails if the guard is ever removed.
			if v := escalationCapabilityViolations(rep.Findings); len(v) > 0 {
				t.Errorf("%s: escalation set capability bits: %v", dir, v)
			}
			assertReportCapabilityBitsFromNonEscalationOnly(t, dir, rep)
		})
	}

	// Hand-built subject: a revocable issuer whose directory entry carries the
	// malicious tag, so reputation escalates on top of a real capability base.
	t.Run("hand-built/escalated-over-revocable", func(t *testing.T) {
		s := escalatingSubject(t, horizon.Flags{AuthRevocable: true})
		rep, err := eng.Run(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		if !rep.Escalated || rep.Severity != mechanics.Critical {
			t.Fatalf("expected an escalated critical report, got escalated=%v severity=%v",
				rep.Escalated, rep.Severity)
		}
		if v := escalationCapabilityViolations(rep.Findings); len(v) > 0 {
			t.Errorf("escalation set capability bits: %v", v)
		}
		assertReportCapabilityBitsFromNonEscalationOnly(t, "escalated-over-revocable", rep)
		// The only capability bit in the report must come from the capability
		// check reading the flag, never from the escalation.
		if got := rep.Mechanics & mechanics.CapabilityMask; got != mechanics.MechAuthRevocable {
			t.Errorf("report capability bits = %v, want exactly [auth_revocable]", got.Names())
		}
	})

	// Hand-built subject: no auth flags at all, escalated to critical by
	// reputation alone. The case the gate masks for: a consumer reading only
	// capability bits out of a CRITICAL report must see an issuer with no
	// powers whatsoever.
	t.Run("hand-built/escalated-no-flags", func(t *testing.T) {
		s := escalatingSubject(t, horizon.Flags{})
		rep, err := eng.Run(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		if !rep.Escalated || rep.Severity != mechanics.Critical {
			t.Fatalf("expected an escalated critical report, got escalated=%v severity=%v",
				rep.Escalated, rep.Severity)
		}
		if v := escalationCapabilityViolations(rep.Findings); len(v) > 0 {
			t.Errorf("escalation set capability bits: %v", v)
		}
		if got := rep.Mechanics & mechanics.CapabilityMask; got != 0 {
			t.Errorf("critical-by-escalation report carries capability bits %v; "+
				"a masked consumer would see a power the issuer does not hold",
				got.Names())
		}
	})
}

// assertReportCapabilityBitsFromNonEscalationOnly checks the report surface a
// consumer actually reads: the aggregated bitset's capability bits must equal
// the OR of the non-escalation findings' capability bits.
func assertReportCapabilityBitsFromNonEscalationOnly(t *testing.T, name string, rep *mechanics.Report) {
	t.Helper()
	var want mechanics.Mechanic
	for _, f := range rep.Findings {
		if !f.Escalation {
			want |= f.Mechanics & mechanics.CapabilityMask
		}
	}
	if got := rep.Mechanics & mechanics.CapabilityMask; got != want {
		t.Errorf("%s: report capability bits = %v, want %v (non-escalation findings only)",
			name, got.Names(), want.Names())
	}
}

// escalatingSubject hand-builds a Subject whose curated directory tags the
// issuer malicious, with the given issuer flags. Nothing here touches the
// network: checks are pure functions over the Subject.
func escalatingSubject(t *testing.T, flags horizon.Flags) *mechanics.Subject {
	t.Helper()
	const (
		code = "TRAP"
		// Not a real account ID; nothing in this test path validates it, and
		// the checks are pure functions over the subject.
		issuer = "GBADISSUERESCALATIONTEST00000000000000000000000000000000"
		domain = "malicious.example"
	)
	fetched := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	return &mechanics.Subject{
		Asset: mechanics.Asset{Code: code, Issuer: issuer},
		Stat: &horizon.AssetStat{
			AssetType:   "credit_alphanum4",
			AssetCode:   code,
			AssetIssuer: issuer,
			Flags:       flags,
		},
		StatFetchedAt:   fetched,
		Issuer:          &horizon.Account{AccountID: issuer, HomeDomain: domain, Flags: flags},
		IssuerFetchedAt: fetched,
		TomlURL:         "https://" + domain + "/.well-known/stellar.toml",
		// No Toml and no TomlErr: home_domain is set, so DomainCheck will
		// report the unreachable toml, which is fine — it sets
		// domain_unverified, a non-capability bit.
		TomlAttemptedAt: fetched,
		DirectoryURL:    "https://api.stellar.expert/explorer/directory/" + issuer,
		Directory: &stellarexpert.DirectoryEntry{
			Address: issuer,
			Name:    "Known trap",
			Domain:  domain,
			Tags:    []string{"malicious"},
		},
		DirectoryFetchedAt:   fetched,
		DirectoryAttemptedAt: fetched,
		BlockedURL:           "https://api.stellar.expert/explorer/directory/blocked-domains/" + domain,
		Blocked:              &stellarexpert.BlockedDomain{Domain: domain, Blocked: true},
		BlockedFetchedAt:     fetched,
		BlockedAttemptedAt:   fetched,
		ScannedAt:            fetched,
	}
}

// TestEngineRejectsEscalationSettingCapabilityBits exercises the runtime
// guard in Engine.Run directly: a check that returns an escalation finding
// carrying a capability bit must make Run fail loudly, not get its bits
// silently masked into the report.
func TestEngineRejectsEscalationSettingCapabilityBits(t *testing.T) {
	bugged := buggedEscalationCheck{}
	eng := mechanics.Engine{Checks: []mechanics.Check{bugged}}
	rep, err := eng.Run(context.Background(), escalatingSubject(t, horizon.Flags{}))
	if err == nil {
		t.Fatalf("Engine.Run accepted an escalation finding setting capability bits "+
			"%v; the runtime guard is not working",
			(buggedFinding.Mechanics & mechanics.CapabilityMask).Names())
	}
	if rep != nil {
		t.Errorf("Run returned a report alongside the error; want nil on failure")
	}
	if !strings.Contains(err.Error(), "capability bits") {
		t.Errorf("error %q does not name the violated invariant", err)
	}
}

// buggedEscalationCheck is a deliberately broken check: it escalates (as
// ReputationCheck is the only check permitted to do) and sets a capability
// bit — the exact bug class the invariant exists to catch.
type buggedEscalationCheck struct{}

var buggedFinding = mechanics.Finding{
	Check:      "bugged-escalation",
	Title:      "Deliberately broken escalation",
	Severity:   mechanics.Critical,
	Escalation: true,
	// Bit 2: the capability bit the issue names as the dangerous one.
	Mechanics: mechanics.MechClawbackEnabled,
}

func (buggedEscalationCheck) ID() string       { return buggedFinding.Check }
func (buggedEscalationCheck) Describe() string { return buggedFinding.Title }
func (buggedEscalationCheck) Run(context.Context, *mechanics.Subject) (mechanics.Finding, error) {
	return buggedFinding, nil
}

// TestEscalationCapabilityMutationIsCaught is the negative half of the
// invariant: it feeds the assertion a deliberately bugged escalation finding
// — one that sets clawback (bit 2), exactly what a careless edit to
// ReputationCheck could produce — and requires the assertion to flag it. If
// someone edits check_reputation.go to set a capability bit, both this
// pattern and Engine.Run's runtime guard fail loudly; nothing masks the bit
// and carries on.
func TestEscalationCapabilityMutationIsCaught(t *testing.T) {
	s := escalatingSubject(t, horizon.Flags{AuthRevocable: true})
	rep, err := mechanics.NewEngine().Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: the unmutated findings satisfy the invariant.
	if v := escalationCapabilityViolations(rep.Findings); len(v) > 0 {
		t.Fatalf("precondition failed: unmutated report already violates the invariant: %v", v)
	}

	// Mutate the escalation finding the way the bug would.
	var bugged *mechanics.Finding
	for i := range rep.Findings {
		if rep.Findings[i].Escalation {
			bugged = &rep.Findings[i]
			break
		}
	}
	if bugged == nil {
		t.Fatal("precondition failed: no escalation finding in the report")
	}
	bugged.Mechanics |= mechanics.MechClawbackEnabled

	v := escalationCapabilityViolations(rep.Findings)
	if len(v) == 0 {
		t.Fatal("the assertion did not catch an escalation finding setting " +
			"auth_clawback_enabled: it would not catch the real bug either")
	}
}
