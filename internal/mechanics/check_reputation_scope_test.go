package mechanics_test

import (
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/sep1"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// These tests pin the decision recorded in docs/severity-model.md: what the
// malicious-domain blocklist is keyed on, and what an unverified or absent
// domain means for escalation. They build Subjects directly because the states
// under test — a blocklist hit on a verified versus an unverified domain, and
// an issuer with no home_domain at all — are not all present in the captured
// fixtures.

const repIssuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

// repDomain is the home_domain these subjects advertise. It is deliberately not
// a real domain: nothing here is fetched.
const repDomain = "rep-issuer.test"

// repSubject builds a fully-consulted Subject: both curated sources answered and
// neither flagged anything. A test mutates it into the state it exercises.
func repSubject(mut func(*mechanics.Subject)) *mechanics.Subject {
	fetched := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	s := &mechanics.Subject{
		Asset: mechanics.Asset{Code: "USDC", Issuer: repIssuer},
		Stat: &horizon.AssetStat{
			AssetCode:   "USDC",
			AssetIssuer: repIssuer,
			Flags:       horizon.Flags{},
		},
		StatFetchedAt:        fetched,
		Issuer:               &horizon.Account{AccountID: repIssuer, HomeDomain: repDomain},
		IssuerFetchedAt:      fetched,
		TomlURL:              "https://" + repDomain + "/.well-known/stellar.toml",
		TomlAttemptedAt:      fetched,
		DirectoryURL:         "https://api.stellar.expert/explorer/directory/" + repIssuer,
		DirectoryFetchedAt:   fetched,
		DirectoryAttemptedAt: fetched,
		BlockedURL:           "https://api.stellar.expert/explorer/directory/blocked-domains/" + repDomain,
		BlockedFetchedAt:     fetched,
		BlockedAttemptedAt:   fetched,
		ScannedAt:            fetched,
	}
	if mut != nil {
		mut(s)
	}
	return s
}

// repFinding isolates the reputation finding from a report.
func repFinding(t *testing.T, rep *mechanics.Report) mechanics.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Check == "reputation" {
			return f
		}
	}
	t.Fatalf("no reputation finding in report: %+v", rep.Findings)
	return mechanics.Finding{}
}

// blocklistHit mutates a subject into a blocklist hit on domain. The domain
// string is what the source answered with; whether the association is verified
// is decided by whether the subject also carries a claiming stellar.toml.
func blocklistHit(domain string) func(*mechanics.Subject) {
	return func(s *mechanics.Subject) {
		s.Blocked = &stellarexpert.BlockedDomain{Domain: domain, Blocked: true}
		s.BlockedFetchedAt = s.BlockedAttemptedAt
	}
}

// TestReputationBlocklistHitOnVerifiedDomainEscalates is the valid state: a
// blocklist hit whose domain has reciprocally claimed the asset escalates to
// critical, and carries no caveat, because the link is verified.
func TestReputationBlocklistHitOnVerifiedDomainEscalates(t *testing.T) {
	s := repSubject(func(s *mechanics.Subject) {
		s.Toml = &sep1.Doc{Currencies: []sep1.Currency{{Code: s.Asset.Code, Issuer: s.Asset.Issuer}}}
		blocklistHit(repDomain)(s)
	})
	rep := run(t, s)

	if rep.Severity != mechanics.Critical || !rep.Escalated {
		t.Fatalf("blocklist hit on a verified domain = severity %v escalated=%v, want critical/escalated",
			rep.Severity, rep.Escalated)
	}
	if rep.Accountability != mechanics.AccountabilityVerified {
		t.Fatalf("accountability = %v, want verified", rep.Accountability)
	}
	if rep.Undetermined {
		t.Fatal("a positive listing decides the question; the report must not be undetermined")
	}
	f := repFinding(t, rep)
	if f.Severity != mechanics.Critical || !f.Escalation || f.Mechanics&mechanics.MechBlocklisted == 0 {
		t.Fatalf("reputation finding = %+v, want an escalation carrying the blocklisted bit", f)
	}
	if strings.Contains(f.Reasoning, "not verified") {
		t.Errorf("a verified domain carried the unverified caveat:\n%s", f.Reasoning)
	}
}

// TestReputationBlocklistHitOnUnverifiedDomainEscalatesWithCaveat is the
// unknown state. The escalation is kept — a curated listing is positive
// evidence and is never suppressed, because suppressing it would let a
// blocklist-only scam (the REPO shape) escape — but the report records that the
// link rests on the issuer's self-asserted domain and is not reciprocally
// verified.
func TestReputationBlocklistHitOnUnverifiedDomainEscalatesWithCaveat(t *testing.T) {
	// No Toml: the domain is advertised but has not claimed the asset.
	s := repSubject(blocklistHit(repDomain))
	rep := run(t, s)

	if rep.Severity != mechanics.Critical || !rep.Escalated {
		t.Fatalf("blocklist hit on an unverified domain = severity %v escalated=%v, want critical/escalated",
			rep.Severity, rep.Escalated)
	}
	if rep.Undetermined {
		t.Fatal("the listing arrived and decided the question; the report must not be undetermined")
	}
	if rep.Accountability != mechanics.AccountabilityUnverified {
		t.Fatalf("accountability = %v, want unverified", rep.Accountability)
	}
	if rep.Mechanics&mechanics.MechDomainUnverified == 0 {
		t.Error("an unverified-domain escalation must carry domain_unverified alongside blocklisted")
	}
	f := repFinding(t, rep)
	if !strings.Contains(f.Reasoning, "not verified") || !strings.Contains(f.Reasoning, repDomain) {
		t.Fatalf("the unverified-domain caveat is not recorded:\n%s", f.Reasoning)
	}
}

// TestReputationWithoutHomeDomainIsUndeterminedNotClean is the missing state:
// the blocklist is keyed on a domain, so with no home_domain the question cannot
// be put at all. A blocklist hit would escalate, so the severity is a floor, not
// an answer, and the report must say so instead of rendering the unread source
// as a clean one.
func TestReputationWithoutHomeDomainIsUndeterminedNotClean(t *testing.T) {
	t.Run("explicit skip recorded by the scanner", func(t *testing.T) {
		s := repSubject(func(s *mechanics.Subject) {
			s.Issuer.HomeDomain = ""
			s.TomlURL = ""
			s.BlockedURL = ""
			s.BlockedSkipped = "the issuer advertises no home_domain to key the lookup on"
		})
		assertBlocklistUnread(t, s)
	})

	t.Run("hand-built subject with no domain and no marker", func(t *testing.T) {
		// The check falls back to the home_domain itself, so a builder that
		// omits the field cannot silently reintroduce the gap.
		s := repSubject(func(s *mechanics.Subject) {
			s.Issuer.HomeDomain = ""
			s.TomlURL = ""
			s.BlockedURL = ""
		})
		assertBlocklistUnread(t, s)
	})
}

func assertBlocklistUnread(t *testing.T, s *mechanics.Subject) {
	t.Helper()
	rep := run(t, s)
	if !rep.Undetermined {
		t.Fatal("an unread blocklist must mark the report undetermined, not clean")
	}
	if len(rep.UndeterminedChecks) != 1 || rep.UndeterminedChecks[0] != "reputation" {
		t.Fatalf("undetermined checks = %v, want exactly [reputation]", rep.UndeterminedChecks)
	}
	if rep.Severity != mechanics.Clear {
		t.Fatalf("severity = %v; a missing source must not inflate severity", rep.Severity)
	}
	f := repFinding(t, rep)
	if !f.Undetermined {
		t.Fatal("the reputation finding is not marked undetermined")
	}
	if !strings.Contains(f.Reasoning, "could not be checked") {
		t.Fatalf("reasoning does not state the blocklist question could not be put:\n%s", f.Reasoning)
	}
	if strings.Contains(f.Reasoning, "the normal case") {
		t.Fatalf("an unread blocklist rendered as the normal case:\n%s", f.Reasoning)
	}
}

// TestReputationDirectoryAndBlocklistDisagree pins the captured BERKSHIRE/DOGE
// shape: the directory tags the issuer malicious while the blocklist answers
// blocked=false for the same domain. Escalation must come from the directory,
// the blocklist's negative answer must be recorded, and the result must not be
// suppressed as undetermined.
func TestReputationDirectoryAndBlocklistDisagree(t *testing.T) {
	s := repSubject(func(s *mechanics.Subject) {
		s.Directory = &stellarexpert.DirectoryEntry{
			Address: repIssuer,
			Name:    "Scam Asset",
			Domain:  repDomain,
			Tags:    []string{"malicious", "unsafe"},
		}
		s.DirectoryFetchedAt = s.DirectoryAttemptedAt
		s.Blocked = &stellarexpert.BlockedDomain{Domain: repDomain, Blocked: false}
		s.BlockedFetchedAt = s.BlockedAttemptedAt
	})
	rep := run(t, s)

	if rep.Severity != mechanics.Critical || !rep.Escalated {
		t.Fatalf("directory-only escalation = severity %v escalated=%v, want critical/escalated",
			rep.Severity, rep.Escalated)
	}
	if rep.Undetermined {
		t.Fatal("both sources answered; the report must not be undetermined")
	}
	f := repFinding(t, rep)
	if !strings.Contains(f.Reasoning, "curated directory") {
		t.Fatalf("escalation does not name the directory as its source:\n%s", f.Reasoning)
	}
	if strings.Contains(f.Reasoning, "could not be checked") {
		t.Errorf("the blocklist answered blocked=false but is reported as unread:\n%s", f.Reasoning)
	}
	var sawBlockedFalse bool
	for _, e := range f.Evidence {
		if e.Source == "stellar.expert/blocked-domains" && strings.Contains(e.Claim, "blocked=false") {
			sawBlockedFalse = true
		}
	}
	if !sawBlockedFalse {
		t.Error("the blocklist's negative answer is not recorded as evidence")
	}
}
