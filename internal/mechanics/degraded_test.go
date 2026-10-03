package mechanics_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// These tests cover the case the fixture-backed eval structurally cannot
// express. loadSubject in eval_test.go builds a Subject from files on disk, so
// a missing directory.json is indistinguishable from a directory that never
// answered — which is precisely the confusion under test. They therefore build
// a Subject directly.

const testIssuer = "GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P"

// subject builds a Subject with no authorization flags, so capability is Clear
// and reputation is the only axis in play. It carries a home_domain and a clean
// blocked-domain answer by default, so the reputation axis is fully consulted:
// these tests are about a source that did answer failing, and a subject with no
// domain would instead be the (separate) "blocklist could not even be asked"
// case, which check_reputation_scope_test.go covers.
func subject(mut func(*mechanics.Subject)) *mechanics.Subject {
	fetched := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	const domain = "doge-issuer.test"
	s := &mechanics.Subject{
		Asset:  mechanics.Asset{Code: "DOGE", Issuer: testIssuer},
		Stat:   &horizon.AssetStat{AssetCode: "DOGE", AssetIssuer: testIssuer},
		Issuer: &horizon.Account{AccountID: testIssuer, HomeDomain: domain},

		DirectoryURL:         "https://api.stellar.expert/explorer/directory/" + testIssuer,
		DirectoryAttemptedAt: fetched,
		BlockedURL:           "https://api.stellar.expert/explorer/directory/blocked-domains/" + domain,
		Blocked:              &stellarexpert.BlockedDomain{Domain: domain, Blocked: false},
		BlockedFetchedAt:     fetched,
		BlockedAttemptedAt:   fetched,
		StatFetchedAt:        fetched,
		IssuerFetchedAt:      fetched,
		ScannedAt:            fetched,
	}
	if mut != nil {
		mut(s)
	}
	return s
}

func run(t *testing.T, s *mechanics.Subject) *mechanics.Report {
	t.Helper()
	rep, err := mechanics.NewEngine().Run(context.Background(), s)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}
	return rep
}

// The rule docs/checks.md states: "'We could not check' and 'this is fine' are
// different answers and must never render the same." This is that rule as a
// test, for the two sources where it was not previously honoured.
func TestOutageDoesNotRenderAsNotListed(t *testing.T) {
	notListed := run(t, subject(nil))
	outage := run(t, subject(func(s *mechanics.Subject) {
		s.DirectoryErr = "stellarexpert: get " + s.DirectoryURL + ": status 429"
	}))

	if notListed.Undetermined {
		t.Fatal("a source that answered 'not listed' must not mark the report undetermined")
	}
	if !outage.Undetermined {
		t.Fatal("an unreachable source must mark the report undetermined")
	}

	// Structural, not merely textual: a consumer parsing JSON has to be able to
	// tell these apart without reading English.
	if len(outage.UndeterminedChecks) != 1 || outage.UndeterminedChecks[0] != "reputation" {
		t.Fatalf("expected the reputation check named as undetermined, got %v", outage.UndeterminedChecks)
	}

	// The old wording asserted the absence was normal. It must not survive an
	// outage.
	for _, f := range outage.Findings {
		if f.Check == "reputation" && strings.Contains(f.Reasoning, "the normal case") {
			t.Fatalf("outage still reported as the normal case: %q", f.Reasoning)
		}
	}
}

// The failure has to reach the report as attributed evidence, the same way an
// unreachable stellar.toml already does, or it is not auditable.
func TestUnreachableSourceIsRecordedAsEvidence(t *testing.T) {
	rep := run(t, subject(func(s *mechanics.Subject) {
		s.DirectoryErr = "stellarexpert: get x: status 503"
	}))

	var found bool
	for _, e := range rep.Evidence {
		if e.Source == "stellar.expert/directory" && strings.Contains(e.Claim, "not retrievable") {
			found = true
			if !strings.Contains(e.Claim, "503") {
				t.Errorf("evidence dropped the underlying failure: %q", e.Claim)
			}
			if e.URL == "" {
				t.Error("evidence recorded no URL, so the claim cannot be re-checked")
			}
		}
	}
	if !found {
		t.Fatalf("no attributed evidence for the unreachable source: %+v", rep.Evidence)
	}
}

// Both endpoints are consumed independently, so either being down has to count.
func TestEitherSourceFailingIsEnough(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*mechanics.Subject)
	}{
		{"directory", func(s *mechanics.Subject) { s.DirectoryErr = "status 429" }},
		{"blocklist", func(s *mechanics.Subject) {
			s.Issuer.HomeDomain = "example.test"
			s.BlockedURL = "https://api.stellar.expert/explorer/directory/blocked-domains/example.test"
			s.BlockedErr = "context deadline exceeded"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !run(t, subject(tc.mut)).Undetermined {
				t.Fatalf("%s failing did not mark the report undetermined", tc.name)
			}
		})
	}
}

// Severity must not be inflated to cover the gap. Inventing a level Assay did
// not measure would be the same class of dishonesty as the bug being fixed,
// pointed the other way.
func TestOutageDoesNotInflateSeverity(t *testing.T) {
	rep := run(t, subject(func(s *mechanics.Subject) {
		s.DirectoryErr = "status 429"
	}))

	if rep.Severity != mechanics.Clear {
		t.Fatalf("severity was raised to %v to compensate for a missing source; it must stay at the measured capability", rep.Severity)
	}
	if rep.Base != mechanics.Clear {
		t.Fatalf("base severity moved to %v; capability was fully readable and must be unaffected", rep.Base)
	}
}

// Failure evidence must carry the attempt time of its own source, and must
// say programmatically that it is an attempt rather than an answer — a consumer
// must not have to parse the English claim to tell the two apart.
func TestFailureEvidenceCarriesAttemptTime(t *testing.T) {
	const attempted = "2026-09-05T00:00:01Z"
	rep := run(t, subject(func(s *mechanics.Subject) {
		s.DirectoryErr = "stellarexpert: get x: status 503"
		s.DirectoryAttemptedAt = mustTime(t, attempted)
	}))

	var found bool
	for _, ev := range rep.Evidence {
		if ev.Source != "stellar.expert/directory" {
			continue
		}
		found = true
		if !ev.Attempted {
			t.Error("failure evidence is not marked Attempted: an attempt is not an answer")
		}
		if !ev.RetrievedAt.Time().Equal(mustTime(t, attempted)) {
			t.Errorf("failure evidence carries %s, want the attempt time %s", ev.RetrievedAt, attempted)
		}
	}
	if !found {
		t.Fatal("no failure evidence for the unreachable directory")
	}
}

// Acceptance: evidence_hash for the labelled fixtures is unchanged by this
// work. Retrieval times are excluded from the preimage, so per-source times
// must not move it — and if they ever do, the attested assets stop verifying.
func TestEvidenceHashUnchangedAcrossTheLabelledSet(t *testing.T) {
	dirs := []string{
		"aqua-clear-verified", "shx-clear-flagslocked", "usdc-revocable-regulated",
		"berkshire-clawback-scam", "doge-noflags-scam",
	}
	eng := mechanics.NewEngine()
	for _, dir := range dirs {
		rep, err := eng.Run(context.Background(), loadSubject(t, dir))
		if err != nil {
			t.Fatalf("%s: run: %v", dir, err)
		}
		params, err := attest.FromReport(rep)
		if err != nil {
			t.Fatalf("%s: FromReport: %v", dir, err)
		}
		// Re-deriving the hash with every evidence time shifted far into the
		// future: identical output is the property under test, because the
		// preimage commits to claims, not to the clock.
		for i := range rep.Evidence {
			rep.Evidence[i].RetrievedAt = mechanics.NewCanonicalTime(rep.Evidence[i].RetrievedAt.Time().Add(100 * 24 * time.Hour))
		}
		rep.ScannedAt = mechanics.NewCanonicalTime(rep.ScannedAt.Time().Add(100 * 24 * time.Hour))
		shifted, err := attest.FromReport(rep)
		if err != nil {
			t.Fatalf("%s: FromReport (shifted): %v", dir, err)
		}
		if params.EvidenceHash != shifted.EvidenceHash {
			t.Errorf("%s: retrieval times moved the evidence_hash: %s != %s",
				dir, params.EvidenceHash, shifted.EvidenceHash)
		}
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return at
}

// A malicious listing that did arrive still decides the question. Evidence of
// abuse does not become less true because a second endpoint timed out, and
// Critical is the ceiling, so nothing missing could raise the level further.
func TestPositiveListingStillEscalatesWhenTheOtherSourceIsDown(t *testing.T) {
	rep := run(t, subject(func(s *mechanics.Subject) {
		s.Issuer.HomeDomain = "example.test"
		s.BlockedURL = "https://api.stellar.expert/explorer/directory/blocked-domains/example.test"
		s.BlockedErr = "status 503"
		s.Directory = &stellarexpert.DirectoryEntry{
			Address: testIssuer,
			Name:    "Scam Asset",
			Domain:  "example.test",
			Tags:    []string{"malicious", "unsafe"},
		}
	}))

	if rep.Severity != mechanics.Critical {
		t.Fatalf("a confirmed malicious listing must still escalate, got %v", rep.Severity)
	}
	if !rep.Escalated {
		t.Fatal("escalation flag not set on a confirmed listing")
	}
	if rep.Undetermined {
		t.Fatal("the answer was reached at the ceiling severity; nothing missing could change it, so it is not undetermined")
	}
}
