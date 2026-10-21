package temporal_test

import (
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/temporal"
)

// These tests drive the evidence-only detector: the class of change that
// produced the reproducibility problem in the attestation run's Finding 2
// (#24). A domain becomes unreachable, the evidence text changes, the hash
// changes, and the verdict does not — a verifier comparing hashes sees a
// mismatch with no explanation. The detector separates "the asset changed"
// from "our view of it changed".

// evidenceObs builds an observation with an evidence set attached. The default
// mechanics and severities are DOGE-shaped: no capability bits, final severity
// escalated by reputation, which is the shape where evidence is the only thing
// that can move.
func evidenceObs(day int, evs []mechanics.Evidence, mut func(*temporal.Observation)) temporal.Observation {
	o := temporal.Observation{
		Asset:     mechanics.Asset{Code: "DOGE", Issuer: testIssuer},
		At:        time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC),
		Mechanics: mechanics.MechDomainUnverified | mechanics.MechBlocklisted,
		Base:      mechanics.Clear,
		Severity:  mechanics.Critical,
		Evidence:  evs,
	}
	if mut != nil {
		mut(&o)
	}
	return o
}

func claim(source, url, claim string, day int) mechanics.Evidence {
	return mechanics.Evidence{
		Source:      source,
		URL:         url,
		Claim:       claim,
		RetrievedAt: mechanics.NewCanonicalTime(time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC)),
	}
}

// The issue's first test case: same verdict, different toml error text.
// BERKSHIRE is the real instance — its on-chain hash commits to a DNS error
// naming one machine's resolver. The verdict does not change; the hash would.
func TestEvidenceOnlyChangeSameVerdictDifferentErrorText(t *testing.T) {
	from := evidenceObs(1, []mechanics.Evidence{
		claim("stellar.toml", "https://nasdaq.finance/.well-known/stellar.toml",
			"not retrievable: dial tcp: lookup nasdaq.finance on 10.255.255.254:53: no such host", 1),
	}, nil)
	to := evidenceObs(2, []mechanics.Evidence{
		claim("stellar.toml", "https://nasdaq.finance/.well-known/stellar.toml",
			"not retrievable: context deadline exceeded", 2),
	}, nil)

	r := temporal.EvidenceTransition(from, to)

	if r.State != temporal.Valid {
		t.Fatalf("state = %q (%s), want valid", r.State, r.Reason)
	}
	if r.VerdictChanged {
		t.Fatal("verdict changed was set on a comparison whose verdict did not move")
	}
	if r.Unchanged {
		t.Fatal("the error text changed; this is not an unchanged comparison")
	}
	if len(r.Events) != 1 {
		t.Fatalf("events = %+v, want one", r.Events)
	}
	e := r.Events[0]
	if e.Source != "stellar.toml" || e.Kind != temporal.EvidenceChanged || !e.FailureText {
		t.Fatalf("event = %+v, want a changed event on stellar.toml flagged failure-text-only", e)
	}
	if !strings.Contains(e.Before.Claim, "10.255.255.254") ||
		!strings.Contains(e.After.Claim, "deadline") {
		t.Fatalf("event dropped the before/after claims: %+v", e)
	}
}

// The issue's second test case: same verdict, source newly unavailable.
// Distinguishing a source going silent from a source changing its answer is an
// acceptance criterion: a removal is a fact about our view, a change is a fact
// about the source's answer, and they must not render the same.
func TestEvidenceOnlyChangeSourceBecomesUnavailable(t *testing.T) {
	from := evidenceObs(1, []mechanics.Evidence{
		claim("stellar.expert/directory", "https://api.stellar.expert/explorer/directory/"+testIssuer,
			"listed as \"Scam Asset\" (domain \"nasdaq.finance\", tags: malicious, unsafe)", 1),
		claim("stellar.toml", "https://nasdaq.finance/.well-known/stellar.toml",
			"not retrievable: status 000", 1),
	}, nil)
	to := evidenceObs(2, []mechanics.Evidence{
		claim("stellar.toml", "https://nasdaq.finance/.well-known/stellar.toml",
			"not retrievable: status 000", 2),
	}, nil)

	r := temporal.EvidenceTransition(from, to)

	if r.State != temporal.Valid {
		t.Fatalf("state = %q (%s), want valid", r.State, r.Reason)
	}
	if len(r.Events) != 1 {
		t.Fatalf("events = %+v, want one", r.Events)
	}
	e := r.Events[0]
	if e.Source != "stellar.expert/directory" || e.Kind != temporal.EvidenceRemoved {
		t.Fatalf("event = %+v, want a removal on stellar.expert/directory", e)
	}
	if e.Before.Claim == "" {
		t.Fatal("removal dropped the earlier claim; the reader cannot see what went missing")
	}
	if e.After.URL != "" || e.After.Claim != "" {
		t.Fatal("a removal must not invent a later side")
	}
}

// And the mirror image: a source that was not there before answering now.
func TestEvidenceOnlyChangeSourceBecomesAvailable(t *testing.T) {
	from := evidenceObs(1, nil, nil)
	to := evidenceObs(2, []mechanics.Evidence{
		claim("stellar.expert/blocked-domains", "https://api.stellar.expert/explorer/directory/blocked-domains/example.test",
			"domain \"example.test\" blocked=true", 2),
	}, nil)

	r := temporal.EvidenceTransition(from, to)

	if len(r.Events) != 1 || r.Events[0].Kind != temporal.EvidenceAdded {
		t.Fatalf("events = %+v, want one added event", r.Events)
	}
	if r.Events[0].Source != "stellar.expert/blocked-domains" {
		t.Fatalf("event source = %q", r.Events[0].Source)
	}
}

// The issue's third test case: verdict changed — not reported as evidence-only.
// A clawback flag arriving moves the verdict; listing evidence differences
// beside it would make the evidence diff the headline and bury the verdict.
func TestVerdictChangeIsNotReportedAsEvidenceOnly(t *testing.T) {
	from := evidenceObs(1, []mechanics.Evidence{
		claim("stellar.toml", "https://x.test/.well-known/stellar.toml", "not retrievable: status 404", 1),
	}, nil)
	to := evidenceObs(2, []mechanics.Evidence{
		claim("stellar.toml", "https://x.test/.well-known/stellar.toml", "not retrievable: status 500", 2),
	}, func(o *temporal.Observation) {
		o.Mechanics |= mechanics.MechClawbackEnabled
		o.Base = mechanics.High
		o.Severity = mechanics.High
	})

	r := temporal.EvidenceTransition(from, to)

	if !r.VerdictChanged {
		t.Fatal("a verdict change was not marked; reporting the evidence diff alone would mislead")
	}
	if len(r.Events) != 0 {
		t.Fatalf("events = %+v, want none beside a verdict change", r.Events)
	}
	if r.Reason == "" {
		t.Fatal("a suppressed diff must explain why, or the reader is left with nothing")
	}
}

// Escalation moving with the capability base holding still is also a verdict
// change: reputation is an axis of the verdict, and DOGE gaining its listing
// is not an evidence-only event.
func TestEscalationChangeIsAlsoAVerdictChange(t *testing.T) {
	// Same base, escalation gained — the DOGE shape appearing between two
	// observations.
	from := temporal.Observation{
		Asset: mechanics.Asset{Code: "DOGE", Issuer: testIssuer},
		At:    time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Base:  mechanics.Clear, Severity: mechanics.Clear,
	}
	to := temporal.Observation{
		Asset: mechanics.Asset{Code: "DOGE", Issuer: testIssuer},
		At:    time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
		Base:  mechanics.Clear, Severity: mechanics.Critical,
		Evidence: []mechanics.Evidence{
			claim("stellar.expert/directory", "https://api.stellar.expert/explorer/directory/"+testIssuer,
				"listed as \"Scam Asset\"", 2),
		},
	}

	r := temporal.EvidenceTransition(from, to)

	if !r.VerdictChanged {
		t.Fatal("escalation gained is a verdict change and must be marked as one")
	}
	if len(r.Events) != 0 {
		t.Fatalf("events = %+v, want none beside a verdict change", r.Events)
	}
}

// Unchanged evidence with an unchanged verdict is a real answer, distinct from
// "could not compare". A consumer reading only Events would collapse the two;
// Unchanged exists so it does not have to.
func TestUnchangedIsARealAnswerNotTheAbsenceOfOne(t *testing.T) {
	evs := []mechanics.Evidence{
		claim("stellar.toml", "https://x.test/.well-known/stellar.toml", "CURRENCIES claims DOGE-"+testIssuer, 1),
	}
	r := temporal.EvidenceTransition(evidenceObs(1, evs, nil), evidenceObs(2, evs, nil))

	if !r.Unchanged || len(r.Events) != 0 {
		t.Fatalf("unchanged comparison reported %+v", r)
	}
	if r.VerdictChanged {
		t.Fatal("unchanged evidence cannot coexist with a verdict change")
	}
}

// A URL change with the same claim text is a change, not a match: the URL is
// where the reader re-fetches the claim, so two different URLs are two
// different things to check even when the wording agrees.
func TestURLChangeCountsAsChanged(t *testing.T) {
	from := evidenceObs(1, []mechanics.Evidence{
		claim("stellar.toml", "https://a.test/.well-known/stellar.toml", "same claim", 1),
	}, nil)
	to := evidenceObs(2, []mechanics.Evidence{
		claim("stellar.toml", "https://b.test/.well-known/stellar.toml", "same claim", 2),
	}, nil)

	r := temporal.EvidenceTransition(from, to)

	if len(r.Events) != 1 || r.Events[0].Kind != temporal.EvidenceChanged {
		t.Fatalf("events = %+v, want one changed event", r.Events)
	}
	if r.Events[0].FailureText {
		t.Fatal("a URL change between two non-failure claims is not a failure-text-only event")
	}
}

// An undetermined observation yields no comparison, exactly as the capability
// detectors behave: what the missing source would have said must not be read
// as unchanged.
func TestUndeterminedObservationIsUnknownNotUnchanged(t *testing.T) {
	from := evidenceObs(1, []mechanics.Evidence{
		claim("stellar.toml", "https://x.test/.well-known/stellar.toml", "not retrievable: status 404", 1),
	}, nil)
	to := evidenceObs(2, []mechanics.Evidence{
		claim("stellar.toml", "https://x.test/.well-known/stellar.toml", "not retrievable: status 404", 2),
	}, func(o *temporal.Observation) {
		o.Undetermined = true
		o.UndeterminedChecks = []string{"reputation"}
	})

	r := temporal.EvidenceTransition(from, to)

	if r.State != temporal.Unknown {
		t.Fatalf("state = %q, want unknown", r.State)
	}
	if len(r.Events) != 0 || r.Unchanged {
		t.Fatalf("an unknown comparison reported events or unchanged: %+v", r)
	}
}

// A single observation has nothing to compare against.
func TestSingleObservationEvidenceIsMissing(t *testing.T) {
	r := temporal.EvidenceTransition(evidenceObs(1, nil, nil), temporal.Observation{})

	if r.State != temporal.Missing {
		t.Fatalf("state = %q, want missing", r.State)
	}
	if len(r.Events) != 0 {
		t.Fatalf("events on a missing comparison: %+v", r.Events)
	}
}

// Events come out sorted by source, so the same pair always renders the same
// way — this is a verifier-adjacent output and must be diffable itself.
func TestEventsAreSortedBySource(t *testing.T) {
	from := evidenceObs(1, nil, nil)
	to := evidenceObs(2, []mechanics.Evidence{
		claim("stellar.toml", "https://x.test/.well-known/stellar.toml", "claim", 2),
		claim("stellar.expert/directory", "https://api.stellar.expert/explorer/directory/"+testIssuer, "claim", 2),
		claim("stellar.expert/blocked-domains", "https://api.stellar.expert/explorer/directory/blocked-domains/x", "claim", 2),
	}, nil)

	r := temporal.EvidenceTransition(from, to)

	if len(r.Events) != 3 {
		t.Fatalf("events = %+v, want three additions", r.Events)
	}
	for i := 1; i < len(r.Events); i++ {
		if r.Events[i-1].Source > r.Events[i].Source {
			t.Fatalf("events not sorted by source: %+v", r.Events)
		}
	}
}

// The pure-function requirement: neither input observation is mutated by the
// comparison.
func TestEvidenceComparisonDoesNotMutateItsInputs(t *testing.T) {
	from := evidenceObs(1, []mechanics.Evidence{
		claim("stellar.toml", "https://x.test/.well-known/stellar.toml", "not retrievable: status 404", 1),
	}, nil)
	to := evidenceObs(2, []mechanics.Evidence{
		claim("stellar.toml", "https://x.test/.well-known/stellar.toml", "not retrievable: status 500", 2),
	}, nil)
	beforeFrom, beforeTo := len(from.Evidence), len(to.Evidence)

	temporal.EvidenceTransition(from, to)

	if len(from.Evidence) != beforeFrom || len(to.Evidence) != beforeTo {
		t.Fatal("comparison mutated an observation's evidence slice")
	}
}

// The #24 signature must be explicit in the rendered text, so a report reader
// sees "only the failure wording moved" without interpreting the kind code.
func TestDescribeEvidenceEventNamesTheFailureTextSignature(t *testing.T) {
	e := temporal.EvidenceEvent{
		Source:      "stellar.toml",
		Kind:        temporal.EvidenceChanged,
		Before:      temporal.EvidenceSide{Claim: "not retrievable: dns failure"},
		After:       temporal.EvidenceSide{Claim: "not retrievable: timeout"},
		FailureText: true,
	}

	s := temporal.DescribeEvidenceEvent(e)
	if !strings.Contains(s, "failure text") || !strings.Contains(s, "#24") {
		t.Fatalf("rendered text does not name the #24 signature: %q", s)
	}

	e.FailureText = false
	if strings.Contains(temporal.DescribeEvidenceEvent(e), "failure text") {
		t.Fatal("ordinary change rendered as failure-text-only")
	}
}
