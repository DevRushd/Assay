package attest_test

import (
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// These tests back the contract-side rows of docs/fail-closed.md (#108). The
// contract's own test suite (assay-contracts) proves the on-chain half; the
// tests here are the Go-side statement of the same invariants, written as the
// issue requires: one test per fail-closed claim, named for the row it backs.
//
// The rule every test encodes: no failure, absence, or malformed input may
// produce attestation arguments more permissive than a complete, honest scan
// would have produced.

// TestFailClosedUnattestedAssetNeverVerifiesAsComplete pins C1: a report with
// no bound check set is "unknown", never "complete". The registry's unattested
// answer is None and fails closed on-chain; this is the verifier-side half of
// the same invariant — a pre-binding report cannot pass a check-set
// verification as if it had run everything.
func TestFailClosedUnattestedAssetNeverVerifiesAsComplete(t *testing.T) {
	rep := report(nil)
	rep.CheckSet = nil // pre-binding report: nothing to compare
	params, err := attest.FromReport(rep)
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}

	v := attest.VerifyParams(params, []string{"capability", "mutability", "sep1-domain", "reputation"})
	if v.Status != attest.CheckSetUnknown {
		t.Fatalf("a pre-binding report verified as %s; want unknown, never complete", v.Status)
	}

	v = attest.VerifyCheckSet(rep, []string{"capability"})
	if v.Status != attest.CheckSetUnknown {
		t.Fatalf("VerifyCheckSet on a report with no check set = %s; want unknown", v.Status)
	}
}

// TestFailClosedMissingCheckIsReportedIncomplete pins the compare half: a
// report that DID bind a check set but is missing an expected check must be
// incomplete, with the absent checks named — a suppressed check cannot hide
// behind an otherwise identical report.
func TestFailClosedMissingCheckIsReportedIncomplete(t *testing.T) {
	rep := report(nil)
	rep.CheckSet = []string{"capability", "mutability"}

	v := attest.VerifyCheckSet(rep, []string{"capability", "mutability", "reputation"})
	if v.Status != attest.CheckSetIncomplete {
		t.Fatalf("status = %s, want incomplete", v.Status)
	}
	if len(v.Missing) != 1 || v.Missing[0] != "reputation" {
		t.Fatalf("missing = %v, want [reputation]", v.Missing)
	}

	// And the complete case really is complete, so the negative above is
	// meaningful.
	rep.CheckSet = []string{"capability", "mutability", "reputation"}
	if v := attest.VerifyCheckSet(rep, []string{"capability", "mutability", "reputation"}); v.Status != attest.CheckSetComplete {
		t.Fatalf("status = %s, want complete", v.Status)
	}
}

// TestFailClosedSeverityAndBitsetAreRefusedTogether pins C3's invariant shape
// on the Go side: the exact pairs the contract rejects at write time
// (InvalidSeverity for severity > 4, InconsistentAttestation for clawback
// below high) are refused here too, so a bad attestation costs a scan rather
// than a transaction.
func TestFailClosedSeverityAndBitsetAreRefusedTogether(t *testing.T) {
	cases := map[string]func(*mechanics.Report){
		"severity above critical": func(r *mechanics.Report) {
			r.Severity, r.Base = mechanics.Unevaluated, mechanics.Unevaluated
		},
		"clawback below high": func(r *mechanics.Report) {
			r.Mechanics = mechanics.MechClawbackEnabled
			r.Severity, r.Base = mechanics.Medium, mechanics.Medium
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := attest.FromReport(report(mut)); err == nil {
				t.Fatalf("%s was accepted by FromReport; the contract would reject it on-chain", name)
			}
		})
	}
}

// TestFailClosedPartialScanIsRefusedAtEverySeverity pins A2 across the
// severity range: an undetermined report is refused whatever level it reached.
// The refusal must not depend on the report being clear — a partial HIGH scan
// is just as non-attestable, because on-chain there is nowhere to put the
// caveat.
func TestFailClosedPartialScanIsRefusedAtEverySeverity(t *testing.T) {
	for _, sev := range []mechanics.Severity{
		mechanics.Clear, mechanics.Low, mechanics.Medium, mechanics.High, mechanics.Critical,
	} {
		_, err := attest.FromReport(report(func(r *mechanics.Report) {
			r.Severity, r.Base = sev, sev
			r.Undetermined = true
			r.UndeterminedChecks = []string{"reputation"}
		}))
		if err == nil {
			t.Fatalf("a %v report that never read reputation was attestable", sev)
		}
	}
}

// TestFailClosedStaleScanCannotBeMadeFresh pins C5's timestamp discipline on
// the Go encoding: ScannedAt is carried into the params as a plain timestamp,
// and the preimage excludes retrieval times — so nothing about the encoding
// lets an old scan present itself as new. The staleness decision belongs to
// attested_at/max_age on-chain, where the test host proves fail-closed
// behaviour; here we pin that the written timestamp is the scan's, not
// something later.
func TestFailClosedStaleScanCannotBeMadeFresh(t *testing.T) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	params, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.ScannedAt = mechanics.NewCanonicalTime(old)
	}))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	if params.ScannedAt != "2026-01-01T00:00:00Z" {
		t.Fatalf("ScannedAt = %s, want the scan's own time; a re-encoded timestamp would age attestation dishonestly", params.ScannedAt)
	}
}
