package attest_test

import (
	"errors"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// These tests pin the decision recorded in docs/contract-interface.md
// (#43): the undetermined flag is deliberately excluded from the evidence
// preimage, and the exclusion is sound only because attest.FromReport refuses
// an undetermined report outright.
//
// The refusal itself is asserted by TestUndeterminedReportIsRefused in
// attest_test.go. What is pinned here is the pair of properties the decision
// depends on: the refusal stays in place, and the flag genuinely commits
// nothing — a preimage is identical whether the report it was derived from
// claims to be undetermined or not, which is why hashing it would add no
// information to anything a verifier ever compares.

// TestPreimageIsImpossibleForAnUndeterminedReport asserts the first
// consequence of the refusal: there are no attest() arguments for an
// undetermined report at all, and therefore no preimage any verifier will ever
// compare. attest.Preimage would happily render bytes for one, but no caller
// ever holds such bytes, because the only producer of preimages — FromReport —
// refuses first. If this invariant breaks, the "constant across everything
// attestable" argument in the documentation is false and the encoding decision
// must be revisited.
func TestPreimageIsImpossibleForAnUndeterminedReport(t *testing.T) {
	_, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Undetermined = true
		r.UndeterminedChecks = []string{"reputation"}
	}))
	if err == nil {
		t.Fatal("an undetermined report derived attest() arguments; the #43 " +
			"decision that undetermined stays out of the preimage rests on this " +
			"refusal, which no longer holds")
	}
	if !errors.Is(err, attest.ErrUndetermined) {
		t.Fatalf("err = %v, want ErrUndetermined", err)
	}
}

// TestEveryAttestableReportCarriesNoUndeterminedFlag is the constant-field
// argument as a test, across both encodings a report can legally carry: a
// report with a bound check set (v2) and one without it (v1). An attestable
// report never has the flag set, so the flag cannot distinguish any pair of
// preimages that exist — which is the reason it is excluded from the encoding
// rather than bound into it.
func TestEveryAttestableReportCarriesNoUndeterminedFlag(t *testing.T) {
	for _, tc := range []struct {
		name string
		bind bool
	}{
		{"v1 without a check set", false},
		{"v2 with a bound check set", true},
	} {
		build := report(func(r *mechanics.Report) {
			if tc.bind {
				r.CheckSet = []string{"capability", "mutability", "reputation", "sep1-domain"}
			}
		})
		if build.Undetermined {
			t.Fatalf("%s: test report is undetermined; the fixture contradicts the property under test", tc.name)
		}
		if _, err := attest.FromReport(build); err != nil {
			t.Fatalf("%s: FromReport: %v", tc.name, err)
		}
	}
}

// TestUndeterminedFlagDoesNotChangeThePreimage closes the loop on the issue's
// observation that degraded reports already hash differently through their
// evidence: a 'not retrievable' claim moves the hash because it is hashed
// evidence, not because the flag is hashed. Setting the flag alone — with the
// evidence untouched — cannot move the preimage, and this is asserted over
// attest.Preimage directly, since FromReport refuses before hashing.
func TestUndeterminedFlagDoesNotChangeThePreimage(t *testing.T) {
	complete := report(nil)
	// The same report, marked undetermined: not attestable, and if the flag
	// were part of the encoding, Preimage would render different bytes. The
	// decision is that it is not, so the bytes are identical.
	degraded := report(func(r *mechanics.Report) { r.Undetermined = true })

	if got, want := attest.Preimage(degraded), attest.Preimage(complete); got != want {
		t.Fatalf("the undetermined flag changed the preimage, contradicting the #43 decision:\n got: %q\nwant: %q", got, want)
	}
}
