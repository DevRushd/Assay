package attest_test

import (
	"context"
	"sort"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/mechanics"
)

// dogeSubject is the fixture the suppression tests use: a known scam with no
// auth flags, whose entire critical severity comes from the reputation check.
// It is the case with the largest consequence, because removing that check
// turns every critical-by-reputation asset into a clean one.
func dogeSubject(t *testing.T) *mechanics.Subject {
	t.Helper()
	s, err := eval.LoadSubject("../mechanics/testdata", "doge-noflags-scam")
	if err != nil {
		t.Fatalf("load doge fixture: %v", err)
	}
	return s
}

func withoutCheck(eng *mechanics.Engine, id string) *mechanics.Engine {
	checks := make([]mechanics.Check, 0, len(eng.Checks))
	for _, c := range eng.Checks {
		if c.ID() != id {
			checks = append(checks, c)
		}
	}
	return &mechanics.Engine{Checks: checks}
}

func evidenceClaims(rep *mechanics.Report) []string {
	claims := make([]string, 0, len(rep.Evidence))
	for _, e := range rep.Evidence {
		claims = append(claims, e.Source+"\t"+e.URL+"\t"+e.Claim)
	}
	sort.Strings(claims)
	return claims
}

// TestSuppressRemovingReputationChangesTheHash is the acceptance test from
// #105: a report produced by an engine without the reputation check hashes
// differently from the full engine's, even though both reports are internally
// consistent and individually attestable.
func TestSuppressRemovingReputationChangesTheHash(t *testing.T) {
	full := mechanics.NewEngine()
	reduced := withoutCheck(full, "reputation")

	s := dogeSubject(t)

	repFull, err := full.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("full run: %v", err)
	}
	repReduced, err := reduced.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("reduced run: %v", err)
	}

	// Without the reputation check DOGE reads clear instead of critical. This
	// is exactly the manipulation the issue describes.
	if repReduced.Severity != mechanics.Clear {
		t.Fatalf("engine without reputation produced severity %v, want clear", repReduced.Severity)
	}

	pFull, err := attest.FromReport(repFull)
	if err != nil {
		t.Fatalf("attest full: %v", err)
	}
	pReduced, err := attest.FromReport(repReduced)
	if err != nil {
		t.Fatalf("attest reduced: %v", err)
	}

	if pFull.EvidenceHash == pReduced.EvidenceHash {
		t.Fatal("a scan with the reputation check removed hashed identically to the full scan; " +
			"a suppressed check would be undetectable")
	}
}

// TestSuppressCheckThatFoundNothingChangesTheHash is the half that proves the
// preimage binds the check set rather than merely the aggregate. Removing
// mutability from the DOGE engine changes no aggregate field and emits no
// evidence, so the aggregate and evidence lines are identical; only the
// `checks` line can distinguish the two hashes.
func TestSuppressCheckThatFoundNothingChangesTheHash(t *testing.T) {
	full := mechanics.NewEngine()
	reduced := withoutCheck(full, "mutability")

	s := dogeSubject(t)

	repFull, err := full.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("full run: %v", err)
	}
	repReduced, err := reduced.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("reduced run: %v", err)
	}

	// Precondition: the removed check moved nothing hashed except the check set.
	identical := repFull.Severity == repReduced.Severity &&
		repFull.Base == repReduced.Base &&
		repFull.Escalated == repReduced.Escalated &&
		repFull.Mechanics == repReduced.Mechanics &&
		repFull.Accountability == repReduced.Accountability
	claims := evidenceClaims(repFull)
	claimsReduced := evidenceClaims(repReduced)
	sameClaims := len(claims) == len(claimsReduced)
	if sameClaims {
		for i := range claims {
			if claims[i] != claimsReduced[i] {
				sameClaims = false
				break
			}
		}
	}
	if !identical || !sameClaims {
		t.Fatalf("the removed check changed more than the check set, so this does not isolate "+
			"binding (identical=%t sameClaims=%t)", identical, sameClaims)
	}

	pFull, err := attest.FromReport(repFull)
	if err != nil {
		t.Fatalf("attest full: %v", err)
	}
	pReduced, err := attest.FromReport(repReduced)
	if err != nil {
		t.Fatalf("attest reduced: %v", err)
	}
	if pFull.EvidenceHash == pReduced.EvidenceHash {
		t.Fatal("a check that found nothing was invisible in the hash; the preimage does not " +
			"bind the check set")
	}
}

// TestSuppressVerifierNamesMissingCheck is the second acceptance criterion: the
// verifier says which check is absent rather than reporting a generic mismatch.
func TestSuppressVerifierNamesMissingCheck(t *testing.T) {
	full := mechanics.NewEngine()
	reduced := withoutCheck(full, "reputation")
	s := dogeSubject(t)

	repFull, err := full.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("full run: %v", err)
	}
	repReduced, err := reduced.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("reduced run: %v", err)
	}

	got := attest.VerifyCheckSet(repReduced, full.CheckIDs())
	if got.Status != attest.CheckSetIncomplete {
		t.Fatalf("verification status = %q, want %q", got.Status, attest.CheckSetIncomplete)
	}
	if len(got.Missing) != 1 || got.Missing[0] != "reputation" {
		t.Fatalf("verifier missing = %v, want exactly [reputation]", got.Missing)
	}

	if ok := attest.VerifyCheckSet(repFull, full.CheckIDs()); ok.Status != attest.CheckSetComplete {
		t.Fatalf("full engine's check set verified as %q, want %q", ok.Status, attest.CheckSetComplete)
	}
}

// TestSuppressPreBindingAttestationIsUnknown covers the unknown state:
// an attestation predating check-set binding carries no check set, and must be
// reported as unknown rather than failed.
func TestSuppressPreBindingAttestationIsUnknown(t *testing.T) {
	full := mechanics.NewEngine()
	s := dogeSubject(t)

	rep, err := full.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// A report from before check-set binding: same content, no bound set.
	legacy := *rep
	legacy.CheckSet = nil

	got := attest.VerifyCheckSet(&legacy, full.CheckIDs())
	if got.Status != attest.CheckSetUnknown {
		t.Fatalf("pre-binding report verified as %q, want %q", got.Status, attest.CheckSetUnknown)
	}
	if len(got.Missing) != 0 {
		t.Fatalf("pre-binding report was reported with missing checks %v; there is nothing to "+
			"compare, so it is unknown rather than incomplete", got.Missing)
	}

	// It must still produce the v1 bytes, so its historical hash reproduces.
	if ver := attest.Preimage(&legacy); !hasPrefix(ver, attest.PreimageVersion+"\n") {
		t.Fatalf("pre-binding report is not written under the v1 encoding: %q", ver)
	}
	if ver := attest.Preimage(rep); !hasPrefix(ver, attest.PreimageVersionCheckSet+"\n") {
		t.Fatalf("bound report is not written under the v2 encoding: %q", ver)
	}
}

// TestSuppressParamsExposeTheCheckSet covers the attestation-as-params form: a
// verifier holding only the derived attest() arguments can still name the check
// a suppressed scan is missing, and a pre-binding attestation is unknown rather
// than incomplete.
func TestSuppressParamsExposeTheCheckSet(t *testing.T) {
	full := mechanics.NewEngine()
	reduced := withoutCheck(full, "reputation")
	s := dogeSubject(t)

	repReduced, err := reduced.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("reduced run: %v", err)
	}
	p, err := attest.FromReport(repReduced)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}

	v := attest.VerifyParams(p, full.CheckIDs())
	if v.Status != attest.CheckSetIncomplete || len(v.Missing) != 1 || v.Missing[0] != "reputation" {
		t.Fatalf("VerifyParams did not name the missing check: %+v", v)
	}

	legacy := p
	legacy.Checks = nil
	if lv := attest.VerifyParams(legacy, full.CheckIDs()); lv.Status != attest.CheckSetUnknown {
		t.Fatalf("params without a check set verified as %q, want %q", lv.Status, attest.CheckSetUnknown)
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
