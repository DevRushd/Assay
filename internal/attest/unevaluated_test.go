package attest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// These tests cover issue #32: a Subject whose flags were never read used to
// attest as Clear, the safest value in the ABI. The Unevaluated sentinel plus
// the ErrUnevaluated refusal here are what close that path.

// TestFromReportRefusesUnevaluatedSeverity is the direct refusal test: a
// report carrying the sentinel must not derive attest() arguments.
func TestFromReportRefusesUnevaluatedSeverity(t *testing.T) {
	_, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Severity = mechanics.Unevaluated
	}))
	if !errors.Is(err, attest.ErrUnevaluated) {
		t.Fatalf("FromReport on an unevaluated report: err = %v, want ErrUnevaluated", err)
	}
}

// The sentinel can also travel in Base (the engine copies it into both, so a
// forged report could carry it in either field). Both must refuse.
func TestFromReportRefusesUnevaluatedBase(t *testing.T) {
	_, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Base = mechanics.Unevaluated
	}))
	if !errors.Is(err, attest.ErrUnevaluated) {
		t.Fatalf("FromReport with an unevaluated base: err = %v, want ErrUnevaluated", err)
	}
}

// The refusal must be its own error so a caller can distinguish "no
// capability statement exists" from "a source was down".
func TestUnevaluatedIsADistinctErrorFromUndetermined(t *testing.T) {
	_, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Severity = mechanics.Unevaluated
	}))
	if errors.Is(err, attest.ErrUndetermined) {
		t.Fatal("unevaluated report matched ErrUndetermined; the two refusals must stay distinguishable")
	}
	_, err = attest.FromReport(report(func(r *mechanics.Report) {
		r.Undetermined = true
		r.UndeterminedChecks = []string{"reputation"}
	}))
	if !errors.Is(err, attest.ErrUndetermined) {
		t.Fatalf("plain undetermined report: err = %v, want ErrUndetermined", err)
	}
	if errors.Is(err, attest.ErrUnevaluated) {
		t.Fatal("plain undetermined report matched ErrUnevaluated; the two refusals must stay distinguishable")
	}
}

// A report can be both (the canonical nil-Stat engine output sets the sentinel
// and undetermined). The specific error must win over the generic one.
func TestUnevaluatedErrorWinsOverUndetermined(t *testing.T) {
	_, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Severity = mechanics.Unevaluated
		r.Base = mechanics.Unevaluated
		r.Undetermined = true
		r.UndeterminedChecks = []string{"capability"}
	}))
	if !errors.Is(err, attest.ErrUnevaluated) {
		t.Fatalf("combined report: err = %v, want ErrUnevaluated", err)
	}
}

// Nothing may be derived from a refused report: no preimage, no hash, no
// severity. The preimage especially — it is what evidence_hash commits to, and
// an unevaluated report has no evidence to commit to.
func TestUnevaluatedReportProducesNoParams(t *testing.T) {
	params, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Severity = mechanics.Unevaluated
		r.Base = mechanics.Unevaluated
	}))
	if err == nil {
		t.Fatal("FromReport accepted an unevaluated report")
	}
	if params.EvidenceHash != "" || params.Preimage != "" || params.Severity != 0 {
		t.Fatalf("FromReport derived partial params from a refused report: %+v", params)
	}
}

// TestNilStatSubjectIsNotAttestable is the issue's end-to-end case: a
// hand-built Subject with no Stat, run through the real engine, must refuse at
// FromReport with ErrUnevaluated. Before #32 this exact path attested Clear.
func TestNilStatSubjectIsNotAttestable(t *testing.T) {
	s := &mechanics.Subject{
		Asset:     mechanics.Asset{Code: "NOPE", Issuer: "GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P"},
		Stat:      nil,
		ScannedAt: time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
	}
	rep, err := mechanics.NewEngine().Run(context.Background(), s)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}
	if rep.Severity != mechanics.Unevaluated || rep.Base != mechanics.Unevaluated {
		t.Fatalf("engine output severity=%v base=%v; want both Unevaluated", rep.Severity, rep.Base)
	}
	if rep.Escalated {
		t.Fatal("unevaluated must not read as a reputation escalation")
	}
	if _, err := attest.FromReport(rep); !errors.Is(err, attest.ErrUnevaluated) {
		t.Fatalf("FromReport on a nil-Stat engine report: err = %v, want ErrUnevaluated", err)
	}
}
