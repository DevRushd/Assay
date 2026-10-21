package attest_test

import (
	"errors"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// These tests cover issue #57 for internal/attest: a stale report must not be
// attestable as fresh, matching the on-chain example gate's AttestationStale (error #2).

func TestFromReportRefusesStaleReport(t *testing.T) {
	t.Run("stale flag set", func(t *testing.T) {
		rep := report(func(r *mechanics.Report) {
			r.Stale = true
			r.State = mechanics.StateStale
			r.StaleReason = "verdict age 48h exceeds policy window 24h"
		})

		params, err := attest.FromReport(rep)
		if err == nil {
			t.Fatal("FromReport accepted a stale report")
		}
		if !errors.Is(err, attest.ErrStale) {
			t.Fatalf("err = %v, want ErrStale", err)
		}
		if params.EvidenceHash != "" || params.Preimage != "" {
			t.Fatalf("FromReport derived params from a refused report: %+v", params)
		}
	})

	t.Run("evaluated stale via freshness window", func(t *testing.T) {
		now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
		rep := report(func(r *mechanics.Report) {
			r.ScannedAt = mechanics.NewCanonicalTime(now.Add(-48 * time.Hour))
		})
		mechanics.EvaluateFreshness(rep, now, 24*time.Hour)

		params, err := attest.FromReport(rep)
		if err == nil {
			t.Fatal("FromReport accepted an evaluated stale report")
		}
		if !errors.Is(err, attest.ErrStale) {
			t.Fatalf("err = %v, want ErrStale", err)
		}
		if params.EvidenceHash != "" {
			t.Fatalf("unexpected params: %+v", params)
		}
	})
}

func TestStaleIsADistinctErrorFromUnevaluatedAndUndetermined(t *testing.T) {
	staleRep := report(func(r *mechanics.Report) {
		r.Stale = true
		r.State = mechanics.StateStale
	})
	_, err := attest.FromReport(staleRep)
	if !errors.Is(err, attest.ErrStale) {
		t.Fatalf("stale report err = %v, want ErrStale", err)
	}
	if errors.Is(err, attest.ErrUnevaluated) {
		t.Fatal("stale report matched ErrUnevaluated; the refusals must stay distinguishable")
	}
	if errors.Is(err, attest.ErrUndetermined) {
		t.Fatal("stale report matched ErrUndetermined; the refusals must stay distinguishable")
	}

	unevaluatedRep := report(func(r *mechanics.Report) {
		r.Severity = mechanics.Unevaluated
	})
	_, err = attest.FromReport(unevaluatedRep)
	if errors.Is(err, attest.ErrStale) {
		t.Fatal("unevaluated report matched ErrStale; the refusals must stay distinguishable")
	}

	undeterminedRep := report(func(r *mechanics.Report) {
		r.Undetermined = true
		r.UndeterminedChecks = []string{"reputation"}
	})
	_, err = attest.FromReport(undeterminedRep)
	if errors.Is(err, attest.ErrStale) {
		t.Fatal("undetermined report matched ErrStale; the refusals must stay distinguishable")
	}
}
