package mechanics_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
)

// These tests cover issue #57: Represent stale state distinctly from unknown and clear.
//
// Assay already learned this lesson twice:
//   1. An unreachable source once rendered as a clean result (#23);
//   2. Clear doubled as not-evaluated (#32).
//
// Stale is the third member: a verdict that was complete when made and is now
// older than the policy window.

func newClearReport(scannedAt time.Time) *mechanics.Report {
	return &mechanics.Report{
		Asset:          mechanics.Asset{Code: "AQUA", Issuer: testIssuer},
		Severity:       mechanics.Clear,
		Base:           mechanics.Clear,
		Accountability: mechanics.AccountabilityVerified,
		State:          mechanics.StateValid,
		Stale:          false,
		Undetermined:   false,
		ScannedAt:      mechanics.NewCanonicalTime(scannedAt),
		Findings: []mechanics.Finding{
			{
				Check:     "capability",
				Title:     "Issuer capability",
				Severity:  mechanics.Clear,
				Reasoning: "The issuer holds no authorization flags.",
			},
		},
	}
}

// TestStaleReportProducesStructurallyDifferentOutput verifies that a stale
// attestation/report and a clear one produce structurally different output in JSON.
// A stale clear report must not render identically to a fresh clear report.
func TestStaleReportProducesStructurallyDifferentOutput(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	freshRep := newClearReport(now.Add(-1 * time.Hour))
	freshRep = mechanics.EvaluateFreshness(freshRep, now, mechanics.DefaultFreshnessWindow)

	staleRep := newClearReport(now.Add(-25 * time.Hour))
	staleRep = mechanics.EvaluateFreshness(staleRep, now, mechanics.DefaultFreshnessWindow)

	freshJSON, err := json.Marshal(freshRep)
	if err != nil {
		t.Fatalf("marshal fresh report: %v", err)
	}

	staleJSON, err := json.Marshal(staleRep)
	if err != nil {
		t.Fatalf("marshal stale report: %v", err)
	}

	var freshMap, staleMap map[string]any
	if err := json.Unmarshal(freshJSON, &freshMap); err != nil {
		t.Fatalf("unmarshal fresh map: %v", err)
	}
	if err := json.Unmarshal(staleJSON, &staleMap); err != nil {
		t.Fatalf("unmarshal stale map: %v", err)
	}

	// Both have clear severity, but their structural state is distinct.
	if freshMap["severity"] != "clear" || staleMap["severity"] != "clear" {
		t.Fatalf("both reports should have clear severity; got fresh=%v, stale=%v",
			freshMap["severity"], staleMap["severity"])
	}

	if freshMap["state"] != "valid" {
		t.Errorf("fresh report state = %v, want %q", freshMap["state"], "valid")
	}
	if freshMap["stale"] != false {
		t.Errorf("fresh report stale = %v, want false", freshMap["stale"])
	}

	if staleMap["state"] != "stale" {
		t.Errorf("stale report state = %v, want %q", staleMap["state"], "stale")
	}
	if staleMap["stale"] != true {
		t.Errorf("stale report stale = %v, want true", staleMap["stale"])
	}
	if staleMap["stale_reason"] == nil || staleMap["stale_reason"] == "" {
		t.Errorf("stale report missing stale_reason in JSON: %v", staleMap["stale_reason"])
	}
}

// TestStaleReportNotAttestableAsFresh ensures that a stale report cannot be
// attested as fresh through attest.FromReport.
func TestStaleReportNotAttestableAsFresh(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	staleRep := newClearReport(now.Add(-48 * time.Hour))
	mechanics.EvaluateFreshness(staleRep, now, mechanics.DefaultFreshnessWindow)

	if !staleRep.IsStale() {
		t.Fatal("expected report to be stale")
	}

	params, err := attest.FromReport(staleRep)
	if err == nil {
		t.Fatal("attest.FromReport accepted a stale report; want ErrStale")
	}
	if !errors.Is(err, attest.ErrStale) {
		t.Fatalf("attest.FromReport err = %v, want errors.Is(err, attest.ErrStale)", err)
	}
	if params.EvidenceHash != "" || params.Preimage != "" {
		t.Fatalf("FromReport produced params for a stale report: %+v", params)
	}
}

// TestStaleDistinctFromUnknownAndClear enforces the semantics defined in #57:
//   - valid state: A fresh, complete verdict.
//   - unknown state: A check could not conclude.
//   - stale state: The verdict was complete when made and is now older than the policy window.
//   - invalid state: Stale rendering identically to clear anywhere in the output.
func TestStaleDistinctFromUnknownAndClear(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

	t.Run("valid state", func(t *testing.T) {
		rep := newClearReport(now.Add(-2 * time.Hour))
		mechanics.EvaluateFreshness(rep, now, mechanics.DefaultFreshnessWindow)

		if rep.State != mechanics.StateValid {
			t.Errorf("state = %v, want %v", rep.State, mechanics.StateValid)
		}
		if rep.Stale {
			t.Error("fresh report marked stale")
		}
		if rep.Undetermined {
			t.Error("valid report marked undetermined")
		}
		if !rep.IsValid() {
			t.Error("IsValid() returned false for fresh report")
		}
	})

	t.Run("unknown state - undetermined", func(t *testing.T) {
		rep := newClearReport(now.Add(-2 * time.Hour))
		rep.Undetermined = true
		rep.UndeterminedChecks = []string{"reputation"}
		rep.State = mechanics.StateUnknown
		mechanics.EvaluateFreshness(rep, now, mechanics.DefaultFreshnessWindow)

		if rep.State != mechanics.StateUnknown {
			t.Errorf("state = %v, want %v", rep.State, mechanics.StateUnknown)
		}
		if rep.Stale {
			t.Error("undetermined report must not be marked stale: staleness applies only to complete verdicts")
		}
	})

	t.Run("unknown state - unevaluated", func(t *testing.T) {
		rep := newClearReport(now.Add(-2 * time.Hour))
		rep.Severity = mechanics.Unevaluated
		rep.Base = mechanics.Unevaluated
		rep.Undetermined = true
		rep.State = mechanics.StateUnknown
		mechanics.EvaluateFreshness(rep, now, mechanics.DefaultFreshnessWindow)

		if rep.State != mechanics.StateUnknown {
			t.Errorf("state = %v, want %v", rep.State, mechanics.StateUnknown)
		}
		if rep.Stale {
			t.Error("unevaluated report must not be marked stale")
		}
	})

	t.Run("stale state", func(t *testing.T) {
		rep := newClearReport(now.Add(-30 * time.Hour))
		mechanics.EvaluateFreshness(rep, now, mechanics.DefaultFreshnessWindow)

		if rep.State != mechanics.StateStale {
			t.Errorf("state = %v, want %v", rep.State, mechanics.StateStale)
		}
		if !rep.Stale {
			t.Error("stale report not marked Stale=true")
		}
		if rep.Undetermined {
			t.Error("stale report was complete when made, must not be marked undetermined")
		}
		if rep.IsValid() {
			t.Error("IsValid() returned true for stale report")
		}
	})
}

// TestStaleFreshnessEvaluator tests the FreshnessEvaluator with various windows.
func TestStaleFreshnessEvaluator(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	evaluator := mechanics.NewFreshnessEvaluator(24 * time.Hour)
	evaluator.Now = func() time.Time { return now }

	// Within 24 hours: fresh
	within := newClearReport(now.Add(-10 * time.Hour))
	evaluator.Evaluate(within)
	if within.State != mechanics.StateValid || within.Stale {
		t.Errorf("report within window is stale: state=%v, stale=%v", within.State, within.Stale)
	}

	// Past 24 hours: stale
	past := newClearReport(now.Add(-26 * time.Hour))
	evaluator.Evaluate(past)
	if past.State != mechanics.StateStale || !past.Stale {
		t.Errorf("report past window is not stale: state=%v, stale=%v", past.State, past.Stale)
	}

	// Custom 1-hour window (settlement class from docs/freshness.md)
	settlementEval := mechanics.NewFreshnessEvaluator(1 * time.Hour)
	settlementEval.Now = func() time.Time { return now }
	settlementRep := newClearReport(now.Add(-2 * time.Hour))
	settlementEval.Evaluate(settlementRep)
	if settlementRep.State != mechanics.StateStale || !settlementRep.Stale {
		t.Errorf("report past 1h window not stale for settlement evaluator")
	}

	// Window <= 0 disables freshness checking
	noWindowEval := mechanics.NewFreshnessEvaluator(0)
	noWindowEval.Now = func() time.Time { return now }
	oldRep := newClearReport(now.Add(-1000 * time.Hour))
	noWindowEval.Evaluate(oldRep)
	if oldRep.State != mechanics.StateValid || oldRep.Stale {
		t.Errorf("window=0 should disable freshness; got state=%v, stale=%v", oldRep.State, oldRep.Stale)
	}
}

// TestStaleEngineRunSetsInitialValidState verifies that a clean engine run produces StateValid.
func TestStaleEngineRunSetsInitialValidState(t *testing.T) {
	s := &mechanics.Subject{
		Asset:           mechanics.Asset{Code: "TEST", Issuer: testIssuer},
		Stat:            &horizon.AssetStat{AssetCode: "TEST", AssetIssuer: testIssuer},
		Issuer:          &horizon.Account{AccountID: testIssuer, HomeDomain: "test.example"},
		StatFetchedAt:   time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
		IssuerFetchedAt: time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
		ScannedAt:       time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
	}

	rep, err := mechanics.NewEngine().Run(context.Background(), s)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.State != mechanics.StateValid {
		t.Fatalf("clean engine run produced state %v, want StateValid", rep.State)
	}
	if rep.Stale {
		t.Fatal("clean engine run produced Stale=true")
	}
}

// TestStaleRendersDistinctName tests string rendering of State.
func TestStaleRendersDistinctName(t *testing.T) {
	if got := mechanics.StateValid.String(); got != "valid" {
		t.Fatalf("StateValid.String() = %q, want %q", got, "valid")
	}
	if got := mechanics.StateUnknown.String(); got != "unknown" {
		t.Fatalf("StateUnknown.String() = %q, want %q", got, "unknown")
	}
	if got := mechanics.StateStale.String(); got != "stale" {
		t.Fatalf("StateStale.String() = %q, want %q", got, "stale")
	}
}
