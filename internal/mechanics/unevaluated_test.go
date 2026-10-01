package mechanics_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
)

// The issue behind these tests (#32): Clear = 0 doubles as "the issuer holds
// no powers" and "this was never assessed". A Subject whose flags were never
// read must therefore not be able to render as Clear.

// evalDirs are the labelled subjects from docs/eval.md, as loaded by
// TestEval. Listed here so the sentinel-leak guard below runs over exactly
// the same set.
var evalDirs = []string{
	"aqua-clear-verified",
	"shx-clear-flagslocked",
	"usdc-revocable-regulated",
	"berkshire-clawback-scam",
	"doge-noflags-scam",
}

// TestNilStatIsUnevaluatedNotClear covers the exact shape from the issue: a
// hand-built Subject with no Stat. The finding must carry the Unevaluated
// sentinel — not Clear — and mark itself undetermined, which is what makes the
// report non-attestable downstream.
func TestNilStatIsUnevaluatedNotClear(t *testing.T) {
	s := &mechanics.Subject{
		Asset:     mechanics.Asset{Code: "NOPE", Issuer: testIssuer},
		Stat:      nil,
		ScannedAt: time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
	}

	f, err := mechanics.CapabilityCheck{}.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("CapabilityCheck.Run on a nil-Stat subject returned an error: %v", err)
	}
	if f.Severity != mechanics.Unevaluated {
		t.Fatalf("nil-Stat subject produced severity %v; the capability axis was never read and must be Unevaluated, not Clear", f.Severity)
	}
	if !f.Undetermined {
		t.Fatal("nil-Stat subject did not mark its finding undetermined; the report would attest as a complete scan")
	}
}

// TestNilStatEngineRunIsUndeterminedNotClear runs the full engine over the
// hand-built subject: the report must propagate undetermined and must never
// carry Clear as if the flags had been read.
func TestNilStatEngineRunIsUndeterminedNotClear(t *testing.T) {
	s := &mechanics.Subject{
		Asset:     mechanics.Asset{Code: "NOPE", Issuer: testIssuer},
		Stat:      nil,
		ScannedAt: time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
	}

	rep, err := mechanics.NewEngine().Run(context.Background(), s)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}
	if !rep.Undetermined {
		t.Fatal("report from a nil-Stat subject is not marked undetermined")
	}
	var capabilityRecorded bool
	for _, f := range rep.Findings {
		if f.Check == "capability" {
			capabilityRecorded = true
			if f.Severity != mechanics.Unevaluated {
				t.Fatalf("capability finding severity is %v; want Unevaluated", f.Severity)
			}
		}
	}
	if !capabilityRecorded {
		t.Fatal("no capability finding in report")
	}
	if rep.Severity == mechanics.Clear {
		t.Fatal("report severity is Clear although the flags were never read; Clear must require a read")
	}
}

// TestEvalSubjectsNotUnevaluated guards the flip side: every labelled eval
// subject carries a real Stat, so none of them may be affected by the new
// sentinel. (Their exact expected levels are pinned by TestEval; this guards
// that the sentinel has not leaked into the evaluated path.) It also checks
// the reports stay fully determined, since an eval subject with fixture data
// has every source answered.
func TestEvalSubjectsNotUnevaluated(t *testing.T) {
	eng := mechanics.NewEngine()
	for _, dir := range evalDirs {
		t.Run(dir, func(t *testing.T) {
			s := loadSubject(t, dir)
			rep, err := eng.Run(context.Background(), s)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if rep.Base == mechanics.Unevaluated || rep.Severity == mechanics.Unevaluated {
				t.Fatalf("eval subject %s reported unevaluated; the sentinel must only arise from a nil Stat", dir)
			}
			if rep.Undetermined {
				t.Fatalf("eval subject %s became undetermined; fixture data must keep every axis answered", dir)
			}
		})
	}
}

// TestUnevaluatedRendersDistinctName checks the sentinel renders as its own
// name — not "clear" and not the unknown fallback — in both String and JSON,
// since those are the paths the API and UI read.
func TestUnevaluatedRendersDistinctName(t *testing.T) {
	if got := mechanics.Unevaluated.String(); got != "unevaluated" {
		t.Fatalf("String() = %q, want %q", got, "unevaluated")
	}
	b, err := json.Marshal(mechanics.Unevaluated)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `"unevaluated"` {
		t.Fatalf("MarshalJSON = %s, want %q", b, `"unevaluated"`)
	}
}

// TestUnevaluatedOutsideABIRange pins the sentinel outside the on-chain 0..4
// range. If someone renumbers the levels, this fails before the sentinel can
// silently collide with an ABI value.
func TestUnevaluatedOutsideABIRange(t *testing.T) {
	if mechanics.Unevaluated <= mechanics.Critical {
		t.Fatalf("Unevaluated (%d) must sort above Critical (%d) to stay outside the ABI's 0..4 range", mechanics.Unevaluated, mechanics.Critical)
	}
}
