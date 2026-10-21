package mechanics_test

import (
	"context"
	"testing"

	"github.com/use-assay/assay/internal/mechanics"
)

// withoutCheck returns an engine with the named check removed and the rest
// kept in order. It is the shape a suppressed check takes: the engine simply
// iterates a smaller slice.
func withoutCheck(eng *mechanics.Engine, id string) *mechanics.Engine {
	checks := make([]mechanics.Check, 0, len(eng.Checks))
	for _, c := range eng.Checks {
		if c.ID() != id {
			checks = append(checks, c)
		}
	}
	return &mechanics.Engine{Checks: checks}
}

func setHas(set []string, id string) bool {
	for _, s := range set {
		if s == id {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSuppressRemovingReputationChangesTheCheckSet is the adversarial case from
// #105: the engine iterates whatever NewEngine returned, so a scan run with a
// check removed must be distinguishable from one where every check ran and
// found nothing. The check set is that distinction.
func TestSuppressRemovingReputationChangesTheCheckSet(t *testing.T) {
	full := mechanics.NewEngine()
	reduced := withoutCheck(full, "reputation")

	s := loadSubject(t, "doge-noflags-scam")

	repFull, err := full.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("full run: %v", err)
	}
	repReduced, err := reduced.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("reduced run: %v", err)
	}

	if !setHas(repFull.CheckSet, "reputation") {
		t.Fatalf("full engine's report does not name the reputation check: %v", repFull.CheckSet)
	}
	if setHas(repReduced.CheckSet, "reputation") {
		t.Fatalf("engine without the reputation check still reports it as run: %v", repReduced.CheckSet)
	}
	if len(repFull.CheckSet) != len(repReduced.CheckSet)+1 {
		t.Fatalf("check sets differ by %d, want exactly 1: full=%v reduced=%v",
			len(repFull.CheckSet)-len(repReduced.CheckSet), repFull.CheckSet, repReduced.CheckSet)
	}
	if sameSet(repFull.CheckSet, repReduced.CheckSet) {
		t.Fatal("removing a check did not change the report's check set")
	}
}

// TestSuppressCheckThatFoundNothingIsStillBound is the harder half. Removing
// the mutability check on DOGE changes no aggregate field and emits no
// evidence, so without a bound check set the two reports would be identical in
// every field the preimage commits to. The check set must still differ.
func TestSuppressCheckThatFoundNothingIsStillBound(t *testing.T) {
	full := mechanics.NewEngine()
	reduced := withoutCheck(full, "mutability")

	s := loadSubject(t, "doge-noflags-scam")

	repFull, err := full.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("full run: %v", err)
	}
	repReduced, err := reduced.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("reduced run: %v", err)
	}

	// Precondition: the removed check moved nothing else, or this test would
	// pass for the wrong reason.
	if repFull.Severity != repReduced.Severity ||
		repFull.Base != repReduced.Base ||
		repFull.Escalated != repReduced.Escalated ||
		repFull.Mechanics != repReduced.Mechanics ||
		repFull.Accountability != repReduced.Accountability {
		t.Fatalf("the removed check changed an aggregate field, so this does not isolate "+
			"check-set binding: full=%+v reduced=%+v", repFull, repReduced)
	}
	if len(repFull.Evidence) != len(repReduced.Evidence) {
		t.Fatalf("the removed check emitted evidence, so this does not isolate binding: %d vs %d",
			len(repFull.Evidence), len(repReduced.Evidence))
	}

	if sameSet(repFull.CheckSet, repReduced.CheckSet) {
		t.Fatal("removing a check that found nothing produced the same check set; a suppressed " +
			"check would be indistinguishable from a clean one")
	}
}
