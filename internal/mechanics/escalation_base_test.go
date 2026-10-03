package mechanics_test

import (
	"context"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
)

type staticCheck struct {
	id      string
	finding mechanics.Finding
}

func (s staticCheck) ID() string { return s.id }
func (s staticCheck) Describe() string { return s.id }
func (s staticCheck) Run(ctx context.Context, sub *mechanics.Subject) (mechanics.Finding, error) {
	return s.finding, nil
}

func TestBaseSeverityDerivesOnlyFromCapability(t *testing.T) {
	ctx := context.Background()
	sub := &mechanics.Subject{ScannedAt: time.Now()}

	baseFindings := []mechanics.Finding{
		{Check: "c1", Severity: mechanics.Clear, Mechanics: mechanics.MechAuthRequired},
		{Check: "c2", Severity: mechanics.Low, Mechanics: mechanics.MechAuthRevocable},
		{Check: "c3", Severity: mechanics.Medium, Mechanics: mechanics.MechClawbackEnabled},
	}

	escalationFindings := []mechanics.Finding{
		{Check: "e1", Severity: mechanics.High, Escalation: true, Mechanics: mechanics.MechBlocklisted},
		{Check: "e2", Severity: mechanics.Critical, Escalation: true, Mechanics: mechanics.MechDomainUnverified},
	}

	// 1. Without any escalation, base and severity should be exactly max(baseFindings).
	var baseChecks []mechanics.Check
	for _, f := range baseFindings {
		baseChecks = append(baseChecks, staticCheck{f.Check, f})
	}
	engine := &mechanics.Engine{Checks: baseChecks}
	rep, err := engine.Run(ctx, sub)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if rep.Base != mechanics.Medium {
		t.Errorf("expected base Medium, got %s", rep.Base)
	}
	if rep.Severity != mechanics.Medium {
		t.Errorf("expected final severity Medium, got %s", rep.Severity)
	}

	// 2. With escalations added, base remains the same, but final severity rises.
	var allChecks []mechanics.Check
	for _, f := range baseFindings {
		allChecks = append(allChecks, staticCheck{f.Check, f})
	}
	for _, f := range escalationFindings {
		allChecks = append(allChecks, staticCheck{f.Check, f})
	}

	engineAll := &mechanics.Engine{Checks: allChecks}
	repAll, err := engineAll.Run(ctx, sub)
	if err != nil {
		t.Fatalf("engineAll.Run: %v", err)
	}

	if repAll.Base != mechanics.Medium {
		t.Errorf("escalation finding changed base severity from Medium to %s", repAll.Base)
	}
	if repAll.Severity != mechanics.Critical {
		t.Errorf("expected final severity Critical, got %s", repAll.Severity)
	}

	// 3. Only escalations: base should be Clear (0).
	var escChecks []mechanics.Check
	for _, f := range escalationFindings {
		escChecks = append(escChecks, staticCheck{f.Check, f})
	}
	engineEsc := &mechanics.Engine{Checks: escChecks}
	repEsc, err := engineEsc.Run(ctx, sub)
	if err != nil {
		t.Fatalf("engineEsc.Run: %v", err)
	}
	if repEsc.Base != mechanics.Clear {
		t.Errorf("base severity should be Clear when only escalations exist, got %s", repEsc.Base)
	}
	if repEsc.Severity != mechanics.Critical {
		t.Errorf("expected final severity Critical, got %s", repEsc.Severity)
	}
}
