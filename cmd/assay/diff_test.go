package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/temporal"
)

// reportFromSequence writes a saved report derived from one committed temporal
// observation fixture. The fixtures are the historical sequences issue #65
// added; reusing them here keeps `assay diff` pinned to the same data the
// detectors are tested over rather than to values a test made up.
//
// The on-disk report deliberately carries only `mechanics` names, as every
// saved scan does: Report.Mechanics is not serialized, so the diff command has
// to rebuild the bitset from those names.
func reportFromSequence(t *testing.T, seq, obs string) *mechanics.Report {
	t.Helper()
	path := filepath.Join("..", "..", "internal", "temporal", "testdata", seq, obs)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var o temporal.Observation
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return &mechanics.Report{
		SchemaVersion:      mechanics.ReportSchemaVersion,
		Asset:              o.Asset,
		Severity:           o.Severity,
		Base:               o.Base,
		Accountability:     o.Accountability,
		MechanicNames:      o.Mechanics.Names(),
		Evidence:           o.Evidence,
		Undetermined:       o.Undetermined,
		UndeterminedChecks: o.UndeterminedChecks,
		ScannedAt:          mechanics.CanonicalTime(o.At),
	}
}

func writeReport(t *testing.T, dir, name string, rep *mechanics.Report) string {
	t.Helper()
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	return path
}

func TestDiffCapabilityAdditionFromHistoricalFixture(t *testing.T) {
	dir := t.TempDir()
	a := writeReport(t, dir, "a.json", reportFromSequence(t, "seq1-capability-addition", "obs2.json"))
	b := writeReport(t, dir, "b.json", reportFromSequence(t, "seq1-capability-addition", "obs3.json"))

	d, out, _, _ := deps(nil, nil)
	if err := runWith([]string{"diff", a, b}, d); err != nil {
		t.Fatalf("diff: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"capability added:",
		"auth_clawback_enabled",
		"base:\tmedium -> high",
		"attribution: capability",
		"result: changed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("diff output missing %q:\n%s", want, got)
		}
	}
}

func TestDiffReputationEscalationFromHistoricalFixture(t *testing.T) {
	dir := t.TempDir()
	a := writeReport(t, dir, "a.json", reportFromSequence(t, "seq2-reputation-escalation", "obs1.json"))
	b := writeReport(t, dir, "b.json", reportFromSequence(t, "seq2-reputation-escalation", "obs2.json"))

	d, out, _, _ := deps(nil, nil)
	if err := runWith([]string{"diff", "-json", a, b}, d); err != nil {
		t.Fatalf("diff: %v", err)
	}
	var got diffResult
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("diff output is not JSON: %v\n%s", err, out.String())
	}
	if got.Severity.Attribution != temporal.AttributionReputation {
		t.Errorf("attribution = %q, want reputation", got.Severity.Attribution)
	}
	if got.Severity.Before != mechanics.Clear || got.Severity.After != mechanics.Critical {
		t.Errorf("severity = %s -> %s, want clear -> critical", got.Severity.Before, got.Severity.After)
	}
	if got.Capability.Added.Bits != 0 || got.Capability.Removed.Bits != 0 {
		t.Errorf("capability moved on a reputation-only change: %+v", got.Capability)
	}
	if !got.Changed {
		t.Error("Changed = false, want true")
	}
}

func TestDiffUndeterminedSideRendersAsSuch(t *testing.T) {
	dir := t.TempDir()
	a := writeReport(t, dir, "a.json", reportFromSequence(t, "seq5-undetermined-observation", "obs1.json"))
	b := writeReport(t, dir, "b.json", reportFromSequence(t, "seq5-undetermined-observation", "obs2.json"))

	d, out, _, _ := deps(nil, nil)
	if err := runWith([]string{"diff", a, b}, d); err != nil {
		t.Fatalf("diff: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "UNDETERMINED (reputation did not complete)") {
		t.Errorf("diff output does not identify the partial side:\n%s", got)
	}
	if !strings.Contains(got, "unknown") {
		t.Errorf("diff output renders a non-comparison without saying unknown:\n%s", got)
	}
	if strings.Contains(got, "result: changed") {
		t.Errorf("an unknown comparison must not render as a change:\n%s", got)
	}
}

func TestDiffRefusesDifferentAssets(t *testing.T) {
	a := testReport()
	a.SchemaVersion = mechanics.ReportSchemaVersion
	b := testReport()
	b.SchemaVersion = mechanics.ReportSchemaVersion
	b.Asset = mechanics.Asset{Code: "AQUA", Issuer: "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"}

	dir := t.TempDir()
	d, _, _, _ := deps(nil, nil)
	err := runWith([]string{
		"diff",
		writeReport(t, dir, "a.json", a),
		writeReport(t, dir, "b.json", b),
	}, d)
	if err == nil || !strings.Contains(err.Error(), "different assets") {
		t.Fatalf("diff error = %v, want a different-assets refusal", err)
	}
}

func TestDiffRefusesUnknownSchemaVersion(t *testing.T) {
	rep := testReport()
	rep.SchemaVersion = mechanics.ReportSchemaVersion + 1

	dir := t.TempDir()
	d, _, _, _ := deps(nil, nil)
	err := runWith([]string{
		"diff",
		writeReport(t, dir, "a.json", rep),
		writeReport(t, dir, "b.json", func() *mechanics.Report { r := testReport(); r.SchemaVersion = mechanics.ReportSchemaVersion; return r }()),
	}, d)
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("diff error = %v, want a schema_version refusal", err)
	}
}

func TestDiffRejectsTwoArgumentsOnly(t *testing.T) {
	d, _, _, _ := deps(nil, nil)
	if err := runWith([]string{"diff", "only-one.json"}, d); err == nil {
		t.Fatal("diff accepted one report; want a usage error")
	}
}
