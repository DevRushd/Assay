package attest_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
)

// The layout each tag names, as documented in docs/contract-interface.md:
// the keys of the lines between the version line and the evidence lines.
var documentedLayouts = map[string][]string{
	attest.PreimageVersion: {"asset", "severity", "base_severity", "escalated", "mechanics", "accountability"},
	attest.PreimageVersionCheckSet: {"asset", "severity", "base_severity", "escalated", "mechanics", "accountability",
		"checks"},
	attest.PreimageVersionNetwork: {"asset", "severity", "base_severity", "escalated", "mechanics", "accountability",
		"checks", "network"},
	attest.PreimageVersionScanner: {"scanner", "asset", "severity", "base_severity", "escalated", "mechanics",
		"accountability", "checks", "network"},
}

// headerKeys returns the keys of a preimage's lines after the version line
// and before the first evidence line.
func headerKeys(pre string) []string {
	var keys []string
	for _, l := range strings.Split(strings.TrimSuffix(pre, "\n"), "\n")[1:] {
		k, _, _ := strings.Cut(l, "\t")
		if k == "evidence" {
			break
		}
		keys = append(keys, k)
	}
	return keys
}

// TestPreimageVersionIsInjective enumerates every combination of the three
// bindings (#270). Each combination either renders under exactly one tag
// whose layout is the documented one, or is refused with ErrUnencodable. No
// two combinations share a tag, so the tag alone determines the bytes, and
// the verifier accepts exactly what the encoder emits.
func TestPreimageVersionIsInjective(t *testing.T) {
	want := map[[3]bool]string{
		{false, false, false}: attest.PreimageVersion,
		{true, false, false}:  attest.PreimageVersionCheckSet,
		{true, true, false}:   attest.PreimageVersionNetwork,
		{true, true, true}:    attest.PreimageVersionScanner,
	}

	tagOwner := map[string][3]bool{}
	for _, cs := range []bool{false, true} {
		for _, net := range []bool{false, true} {
			for _, sb := range []bool{false, true} {
				combo := [3]bool{cs, net, sb}
				rep := report(func(r *mechanics.Report) {
					if cs {
						r.CheckSet = []string{"reputation", "capability"}
					}
					if net {
						r.Network = horizon.TestNet
					}
					r.ScannerBound = sb
				})

				pre, err := attest.Preimage(rep)
				wantTag, allowed := want[combo]
				if !allowed {
					if !errors.Is(err, attest.ErrUnencodable) {
						t.Errorf("checks=%t network=%t scanner=%t: want ErrUnencodable, got %v (%q)",
							cs, net, sb, err, firstLine(pre))
					}
					if _, ferr := attest.FromReport(rep); !errors.Is(ferr, attest.ErrUnencodable) {
						t.Errorf("checks=%t network=%t scanner=%t: FromReport did not refuse: %v", cs, net, sb, ferr)
					}
					continue
				}
				if err != nil {
					t.Errorf("checks=%t network=%t scanner=%t: %v", cs, net, sb, err)
					continue
				}

				tag := firstLine(pre)
				if tag != wantTag {
					t.Errorf("checks=%t network=%t scanner=%t: tag %s, want %s", cs, net, sb, tag, wantTag)
				}
				if prev, dup := tagOwner[tag]; dup {
					t.Errorf("tag %s used by both %v and %v", tag, prev, combo)
				}
				tagOwner[tag] = combo

				if got := headerKeys(pre); !reflect.DeepEqual(got, documentedLayouts[tag]) {
					t.Errorf("%s layout = %v, documented %v", tag, got, documentedLayouts[tag])
				}

				info, err := attest.ParsePreimage([]byte(pre))
				if err != nil {
					t.Errorf("%s: verifier refuses what the encoder emits: %v", tag, err)
					continue
				}
				if (info.Checks != nil) != cs || (info.Network != "") != net || (info.Scanner != "") != sb {
					t.Errorf("%s: verifier read %+v from bindings checks=%t network=%t scanner=%t",
						tag, info, cs, net, sb)
				}
			}
		}
	}
	if len(tagOwner) != len(want) {
		t.Errorf("%d tags rendered, want %d", len(tagOwner), len(want))
	}
}

// Every tag has a committed vector, so a reimplementation can check itself
// against every layout without running this repo's code (#270).
func TestEveryTagHasACommittedVector(t *testing.T) {
	seen := map[string]bool{}
	for name := range vectorReports {
		raw, err := os.ReadFile(filepath.Join("testdata", "vectors", name+".preimage"))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		seen[firstLine(string(raw))] = true
	}
	for tag := range documentedLayouts {
		if !seen[tag] {
			t.Errorf("no committed vector is written under %s", tag)
		}
	}
}

// PreimageAs re-renders a fresh, fully bound report under an older encoding
// by withholding the bindings that encoding predates — how a v1 attestation is
// re-derived from a scan that binds everything.
func TestPreimageAsWithholdsNewerBindings(t *testing.T) {
	full := scannerBoundReport(nil)
	for _, enc := range []string{"v1", "v2", "v3", "v4", attest.PreimageVersionNetwork} {
		pre, err := attest.PreimageAs(full, enc)
		if err != nil {
			t.Fatalf("PreimageAs(%s): %v", enc, err)
		}
		tag, _ := attest.NormalizePreimageVersion(enc)
		if got := firstLine(pre); got != tag {
			t.Errorf("PreimageAs(%s) renders %s", enc, got)
		}
		if got := headerKeys(pre); !reflect.DeepEqual(got, documentedLayouts[tag]) {
			t.Errorf("PreimageAs(%s) layout = %v, documented %v", enc, got, documentedLayouts[tag])
		}
	}

	v1, err := attest.PreimageAs(full, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if want := mustPreimage(t, report(nil)); v1 != want {
		t.Error("a fully bound report under v1 does not render the same bytes as an unbound one")
	}
}

// A named version may withhold a binding but never invent one: rendering v3
// from a report with no network would need a network line the report cannot
// fill.
func TestPreimageAsNeverAddsABinding(t *testing.T) {
	v2 := report(func(r *mechanics.Report) { r.CheckSet = []string{"capability"} })
	if _, err := attest.PreimageAs(v2, "v3"); !errors.Is(err, attest.ErrUnencodable) {
		t.Fatalf("asking a v2 report for v3: want ErrUnencodable, got %v", err)
	}
	if _, err := attest.FromReportAs(v2, "v4"); !errors.Is(err, attest.ErrUnencodable) {
		t.Fatalf("FromReportAs v4 on a v2 report: want ErrUnencodable, got %v", err)
	}
	if _, err := attest.PreimageAs(v2, "v5"); !errors.Is(err, attest.ErrUnknownPreimageVersion) {
		t.Fatalf("unknown encoding: want ErrUnknownPreimageVersion, got %v", err)
	}
}
