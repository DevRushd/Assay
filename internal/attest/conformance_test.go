package attest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// conformanceCase is one entry of the language-neutral suite in
// conformance/cases.json (#468). The JSON pairs a minimal report with the
// preimage bytes and evidence_hash the canonical encoding must produce; a
// reimplementation in any language can run the same file, and this test is
// this repo's run of it, so the suite and the Go encoder cannot drift apart
// silently.
type conformanceCase struct {
	Name   string   `json:"name"`
	Covers []string `json:"covers"`
	Notes  string   `json:"notes"`
	// ScannerIdentity is the identity the scanner line must render for a
	// case with scanner_bound. The real value is build-dependent, so the
	// case names it and the test pins it for the case's duration.
	ScannerIdentity string           `json:"scanner_identity"`
	Input           mechanics.Report `json:"input"`
	Preimage        string           `json:"preimage"`
	Digest          string           `json:"digest"`
}

const (
	conformanceFile  = "../../conformance/cases.json"
	specFile         = "../../docs/contract-interface.md"
	conformanceIdent = "v9.9.9-conformance"
)

func loadConformance(t *testing.T) []conformanceCase {
	t.Helper()
	raw, err := os.ReadFile(conformanceFile)
	if err != nil {
		t.Fatalf("read conformance suite: %v", err)
	}
	var cases []conformanceCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse conformance suite: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("conformance suite is empty")
	}
	return cases
}

// mechanicsFromNames recovers the bitset the preimage hashes from the names
// the JSON carries, using the canonical Names table itself rather than a
// second copy of the bit positions: the encoding renders the bitset, the
// report document speaks in names, and the mapping between them is the ABI.
func mechanicsFromNames(t *testing.T, names []string) mechanics.Mechanic {
	t.Helper()
	var m mechanics.Mechanic
	for _, n := range names {
		found := false
		for bit := mechanics.Mechanic(1); bit != 0; bit <<= 1 {
			ns := bit.Names()
			if len(ns) == 1 && ns[0] == n {
				m |= bit
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("mechanics name %q has no bit in the ABI table", n)
		}
	}
	return m
}

func TestConformanceSuite(t *testing.T) {
	cases := loadConformance(t)
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			rep := c.Input
			rep.Mechanics = mechanicsFromNames(t, rep.MechanicNames)

			if c.ScannerIdentity != "" {
				if c.ScannerIdentity != conformanceIdent {
					t.Fatalf("case pins scanner identity %q but the test pins %q",
						c.ScannerIdentity, conformanceIdent)
				}
				prev := attest.ScannerIdentity
				attest.ScannerIdentity = c.ScannerIdentity
				t.Cleanup(func() { attest.ScannerIdentity = prev })
			} else if rep.ScannerBound {
				t.Fatal("scanner_bound input without a scanner_identity to render")
			}

			params, err := attest.FromReport(&rep)
			if err != nil {
				t.Fatalf("FromReport: %v", err)
			}
			if params.Preimage != c.Preimage {
				t.Errorf("preimage diverges from the suite\n got: %q\nwant: %q",
					params.Preimage, c.Preimage)
			}
			if params.EvidenceHash != c.Digest {
				t.Errorf("evidence_hash diverges from the suite: got %s, want %s",
					params.EvidenceHash, c.Digest)
			}

			// The committed bytes hash to the committed digest, checked
			// without the encoder: anyone, in any language, can run this
			// half of the suite with nothing but SHA-256.
			sum := sha256.Sum256([]byte(c.Preimage))
			if got := hex.EncodeToString(sum[:]); got != c.Digest {
				t.Errorf("preimage bytes do not hash to the recorded digest: got %s", got)
			}

			// The version line must be a tag the encoding actually emits.
			first, _, _ := strings.Cut(c.Preimage, "\n")
			switch first {
			case attest.PreimageVersion, attest.PreimageVersionCheckSet, attest.PreimageVersionNetwork,
				attest.PreimageVersionScanner:
			default:
				t.Errorf("preimage starts with unknown version line %q", first)
			}
		})
	}
}

// abnfRuleName matches one rule definition in the spec's ABNF block. The
// grammar is written over lowercase kebab-case names, so a comment line
// (starting with ";") can never match.
var abnfRuleName = regexp.MustCompile(`(?m)^([a-z][a-z0-9-]*)\s*=`)

// TestConformanceCoversEveryGrammarRule makes the coverage requirement in
// #468 structural rather than aspirational: every rule the spec's grammar
// defines must be exercised by at least one case, and a case may only claim
// rules that exist. When the grammar grows, this test names the rule that
// still needs a case.
func TestConformanceCoversEveryGrammarRule(t *testing.T) {
	raw, err := os.ReadFile(specFile)
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	abnfStart := strings.Index(string(raw), "```abnf")
	if abnfStart < 0 {
		t.Fatal("docs/contract-interface.md has no ```abnf grammar block")
	}
	rest := string(raw)[abnfStart+len("```abnf"):]
	abnfEnd := strings.Index(rest, "```")
	if abnfEnd < 0 {
		t.Fatal("the ABNF grammar block in docs/contract-interface.md is not closed")
	}
	grammar := rest[:abnfEnd]

	rules := map[string]bool{}
	for _, m := range abnfRuleName.FindAllStringSubmatch(grammar, -1) {
		rules[m[1]] = true
	}
	if len(rules) == 0 {
		t.Fatal("the ABNF grammar block defines no rules")
	}

	covered := map[string]bool{}
	for _, c := range loadConformance(t) {
		for _, r := range c.Covers {
			if !rules[r] {
				t.Errorf("case %q claims grammar rule %q, which the spec does not define",
					c.Name, r)
			}
			covered[r] = true
		}
	}
	for r := range rules {
		if !covered[r] {
			t.Errorf("grammar rule %q is exercised by no conformance case", r)
		}
	}
}

// A suite file without cases would make every assertion above vacuous.
func TestConformanceSuiteIsNotEmptyAndNamed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range loadConformance(t) {
		if strings.TrimSpace(c.Name) == "" {
			t.Error("a case has no name")
		}
		if seen[c.Name] {
			t.Errorf("duplicate case name %q", c.Name)
		}
		seen[c.Name] = true
		if len(c.Covers) == 0 {
			t.Errorf("case %q declares no grammar rules it exercises", c.Name)
		}
	}
}
