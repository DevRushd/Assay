package attest_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/mechanics"
)

// The independent encoder in scripts/preimage_encoder.py is written from
// docs/contract-interface.md alone, not from the Go implementation. This test
// is the CI bridge between the two: for every committed vector, every mechanics
// fixture, and every language-neutral conformance case, it feeds the same
// report JSON to both encoders and fails when the preimage bytes or SHA-256
// digests disagree.
//
// A deliberate encoding change therefore has to move both implementations and
// the specification together. Updating only the Go encoder leaves Python
// producing the old bytes, and this test names the case that diverged.
func TestIndependentEncoderMatchesGo(t *testing.T) {
	python := crossCheckPython(t)
	root := crossCheckRepoRoot(t)
	encoder := filepath.Join(root, "scripts", "preimage_encoder.py")
	if _, err := os.Stat(encoder); err != nil {
		t.Fatalf("independent encoder is missing: %v", err)
	}

	t.Run("vectors", func(t *testing.T) {
		if len(vectorReports) == 0 {
			t.Fatal("vectorReports is empty: there is nothing to cross-check")
		}
		for name, build := range vectorReports {
			name, build := name, build
			t.Run(name, func(t *testing.T) {
				rep := build()
				// The engine normally fills this from the bitset; the vector
				// builders set Mechanics directly, so mirror that here before
				// the report is serialized for the independent encoder.
				rep.MechanicNames = rep.Mechanics.Names()
				// A scanner-bound vector names the identity it was written
				// with; both encoders must render that one.
				pinVectorIdentity(t, name)
				compareWithIndependentEncoder(t, python, encoder, rep, vectorIdentity[name])
			})
		}
	})

	t.Run("fixtures", func(t *testing.T) {
		fixturesDir := filepath.Join(root, "internal", "mechanics", "testdata")
		entries, err := os.ReadDir(fixturesDir)
		if err != nil {
			t.Fatalf("read mechanics fixtures: %v", err)
		}
		engine := mechanics.NewEngine()
		checked := 0
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			t.Run(name, func(t *testing.T) {
				subject, err := eval.LoadSubject(fixturesDir, name)
				if err != nil {
					t.Fatalf("load subject: %v", err)
				}
				rep, err := engine.Run(context.Background(), subject)
				if err != nil {
					t.Fatalf("run engine: %v", err)
				}
				compareWithIndependentEncoder(t, python, encoder, rep, "")
			})
			checked++
		}
		if checked == 0 {
			t.Fatal("no mechanics fixture subjects were checked")
		}
	})

	t.Run("conformance", func(t *testing.T) {
		for _, c := range loadConformance(t) {
			c := c
			t.Run(c.Name, func(t *testing.T) {
				rep := c.Input
				rep.Mechanics = mechanicsFromNames(t, rep.MechanicNames)

				if c.ScannerIdentity != "" {
					prev := attest.ScannerIdentity
					attest.ScannerIdentity = c.ScannerIdentity
					t.Cleanup(func() { attest.ScannerIdentity = prev })
				} else if rep.ScannerBound {
					t.Fatal("scanner_bound input without a scanner_identity to render")
				}

				compareWithIndependentEncoder(t, python, encoder, &rep, c.ScannerIdentity)
			})
		}
	})
}

// crossCheckPython locates the interpreter CI provides. Locally, a missing
// python3 skips the cross-check rather than making every Go test depend on a
// non-Go tool; in CI it is a hard failure, because a skipped job would claim
// agreement it never checked.
func crossCheckPython(t *testing.T) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("python3 is required for the cross-implementation check in CI: %v", err)
		}
		t.Skip("python3 not found; install python3 to run the cross-implementation check")
	}
	return python
}

func crossCheckRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

type independentEncoderResult struct {
	Version  string `json:"version"`
	Preimage string `json:"preimage"`
	Digest   string `json:"digest"`
}

// compareWithIndependentEncoder serializes the report, runs the independent
// encoder over it, and requires byte-identical preimages and digests.
func compareWithIndependentEncoder(t *testing.T, python, encoder string, rep *mechanics.Report, scannerIdentity string) {
	t.Helper()

	input, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report for independent encoder: %v", err)
	}
	inputPath := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatalf("write report for independent encoder: %v", err)
	}

	args := []string{encoder}
	if scannerIdentity != "" {
		args = append(args, "--scanner-identity", scannerIdentity)
	}
	args = append(args, inputPath)

	cmd := exec.Command(python, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("independent encoder failed: %v\nstderr: %s", err, stderr.String())
	}

	var got independentEncoderResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode independent encoder output: %v\noutput: %s", err, out)
	}

	wantPreimage := mustPreimage(t, rep)
	if got.Preimage != wantPreimage {
		t.Fatalf("independent encoder preimage diverged\n got: %q\nwant: %q", got.Preimage, wantPreimage)
	}
	wantVersion, _, _ := strings.Cut(wantPreimage, "\n")
	if got.Version != wantVersion {
		t.Fatalf("independent encoder version = %q, want %q", got.Version, wantVersion)
	}

	sum := sha256.Sum256([]byte(wantPreimage))
	wantDigest := hex.EncodeToString(sum[:])
	if got.Digest != wantDigest {
		t.Fatalf("independent encoder digest = %s, want %s", got.Digest, wantDigest)
	}
}

// Both encoders refuse the same binding combinations (#270): a network
// without a check set, and a scanner without both. Rendering one would need a
// tag that describes a different layout, so neither implementation may emit
// bytes for it.
func TestIndependentEncoderRefusesUnencodable(t *testing.T) {
	python := crossCheckPython(t)
	encoder := filepath.Join(crossCheckRepoRoot(t), "scripts", "preimage_encoder.py")

	cases := map[string]func(*mechanics.Report){
		"network without checks": func(r *mechanics.Report) { r.Network = "Test SDF Network ; September 2015" },
		"scanner alone":          func(r *mechanics.Report) { r.ScannerBound = true },
		"scanner with checks":    func(r *mechanics.Report) { r.ScannerBound, r.CheckSet = true, []string{"capability"} },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			rep := report(mut)
			rep.MechanicNames = rep.Mechanics.Names()
			if _, err := attest.Preimage(rep); err == nil {
				t.Fatal("Go encoder rendered an unencodable report")
			}

			input, err := json.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, input, 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(python, encoder, "--scanner-identity", "v1.2.3", path).Output()
			if err == nil {
				t.Fatalf("independent encoder rendered an unencodable report: %s", out)
			}
		})
	}
}
