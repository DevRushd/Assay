package attest_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
)

// The verifier is the thing a third party runs when they do not trust us, so
// the vectors it has to accept are the committed ones rather than fresh
// fixtures: if `verify` cannot reproduce the digests in testdata/vectors, it
// cannot reproduce the digest of a live attestation either.
func TestVerifyPreimageAcceptsEveryCommittedVector(t *testing.T) {
	for name := range vectorReports {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "vectors", name+".preimage"))
			if err != nil {
				t.Fatalf("read vector: %v", err)
			}
			digestBytes, err := os.ReadFile(filepath.Join("testdata", "vectors", name+".digest"))
			if err != nil {
				t.Fatalf("read digest: %v", err)
			}
			digest := strings.TrimSpace(string(digestBytes))

			v, err := attest.VerifyPreimage(raw, digest)
			if err != nil {
				t.Fatalf("VerifyPreimage: %v", err)
			}
			if !v.Match {
				t.Fatalf("vector %s did not verify against its own digest", name)
			}
			if v.Computed != digest {
				t.Fatalf("computed %s, digest file says %s", v.Computed, digest)
			}
		})
	}
}

// A hash copied out of a block explorer, a shell, or a JSON document does not
// arrive in one spelling, and none of the differences change the value.
func TestVerifyPreimageAcceptsHashSpellings(t *testing.T) {
	raw := []byte("assay-evidence-v1\nasset\tAQUA-GABC\n")
	want := attest.HashPreimage(raw)

	for _, spelling := range []string{
		want,
		strings.ToUpper(want),
		"0x" + want,
		"0X" + strings.ToUpper(want),
		"  " + want + "\n",
	} {
		v, err := attest.VerifyPreimage(raw, spelling)
		if err != nil {
			t.Fatalf("spelling %q: %v", spelling, err)
		}
		if !v.Match {
			t.Fatalf("spelling %q did not match", spelling)
		}
	}
}

// A mismatch is the verdict that matters, and it must leave both values
// populated so a caller can show what disagreed rather than only that
// something did.
func TestVerifyPreimageReportsMismatchWithBothHashes(t *testing.T) {
	raw := []byte("assay-evidence-v1\nasset\tAQUA-GABC\n")
	tampered := []byte("assay-evidence-v1\nasset\tAQUA-GABD\n")
	claimed := attest.HashPreimage(raw)

	v, err := attest.VerifyPreimage(tampered, claimed)
	if !errors.Is(err, attest.ErrHashMismatch) {
		t.Fatalf("want ErrHashMismatch, got %v", err)
	}
	if v.Match {
		t.Fatal("Match is true on a mismatch")
	}
	if v.Claimed != claimed {
		t.Fatalf("claimed %s, want %s", v.Claimed, claimed)
	}
	if v.Computed != attest.HashPreimage(tampered) {
		t.Fatalf("computed %s does not hash the tampered bytes", v.Computed)
	}
	if v.Computed == v.Claimed {
		t.Fatal("computed and claimed are equal on a mismatch")
	}
}

// Without a claimed hash there is no verdict to give, but the command still has
// a job: printing the hash of a preimage without a second tool.
func TestVerifyPreimageWithoutClaimReportsNoVerdict(t *testing.T) {
	raw := []byte("assay-evidence-v1\nasset\tAQUA-GABC\n")

	v, err := attest.VerifyPreimage(raw, "")
	if err != nil {
		t.Fatalf("VerifyPreimage: %v", err)
	}
	if v.Match {
		t.Fatal("Match is true with nothing to match against")
	}
	if v.Computed != attest.HashPreimage(raw) {
		t.Fatalf("Computed = %s, want %s", v.Computed, attest.HashPreimage(raw))
	}
}

// A v1 preimage binds no check set. Reporting that as unknown rather than
// complete is the rule the encoding document states, and the verifier is where
// a consumer meets it.
func TestVerifyPreimageNotesV1CheckSetIsUnknown(t *testing.T) {
	raw := []byte("assay-evidence-v1\nasset\tAQUA-GABC\n")

	v, err := attest.VerifyPreimage(raw, "")
	if err != nil {
		t.Fatalf("VerifyPreimage: %v", err)
	}
	if v.Checks != nil {
		t.Fatalf("v1 preimage reported a check set: %v", v.Checks)
	}
	if len(v.Notes) == 0 {
		t.Fatal("v1 preimage produced no note about its unknown check set")
	}
	if !strings.Contains(strings.Join(v.Notes, " "), "unknown") {
		t.Fatalf("notes do not say the check set is unknown: %v", v.Notes)
	}
}

// A malformed hash is a copy-paste error, not a broken attestation, and saying
// so keeps a typo from being mistaken for a failure of the preimage.
func TestVerifyPreimageRejectsMalformedHashAsItsOwnError(t *testing.T) {
	raw := []byte("assay-evidence-v1\nasset\tAQUA-GABC\n")

	for _, bad := range []string{"", "deadbeef", strings.Repeat("z", 64), attest.HashPreimage(raw) + "00"} {
		if strings.TrimSpace(bad) == "" {
			continue
		}
		_, err := attest.VerifyPreimage(raw, bad)
		if !errors.Is(err, attest.ErrMalformedHash) {
			t.Errorf("hash %q: want ErrMalformedHash, got %v", bad, err)
		}
	}
}

func TestNormalizeEvidenceHash(t *testing.T) {
	const bare = "688453bd22e9b694b9c70659d37526bdae18944645542642008e9d961461a4a9"

	cases := []struct {
		in      string
		want    string
		wantErr error
	}{
		{in: bare, want: bare},
		{in: strings.ToUpper(bare), want: bare},
		{in: "0x" + bare, want: bare},
		{in: " " + bare + "\n", want: bare},
		{in: "0xDEAD", wantErr: attest.ErrMalformedHash},
		{in: strings.Repeat("a", 63), wantErr: attest.ErrMalformedHash},
		{in: strings.Repeat("a", 65), wantErr: attest.ErrMalformedHash},
		{in: strings.Repeat("g", 64), wantErr: attest.ErrMalformedHash},
	}
	for _, tc := range cases {
		got, err := attest.NormalizeEvidenceHash(tc.in)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("NormalizeEvidenceHash(%q): want %v, got %v", tc.in, tc.wantErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeEvidenceHash(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeEvidenceHash(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParsePreimage(t *testing.T) {
	const v1 = "assay-evidence-v1\n" +
		"asset\tAQUA-GABC\n" +
		"severity\t1\n" +
		"base_severity\t1\n" +
		"escalated\tfalse\n" +
		"mechanics\t0\n" +
		"accountability\tunknown\n"
	const v2 = "assay-evidence-v2\n" +
		"asset\tAQUA-GABC\n" +
		"severity\t1\n" +
		"base_severity\t1\n" +
		"escalated\tfalse\n" +
		"mechanics\t0\n" +
		"accountability\tunknown\n" +
		"checks\treputation,capability\n"

	t.Run("v1 has no check set", func(t *testing.T) {
		info, err := attest.ParsePreimage([]byte(v1))
		if err != nil {
			t.Fatalf("ParsePreimage: %v", err)
		}
		if info.Version != attest.PreimageVersion {
			t.Errorf("Version = %q", info.Version)
		}
		if info.Asset != "AQUA-GABC" {
			t.Errorf("Asset = %q", info.Asset)
		}
		if info.Checks != nil {
			t.Errorf("Checks = %v, want nil", info.Checks)
		}
	})

	t.Run("v2 reports the bound set sorted", func(t *testing.T) {
		info, err := attest.ParsePreimage([]byte(v2))
		if err != nil {
			t.Fatalf("ParsePreimage: %v", err)
		}
		if info.Version != attest.PreimageVersionCheckSet {
			t.Errorf("Version = %q", info.Version)
		}
		got := strings.Join(info.Checks, ",")
		if got != "capability,reputation" {
			t.Errorf("Checks = %q, want sorted capability,reputation", got)
		}
	})

	t.Run("asset is unescaped", func(t *testing.T) {
		info, err := attest.ParsePreimage([]byte("assay-evidence-v1\nasset\tsome\\tasset\n"))
		if err != nil {
			t.Fatalf("ParsePreimage: %v", err)
		}
		if info.Asset != "some\tasset" {
			t.Errorf("Asset = %q, want the tab restored", info.Asset)
		}
	})

	t.Run("a preimage missing its trailing newline still parses", func(t *testing.T) {
		if _, err := attest.ParsePreimage([]byte(strings.TrimSuffix(v1, "\n"))); err != nil {
			t.Fatalf("ParsePreimage: %v", err)
		}
	})

	refusals := map[string]string{
		"empty":             "",
		"unknown version":   "assay-evidence-v9\nasset\tAQUA-GABC\n",
		"no asset line":     "assay-evidence-v1\nseverity\t1\n",
		"line without tab":  "assay-evidence-v1\nasset\tAQUA-GABC\nnot-a-pair\n",
		"v2 without checks": "assay-evidence-v2\nasset\tAQUA-GABC\n",
	}
	for name, in := range refusals {
		t.Run("refuses "+name, func(t *testing.T) {
			if _, err := attest.ParsePreimage([]byte(in)); err == nil {
				t.Fatal("want an error, got nil")
			}
		})
	}
}
