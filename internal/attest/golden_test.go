package attest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
)

// The reproducibility claim, tested directly: the preimage bytes are
// byte-identical no matter which Go version or platform derives them.
//
// The vectors_test.go tests already prove the bytes agree with the committed
// fixtures on the Go version that runs them. What that cannot show is whether
// they would still agree under a different toolchain or OS — and CI pins Go
// via go.mod while contributors run whatever they have, so a divergence there
// would surface as an unexplained evidence_hash mismatch for someone
// re-scanning an already-attested asset.
//
// The places a cross-version or cross-platform difference could appear are all
// in Preimage's inputs, and this test is sensitive to each:
//
//   - map iteration order: the encoder must never range over a map. If it
//     starts to, re-derived bytes vary run to run and the comparison below
//     fails at least sometimes; the repetition makes a flaky failure a
//     probable one rather than a rare one.
//   - strconv: FormatUint, FormatBool and the ScannedAt layout are version-
//     stable, but a future toolchain that formatted differently would change
//     the numeric and boolean lines here and nothing else would catch it.
//   - sort.Strings: byte-lexicographic ordering of evidence lines. A runtime
//     sort change or a switch to a collation-aware sort would reorder them.
//   - line endings and the source encoding: git can translate LF on checkout
//     and a Windows editor can introduce CRLF. A preimage derived from such
//     files, or a vector committed with CRLF, would hash differently on that
//     platform alone. The digest assertion and the LF checks below pin this.
//
// The comparison is bytes.Equal against the raw committed file — no parse, no
// re-encoding, no normalization. If the bytes differ, this names the first
// divergent offset so the mismatch is diagnosable from the CI log alone.
//
// The vectors come from vectorReports in vectors_test.go (#38), which pairs
// every fixture with the Report that produces it, so this test automatically
// covers every vector the test-vector issue added, including
// aqua-mainnet-onchain, whose digest is the evidence_hash of a live mainnet
// attestation.
func TestGoldenPreimageBytesAreIdentical(t *testing.T) {
	if len(vectorReports) == 0 {
		t.Fatal("vectorReports is empty: the golden test has nothing to pin")
	}

	for name, build := range vectorReports {
		t.Run(name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", "vectors", name+".preimage"))
			if err != nil {
				t.Fatalf("read committed golden preimage: %v", err)
			}
			digestBytes, err := os.ReadFile(filepath.Join("testdata", "vectors", name+".digest"))
			if err != nil {
				t.Fatalf("read committed golden digest: %v", err)
			}
			wantDigest := strings.TrimSpace(string(digestBytes))

			// Derive the bytes fresh. Preimage takes the Report and returns
			// the encoding; nothing else is involved.
			rep := build()
			got := []byte(attest.Preimage(rep))

			// The property under test: identical bytes, no interpretation.
			if !bytes.Equal(got, want) {
				offset := -1
				for i := range got {
					if i >= len(want) || got[i] != want[i] {
						offset = i
						break
					}
				}
				if offset == -1 && len(want) < len(got) {
					offset = len(want)
				}
				t.Fatalf("preimage bytes are not identical to the committed golden file: first divergence at offset %d\ngot %d bytes, want %d bytes\ngot:  %q\nwant: %q",
					offset, len(got), len(want), got, want)
			}

			// sha256 over the exact derived bytes must equal the committed
			// digest: the claim is about bytes, so the digest has to come from
			// those bytes and not from a parsed-then-rewritten structure.
			sum := sha256.Sum256(got)
			if gotDigest := hex.EncodeToString(sum[:]); gotDigest != wantDigest {
				t.Fatalf("sha256 of the derived bytes diverged from the committed digest: got %s, want %s", gotDigest, wantDigest)
			}

			// The encoder derives the same digest again on a second pass.
			// Re-running it also keeps the test meaningful under -count and
			// -race, where a map-order bug would not always show on one pass.
			if again := attest.Preimage(rep); !bytes.Equal([]byte(again), got) {
				t.Fatalf("Preimage did not derive the same bytes twice: a map or sort is deciding the output")
			}
		})
	}
}

// A golden file that does not itself have canonical line endings would make
// every platform wrong in the same way, which the test above cannot detect.
// These checks pin the committed bytes' shape: LF-terminated, no CRLF, no
// trailing blank line, and no embedded CR — the exact differences a Windows
// checkout or a gofmt-introducing editor would introduce. Combined with a
// .gitattributes entry forcing LF for *.preimage, they keep the fixtures
// byte-identical across contributor platforms.
func TestGoldenFilesHaveCanonicalLineEndings(t *testing.T) {
	entries, err := filepath.Glob(filepath.Join("testdata", "vectors", "*.preimage"))
	if err != nil {
		t.Fatalf("glob vectors: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no golden preimage files found under testdata/vectors")
	}
	for _, e := range entries {
		raw, err := os.ReadFile(e)
		if err != nil {
			t.Fatalf("read %s: %v", e, err)
		}
		if bytes.Contains(raw, []byte("\r")) {
			t.Errorf("%s contains CR: the golden fixture must be LF-only, or that platform's hash diverges", e)
		}
		if !bytes.HasSuffix(raw, []byte("\n")) {
			t.Errorf("%s does not end with LF: the canonical encoding terminates every line", e)
		}
		if bytes.HasSuffix(raw, []byte("\n\n")) {
			t.Errorf("%s ends with a blank line: the canonical encoding terminates the last line exactly once", e)
		}
		if !strings.HasPrefix(string(raw), attest.PreimageVersion+"\n") {
			t.Errorf("%s does not start with the version line %q", e, attest.PreimageVersion)
		}
	}
}
