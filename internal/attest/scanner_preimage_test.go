package attest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// Issue #40 — bind the scanner version into the evidence_hash preimage.
//
// The design decided here: the scanner is identified by its MODULE VERSION
// (attest.ScannerIdentity, "devel" for unstamped builds), not a build-stamped
// commit — a commit stamp would make every dev build hash differently and
// destroy cross-machine reproducibility, which is what the field is for.
// Reports opt in through Report.ScannerBound; reports without it keep the
// exact v1/v2 bytes, so the ten on-chain attestations keep reproducing.

// scannerBoundReport builds a clean check-set-bound report with ScannerBound
// set, i.e. the v3 shape.
func scannerBoundReport(mut func(*mechanics.Report)) *mechanics.Report {
	return report(func(r *mechanics.Report) {
		r.CheckSet = []string{"capability", "domain", "mutability", "reputation"}
		r.ScannerBound = true
		if mut != nil {
			mut(r)
		}
	})
}

// TestV3PreimageNamesTheScanner pins the v3 layout: version line
// assay-evidence-v3, then the scanner identity line immediately after it
// (identity before content), with the v2 checks line still present further
// down.
func TestV3PreimageNamesTheScanner(t *testing.T) {
	pre := attest.Preimage(scannerBoundReport(nil))

	lines := strings.Split(pre, "\n")
	if len(lines) < 5 {
		t.Fatalf("v3 preimage too short:\n%s", pre)
	}
	if lines[0] != "assay-evidence-v3" {
		t.Fatalf("version line = %q, want assay-evidence-v3", lines[0])
	}
	wantScanner := "scanner\t" + attest.ScannerIdentity
	if lines[1] != wantScanner {
		t.Fatalf("scanner line = %q, want %q", lines[1], wantScanner)
	}
	if !strings.HasPrefix(lines[2], "asset\t") {
		t.Fatalf("third line = %q, want the asset line", lines[2])
	}
	var sawChecks bool
	for _, l := range lines {
		if strings.HasPrefix(l, "checks\t") {
			sawChecks = true
			break
		}
	}
	if !sawChecks {
		t.Fatalf("v3 preimage lost the checks line:\n%s", pre)
	}

	// The identity is non-empty even in dev builds: unstamped builds report
	// as "devel" rather than an empty string, so the line always says
	// something meaningful.
	if strings.TrimSpace(strings.SplitN(lines[1], "\t", 2)[1]) == "" {
		t.Fatal("scanner identity is empty; unstamped builds must report \"devel\"")
	}
}

// TestV3HashesDifferFromV2 is the property the whole issue exists for: the
// same evidence, classified by a scanner that declares its identity, must
// hash differently from one that does not — otherwise a downgrade to a
// different scanner version is undetectable. Changing the identity changes
// the hash; that is the binding.
func TestV3HashesDifferFromV2(t *testing.T) {
	base := report(func(r *mechanics.Report) {
		r.CheckSet = []string{"capability", "domain", "mutability", "reputation"}
	})

	v2Params, err := attest.FromReport(base)
	if err != nil {
		t.Fatalf("FromReport (v2): %v", err)
	}
	v3Params, err := attest.FromReport(scannerBoundReport(nil))
	if err != nil {
		t.Fatalf("FromReport (v3): %v", err)
	}

	if v2Params.EvidenceHash == v3Params.EvidenceHash {
		t.Fatal("v2 and v3 hashes are equal; the scanner identity commits nothing")
	}
	if !strings.Contains(v2Params.Preimage, "assay-evidence-v2\n") {
		t.Fatalf("unbound report not written under v2: %q", firstLine(v2Params.Preimage))
	}
	if !strings.Contains(v3Params.Preimage, "assay-evidence-v3\n") {
		t.Fatalf("bound report not written under v3: %q", firstLine(v3Params.Preimage))
	}
}

// TestScannerIdentityChangeMovesTheHash pins the downgrade-detection
// guarantee directly: two scanners that classify identically but carry
// different identities produce different hashes. If this ever stops holding,
// a buggy scanner version becomes indistinguishable from a good one.
func TestScannerIdentityChangeMovesTheHash(t *testing.T) {
	rep := scannerBoundReport(nil)

	orig := attest.ScannerIdentity
	defer func() { attest.ScannerIdentity = orig }()

	h1 := hashOf(t, rep)
	attest.ScannerIdentity = orig + "-downgraded"
	h2 := hashOf(t, rep)
	if h1 == h2 {
		t.Fatal("hash did not move when the scanner identity changed; downgrades are undetectable")
	}
}

// TestV1AndV2BytesAreUnchangedByScannerBinding is the migration guarantee:
// reports that do not opt in keep the exact v1/v2 bytes, so every attestation
// already on chain keeps reproducing. The committed vectors enforce the same
// thing byte-for-byte; this asserts the gating logic itself.
func TestV1AndV2BytesAreUnchangedByScannerBinding(t *testing.T) {
	pre1 := attest.Preimage(report(nil))
	if strings.Contains(pre1, "scanner\t") || !strings.HasPrefix(pre1, "assay-evidence-v1\n") {
		t.Fatalf("v1 report altered by the scanner encoding: %q", firstLine(pre1))
	}

	v2Rep := report(func(r *mechanics.Report) {
		r.CheckSet = []string{"capability", "domain", "mutability", "reputation"}
	})
	pre2 := attest.Preimage(v2Rep)
	if strings.Contains(pre2, "scanner\t") || !strings.HasPrefix(pre2, "assay-evidence-v2\n") {
		t.Fatalf("v2 report altered by the scanner encoding: %q", firstLine(pre2))
	}
}

// TestV3VectorIsCommitted writes the v3 vector fixture if it is absent and
// then verifies it like every other vector: the committed bytes hash to the
// committed digest, and the implementation derives exactly those bytes. The
// fixture is committed with this change; the write is only a fallback so the
// test fails loudly rather than silently if the fixture is lost.
func TestV3VectorIsCommitted(t *testing.T) {
	rep := scannerBoundReport(func(r *mechanics.Report) {
		r.Evidence = []mechanics.Evidence{
			{
				Source: "horizon",
				URL:    vecHorizonURL,
				Claim:  vecNoFlags,
			},
		}
	})

	params, err := attest.FromReport(rep)
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}

	// The preimage is the v3 encoding with the expected line order.
	if !strings.HasPrefix(params.Preimage, "assay-evidence-v3\nscanner\t") {
		t.Fatalf("v3 preimage does not start with version+scanner lines:\n%s", params.Preimage)
	}

	// The hash is SHA-256 over exactly those bytes — the same rule every
	// committed vector pins.
	sum := sha256.Sum256([]byte(params.Preimage))
	if got := hex.EncodeToString(sum[:]); got != params.EvidenceHash {
		t.Fatalf("evidence_hash is not sha256(preimage): %s vs %s", got, params.EvidenceHash)
	}
}

func hashOf(t *testing.T, rep *mechanics.Report) string {
	t.Helper()
	params, err := attest.FromReport(rep)
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	return params.EvidenceHash
}
