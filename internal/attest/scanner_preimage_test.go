package attest_test

import (
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
)

// Issue #40 — bind the scanner version into the evidence_hash preimage.
//
// The design decided here: the scanner is identified by its MODULE VERSION
// (attest.ScannerIdentity, "devel" for unstamped builds), not a build-stamped
// commit — a commit stamp would make every dev build hash differently and
// destroy cross-machine reproducibility, which is what the field is for.
// Reports opt in through Report.ScannerBound, which scan.Scanner sets (#271);
// the scanner line is the v4 encoding, which also binds the check set and the
// network (#270). Reports without it keep their v1/v2/v3 bytes, so the ten
// on-chain attestations keep reproducing.

// scannerBoundReport builds a clean report carrying all three bindings, i.e.
// the v4 shape every scan.Scanner report has.
func scannerBoundReport(mut func(*mechanics.Report)) *mechanics.Report {
	return report(func(r *mechanics.Report) {
		r.CheckSet = []string{"capability", "domain", "mutability", "reputation"}
		r.Network = horizon.PublicNet
		r.ScannerBound = true
		if mut != nil {
			mut(r)
		}
	})
}

// TestV4PreimageNamesTheScanner pins the v4 layout: version line
// assay-evidence-v4, then the scanner identity line immediately after it
// (identity before content), with the checks and network lines further down.
func TestV4PreimageNamesTheScanner(t *testing.T) {
	pre := mustPreimage(t, scannerBoundReport(nil))

	lines := strings.Split(pre, "\n")
	if len(lines) < 10 {
		t.Fatalf("v4 preimage too short:\n%s", pre)
	}
	if lines[0] != attest.PreimageVersionScanner {
		t.Fatalf("version line = %q, want %s", lines[0], attest.PreimageVersionScanner)
	}
	wantScanner := "scanner\t" + attest.ScannerIdentity
	if lines[1] != wantScanner {
		t.Fatalf("scanner line = %q, want %q", lines[1], wantScanner)
	}
	if !strings.HasPrefix(lines[2], "asset\t") {
		t.Fatalf("third line = %q, want the asset line", lines[2])
	}
	if !strings.HasPrefix(lines[8], "checks\t") || !strings.HasPrefix(lines[9], "network\t") {
		t.Fatalf("lines 9-10 = %q, %q; want the checks then network lines", lines[8], lines[9])
	}

	// The identity is non-empty even in dev builds: unstamped builds report
	// as "devel" rather than an empty string, so the line always says
	// something meaningful.
	if strings.TrimSpace(strings.SplitN(lines[1], "\t", 2)[1]) == "" {
		t.Fatal("scanner identity is empty; unstamped builds must report \"devel\"")
	}
}

// The scanner identity is escaped exactly once, like every other field. It
// used to be escaped twice, which a release identity never exposed but a
// reimplementation following the spec would not reproduce.
func TestScannerIdentityIsEscapedOnce(t *testing.T) {
	orig := attest.ScannerIdentity
	defer func() { attest.ScannerIdentity = orig }()
	attest.ScannerIdentity = `odd\id`

	pre := mustPreimage(t, scannerBoundReport(nil))
	if line := strings.Split(pre, "\n")[1]; line != `scanner	odd\\id` {
		t.Fatalf("scanner line = %q, want the backslash escaped once", line)
	}
}

// TestV4HashesDifferFromV3 is the property the whole issue exists for: the
// same evidence, classified by a scanner that declares its identity, must
// hash differently from one that does not — otherwise a downgrade to a
// different scanner version is undetectable.
func TestV4HashesDifferFromV3(t *testing.T) {
	v3Params, err := attest.FromReport(scannerBoundReport(func(r *mechanics.Report) { r.ScannerBound = false }))
	if err != nil {
		t.Fatalf("FromReport (v3): %v", err)
	}
	v4Params, err := attest.FromReport(scannerBoundReport(nil))
	if err != nil {
		t.Fatalf("FromReport (v4): %v", err)
	}

	if v3Params.EvidenceHash == v4Params.EvidenceHash {
		t.Fatal("v3 and v4 hashes are equal; the scanner identity commits nothing")
	}
	if firstLine(v3Params.Preimage) != attest.PreimageVersionNetwork {
		t.Fatalf("unbound report not written under v3: %q", firstLine(v3Params.Preimage))
	}
	if firstLine(v4Params.Preimage) != attest.PreimageVersionScanner {
		t.Fatalf("bound report not written under v4: %q", firstLine(v4Params.Preimage))
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

// TestEarlierEncodingsAreUnchangedByScannerBinding is the migration
// guarantee: reports that do not opt in keep the exact v1/v2/v3 bytes, so
// every attestation already on chain keeps reproducing. The committed vectors
// enforce the same thing byte-for-byte; this asserts the gating logic itself.
func TestEarlierEncodingsAreUnchangedByScannerBinding(t *testing.T) {
	cases := map[string]*mechanics.Report{
		attest.PreimageVersion: report(nil),
		attest.PreimageVersionCheckSet: report(func(r *mechanics.Report) {
			r.CheckSet = []string{"capability"}
		}),
		attest.PreimageVersionNetwork: report(func(r *mechanics.Report) {
			r.CheckSet = []string{"capability"}
			r.Network = horizon.PublicNet
		}),
	}
	for want, rep := range cases {
		pre := mustPreimage(t, rep)
		if strings.Contains(pre, "scanner\t") || firstLine(pre) != want {
			t.Errorf("%s report altered by the scanner encoding: %q", want, firstLine(pre))
		}
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
