package scan_test

import (
	"context"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/horizon"
)

// Every report scan.Scanner produces names the code that produced it (#271).
// scan.Scanner is where the binding is switched on, so a report from it must
// be scanner-bound and its preimage must be v4 with a scanner line. Without
// this, the downgrade defence #40 describes covers no real attestation.
func TestScanBindsTheScanner(t *testing.T) {
	sc := networkFixture(t, "", horizon.PublicNet)
	rep, err := sc.Scan(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !rep.ScannerBound {
		t.Fatal("scan.Scanner produced a report that is not scanner-bound")
	}

	pre, err := attest.Preimage(rep)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	lines := strings.SplitN(pre, "\n", 3)
	if lines[0] != attest.PreimageVersionScanner {
		t.Fatalf("version line = %q, want %s", lines[0], attest.PreimageVersionScanner)
	}
	if lines[1] != "scanner\t"+attest.ScannerIdentity {
		t.Fatalf("second line = %q, want the scanner line", lines[1])
	}
}

func TestScanWithHolderBindsTheScanner(t *testing.T) {
	sc := newStubScanner(t, stubConfig{homeDomain: scanHomeDom, holderTrustline: true})
	for _, holder := range []string{"", holderIssuer} {
		rep, err := sc.ScanWithHolder(context.Background(), mustParse(t, "USDC-"+scanIssuer), holder)
		if err != nil {
			t.Fatalf("ScanWithHolder(%q): %v", holder, err)
		}
		if !rep.ScannerBound {
			t.Fatalf("ScanWithHolder(%q) produced a report that is not scanner-bound", holder)
		}
	}
}
