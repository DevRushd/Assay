package attest_test

import (
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/version"
)

// Issue #278 — one version source, two consumers.
//
// The eval recorder reads internal/version.Version; the v4 preimage's
// `scanner` line reads attest.ScannerIdentity. The acceptance criterion is
// that they cannot disagree for a tagged build, which holds because
// ScannerIdentity is initialized from Version and nothing re-derives it. This
// test is the tripwire if that ever changes: it fails the moment the two stop
// being the same value, tagged or not.
func TestScannerIdentityIsVersionPackage(t *testing.T) {
	if attest.ScannerIdentity != version.Version {
		t.Fatalf("attest.ScannerIdentity = %q, version.Version = %q; they must be one value",
			attest.ScannerIdentity, version.Version)
	}
	if version.Version == "" {
		t.Fatal("version.Version is empty; unstamped builds must report \"devel\"")
	}
}
