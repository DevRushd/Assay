package attest_test

import (
	"errors"
	"testing"

	"github.com/use-assay/assay/internal/attest"
)

// TestDowngrade_OldVersionFlagged verifies that an attestation carrying an older
// scanner identity (such as pre-#23 fail-open outage or pre-#25 empty-directory misread)
// is flagged when a consumer requires a minimum acceptable version.
func TestDowngrade_OldVersionFlagged(t *testing.T) {
	minVersion := "v1.0.0"

	// Historical bugs modeled as older scanner versions:
	// - pre-#23 scanner code (e.g., v0.1.0) reported Horizon outages as clean scans
	// - pre-#25 scanner code (e.g., v0.2.0) reported unlisted addresses as empty directory listings
	historicalBugs := []struct {
		name    string
		version string
	}{
		{"pre_23_outage_fail_open_bug", "v0.1.0"},
		{"pre_25_empty_directory_misread_bug", "v0.2.0"},
		{"pre_release_beta_scanner", "v0.9.9"},
	}

	for _, tc := range historicalBugs {
		t.Run(tc.name, func(t *testing.T) {
			status, err := attest.VerifyVersion(tc.version, minVersion)
			if status != attest.ProvenanceInvalid {
				t.Fatalf("expected ProvenanceInvalid for older scanner version %q, got %q", tc.version, status)
			}
			if !errors.Is(err, attest.ErrScannerDowngrade) {
				t.Fatalf("expected ErrScannerDowngrade, got %v", err)
			}
		})
	}
}

// TestDowngrade_AbsentVersionFlaggedAsUnknown verifies that an attestation without a
// recorded scanner version (pre-v2 attestation) is reported as unknown provenance,
// and is never silently accepted as valid.
func TestDowngrade_AbsentVersionFlaggedAsUnknown(t *testing.T) {
	minVersion := "v1.0.0"

	for _, absent := range []string{"", "   "} {
		status, err := attest.VerifyVersion(absent, minVersion)
		if status != attest.ProvenanceUnknown {
			t.Fatalf("expected ProvenanceUnknown for absent version %q, got %q", absent, status)
		}
		if !errors.Is(err, attest.ErrUnknownProvenance) {
			t.Fatalf("expected ErrUnknownProvenance, got %v", err)
		}
	}
}

// TestDowngrade_CurrentVersionAccepted verifies that an attestation from an acceptable
// scanner version (>= caller's minimum) is verified and accepted.
func TestDowngrade_CurrentVersionAccepted(t *testing.T) {
	minVersion := "v1.0.0"

	acceptable := []struct {
		name    string
		version string
	}{
		{"exact_minimum", "v1.0.0"},
		{"patch_bump", "v1.0.1"},
		{"minor_bump", "v1.1.0"},
		{"next_major", "v2.0.0"},
	}

	for _, tc := range acceptable {
		t.Run(tc.name, func(t *testing.T) {
			status, err := attest.VerifyVersion(tc.version, minVersion)
			if status != attest.ProvenanceValid {
				t.Fatalf("expected ProvenanceValid for acceptable version %q, got %q", tc.version, status)
			}
			if err != nil {
				t.Fatalf("expected nil error for valid version, got %v", err)
			}
		})
	}
}

// TestDowngrade_ConsumerExpressesMinimumVersion verifies that callers can express
// arbitrary minimum version constraints.
func TestDowngrade_ConsumerExpressesMinimumVersion(t *testing.T) {
	cases := []struct {
		recorded   string
		min        string
		wantStatus attest.ProvenanceStatus
	}{
		{"v2.0.0", "v2.0.0", attest.ProvenanceValid},
		{"v1.9.0", "v2.0.0", attest.ProvenanceInvalid},
		{"v2.1.0", "v2.0.0", attest.ProvenanceValid},
		{"", "v2.0.0", attest.ProvenanceUnknown},
	}

	for _, tc := range cases {
		status, _ := attest.VerifyVersion(tc.recorded, tc.min)
		if status != tc.wantStatus {
			t.Errorf("VerifyVersion(%q, %q) = %q, want %q", tc.recorded, tc.min, status, tc.wantStatus)
		}
	}
}

// TestDowngrade_DoesNotInvalidateExistingAttestations verifies that pre-versioning
// attestations return unknown provenance rather than invalid state, ensuring existing
// on-chain attestations can be handled with documented migration rules.
func TestDowngrade_DoesNotInvalidateExistingAttestations(t *testing.T) {
	status, err := attest.VerifyVersion("", "v1.0.0")
	if status == attest.ProvenanceInvalid {
		t.Fatal("pre-versioning attestation must not be retroactively marked as invalid without migration")
	}
	if status != attest.ProvenanceUnknown {
		t.Fatalf("expected ProvenanceUnknown, got %q", status)
	}
	if !errors.Is(err, attest.ErrUnknownProvenance) {
		t.Fatalf("expected ErrUnknownProvenance, got %v", err)
	}
}
