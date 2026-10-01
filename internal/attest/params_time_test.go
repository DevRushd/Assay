package attest_test

import (
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// The on-chain boundary. Params.ScannedAt is what a submitter feeds toward
// the attest() call alongside attested_at, the ledger's u64 unix-second
// count. The u64 leg itself lives in Soroban and is out of scope by the
// issue's own terms; what is testable here is the Go half of the boundary:
// the rendering Params exposes, and the instants a ledger timestamp can and
// cannot name.

// TestScannedAtTimePrecisionIsPinned: FromReport renders ScannedAt at
// whole-second UTC precision — Go layout 2006-01-02T15:04:05Z, the same shape
// attested_at counts in whole seconds. Sub-second information is dropped here
// by definition; this test makes that definition loud. If the rendering
// changes, anyone comparing Params.ScannedAt against attested_at needs to know
// first.
func TestScannedAtTimePrecisionIsPinned(t *testing.T) {
	for _, tc := range []struct {
		name string
		nano int
		want string
	}{
		{"zero", 0, "2026-09-24T12:00:00Z"},
		{"whole_second", 0, "2026-09-24T12:00:00Z"},
		{"one_nano", 1, "2026-09-24T12:00:00Z"},
		{"half_second", 500000000, "2026-09-24T12:00:00Z"},
		{"just_under_next_second", 999999999, "2026-09-24T12:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := attest.FromReport(report(func(r *mechanics.Report) {
				r.ScannedAt = mechanics.NewCanonicalTime(time.Date(2026, 9, 24, 12, 0, 0, tc.nano, time.UTC))
			}))
			if err != nil {
				t.Fatalf("FromReport: %v", err)
			}
			if params.ScannedAt != tc.want {
				t.Fatalf("ScannedAt rendered %q, want %q (whole-second UTC precision)",
					params.ScannedAt, tc.want)
			}
		})
	}
}

// TestParamsScannedAtIsUTCHoweverTheReportWasMade: a Report built with a
// non-UTC clock location must still render as a UTC instant. attested_at is a
// unix second count — zone-free — so the string form of the scan time must
// not carry a local offset that a submitter could echo into the ledger tooling.
func TestScannedAtTimeIsUTCHoweverTheReportWasMade(t *testing.T) {
	loc := time.FixedZone("UTC+5:30", 5*3600+1800)
	params, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.ScannedAt = mechanics.NewCanonicalTime(time.Date(2026, 9, 24, 17, 30, 0, 0, loc)) // = 12:00:00Z
	}))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	if params.ScannedAt != "2026-09-24T12:00:00Z" {
		t.Fatalf("non-UTC ScannedAt rendered %q, want the UTC instant 2026-09-24T12:00:00Z", params.ScannedAt)
	}
}

// TestScannedAtUnixSecondRoundTrip pins the correspondence with the on-chain
// representation: attested_at is a u64 count of unix seconds, so the string
// Params exposes must convert back to exactly the unix second of the source
// instant, and every edge instant the report format can carry must have a
// well-defined second-level form.
func TestScannedAtTimeUnixSecondRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Time
		want int64
	}{
		{"unix_epoch", time.Unix(0, 0).UTC(), 0},
		{"pre_epoch_negative", time.Unix(-1, 999999999).UTC(), -1},
		{"documented_attested_at", time.Date(2026, 8, 15, 5, 27, 31, 0, time.UTC), 1786771651},
		{"far_future", time.Unix(34359738368, 0).UTC(), 34359738368},
		{"non_utc_same_instant", time.Unix(1786771651, 0).In(time.FixedZone("UTC+5:30", 5*3600+1800)), 1786771651},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := attest.FromReport(report(func(r *mechanics.Report) {
				r.ScannedAt = mechanics.NewCanonicalTime(tc.at)
			}))
			if err != nil {
				t.Fatalf("FromReport: %v", err)
			}
			parsed, err := time.Parse(time.RFC3339, params.ScannedAt)
			if err != nil {
				t.Fatalf("Params.ScannedAt does not parse: %v", err)
			}
			if got := parsed.Unix(); got != tc.want {
				t.Fatalf("unix second = %d, want %d", got, tc.want)
			}
		})
	}
}
