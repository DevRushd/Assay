package mechanics_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
)

// The JSON boundary. Report.ScannedAt and Evidence.RetrievedAt cross it as
// canonical whole-second UTC strings (issue #52): one documented format for
// every time value Assay emits, so the same instant cannot print two ways
// depending on which command produced it. docs/contract-interface.md excludes
// retrieval times from the preimage, so JSON is the only place these two
// fields are serialized at all — which makes the format they use there the
// documented one.

// jsonTimeCases are the instants worth covering at a time boundary. The epoch
// because it is the zero unix second; a leap-second-adjacent instant because a
// leap second (:60) has no Go time.Time representation; a far-future time
// because attested_at consumers compare against ledger clocks; a non-UTC
// offset because the wire format is UTC and a +hh:mm rendering must normalise,
// not reject; and sub-second precision because the canonical format truncates
// it and the truncation is the documented, tested behavior.
var jsonTimeCases = []struct {
	name string
	at   time.Time
}{
	{"unix_epoch", time.Unix(0, 0).UTC()},
	{"leap_second_adjacent", time.Date(2016, 12, 31, 23, 59, 59, 500000000, time.UTC)},
	{"far_future", time.Date(2338, 6, 11, 3, 46, 40, 123000000, time.UTC)}, // 2^35 unix secs
	{"non_utc_input", time.Date(2026, 9, 24, 3, 30, 0, 750000000, time.FixedZone("UTC+5:30", 5*3600+1800))},
	{"zero_nanos", time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)},
	{"nine_digit_nanos", time.Date(2026, 9, 24, 12, 0, 0, 123456789, time.UTC)},
}

// TestScannedAtTimeJSONRoundTrip marshals ScannedAt through the report JSON
// and asserts the value survives at the documented whole-second precision:
// sub-second input is truncated to the canonical representation, non-UTC
// input is normalised to UTC (never rejected), and the round trip is stable.
func TestScannedAtTimeJSONRoundTrip(t *testing.T) {
	for _, tc := range jsonTimeCases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &mechanics.Report{ScannedAt: mechanics.NewCanonicalTime(tc.at)}
			raw, err := json.Marshal(rep)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got mechanics.Report
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			want := tc.at.UTC().Truncate(time.Second)
			if !got.ScannedAt.Time().Equal(want) {
				t.Fatalf("ScannedAt did not survive the JSON round trip: sent %s, want %s, got %s",
					tc.at.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano),
					got.ScannedAt.Time().Format(time.RFC3339Nano))
			}
		})
	}
}

// TestRetrievedAtTimeJSONRoundTrip does the same for evidence claims,
// including an Attempted one — failure evidence carries an attempt time and
// that time must survive serialization like any other.
func TestRetrievedAtTimeJSONRoundTrip(t *testing.T) {
	for _, tc := range jsonTimeCases {
		t.Run(tc.name, func(t *testing.T) {
			f := mechanics.Finding{Evidence: []mechanics.Evidence{{
				Source: "test", Claim: "x", RetrievedAt: mechanics.NewCanonicalTime(tc.at), Attempted: true,
			}}}
			raw, err := json.Marshal(f)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got mechanics.Finding
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(got.Evidence) != 1 {
				t.Fatalf("evidence did not survive: %d entries", len(got.Evidence))
			}
			want := tc.at.UTC().Truncate(time.Second)
			if !got.Evidence[0].RetrievedAt.Time().Equal(want) {
				t.Fatalf("RetrievedAt did not survive the JSON round trip: sent %s, want %s, got %s",
					tc.at.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano),
					got.Evidence[0].RetrievedAt.Time().Format(time.RFC3339Nano))
			}
			if !got.Evidence[0].Attempted {
				t.Error("Attempted flag did not survive the round trip")
			}
		})
	}
}

// TestJSONTimestampPrecisionIsPinned locks the wire format itself. The old
// format was time.Time's RFC 3339Nano default, which emitted nanoseconds from
// `scan` while the attestation stream truncated to seconds — two
// representations of one instant (issue #52). The canonical format is
// whole-second UTC, and this test fails if the emitted form moves again.
func TestJSONTimestampPrecisionIsPinned(t *testing.T) {
	// Every nonzero sub-second digit: 1 nanosecond past whole seconds.
	at := time.Date(2026, 9, 24, 12, 34, 56, 1, time.UTC)
	rep := &mechanics.Report{ScannedAt: mechanics.NewCanonicalTime(at)}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	const wantToken = `"scanned_at":"2026-09-24T12:34:56Z"`
	if got := string(raw); !contains(got, wantToken) {
		t.Fatalf("scanned_at wire format changed:\n got: %s\nwant token: %s\n"+
			"If this change is deliberate, it changes the meaning of every stored report and needs a documented format note.",
			got, wantToken)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// TestJSONTimestampUnmarshalRejectsMalformed pins the invalid state: a value
// that is not a parseable RFC 3339 instant must be rejected, not zeroed.
func TestJSONTimestampUnmarshalRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"2026-09-24 12:00:00Z", // space instead of T
		"2026-09-24T12:00:00",  // missing zone
		"not-a-time",
		"2016-12-31T23:59:60Z", // leap second: real UTC cannot represent it
	} {
		var rep mechanics.Report
		if err := json.Unmarshal([]byte(`{"scanned_at":"`+bad+`"}`), &rep); err == nil {
			t.Errorf("scanned_at %q was accepted by the JSON boundary", bad)
		}
	}
}

// TestJSONTimestampUnmarshalMatchesToolchainOffsetRange pins the RFC 3339
// offset-range rule against whatever the pinned toolchain's time.Parse does,
// so the JSON boundary never diverges from the toolchain.
func TestJSONTimestampUnmarshalMatchesToolchainOffsetRange(t *testing.T) {
	cases := []string{
		"2026-09-24T12:00:00+25:00",
		"2026-09-24T12:00:00-25:00",
		"2026-09-24T12:00:00+23:59", // in range: must always be accepted
	}
	for _, s := range cases {
		_, parseErr := time.Parse(time.RFC3339, s)
		want := parseErr == nil
		var rep mechanics.Report
		err := json.Unmarshal([]byte(`{"scanned_at":"`+s+`"}`), &rep)
		got := err == nil
		if got != want {
			t.Errorf("scanned_at %q: JSON boundary says accepted=%v, toolchain time.Parse says %v", s, got, want)
		}
	}
}
