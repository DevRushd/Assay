package attest_test

import (
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// The preimage boundary. docs/contract-interface.md specifies the preimage as
// the hashable record of what the sources CLAIMED, and documents retrieval
// timestamps as deliberately excluded — "the hash commits to what the sources
// claimed, not to when they were asked". These tests turn that documentation
// into a property a regression cannot pass silently.

// TestPreimageExcludesTimestamps: neither ScannedAt nor any Evidence
// RetrievedAt may appear in the preimage bytes, and shifting them may not
// move the hash. If timestamps ever enter the preimage, every attestation
// already on-chain stops reproducing — the exact failure the encoding
// decision exists to prevent.
func TestPreimageExcludesTimestamps(t *testing.T) {
	rep := report(func(r *mechanics.Report) {
		r.ScannedAt = mechanics.NewCanonicalTime(time.Date(2026, 9, 24, 12, 0, 0, 123456789, time.UTC))
		r.Evidence[0].RetrievedAt = mechanics.NewCanonicalTime(time.Date(2016, 12, 31, 23, 59, 59, 999999999, time.UTC))
	})

	params, err := attest.FromReport(rep)
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}

	pre := params.Preimage
	for _, fragment := range []string{
		"scanned", "scanned_at", "retrieved", "retrieved_at",
		"2026-09-24", "2016-12-31", "12:00:00", "23:59:59", "123456789", "Z\n",
	} {
		if strings.Contains(pre, fragment) {
			t.Errorf("preimage contains timestamp fragment %q — timestamps must be excluded:\n%s", fragment, pre)
		}
	}

	// The documented format table, verbatim: a timestamp field added to the
	// encoding shows up here as a record that should not exist.
	for _, got := range strings.Split(pre, "\n") {
		if got == "" {
			continue
		}
		key := strings.SplitN(got, "\t", 2)[0]
		switch key {
		case "assay-evidence-v1", "asset", "severity", "base_severity",
			"escalated", "mechanics", "accountability", "checks", "evidence":
		default:
			t.Errorf("preimage record key %q is not in the documented format table", key)
		}
	}

	// And the hash is invariant under an arbitrary shift of every clock field.
	shifted := *rep
	shifted.ScannedAt = mechanics.NewCanonicalTime(rep.ScannedAt.Time().Add(100 * 24 * time.Hour))
	shifted.Evidence = append([]mechanics.Evidence(nil), rep.Evidence...)
	shifted.Evidence[0].RetrievedAt = mechanics.NewCanonicalTime(rep.Evidence[0].RetrievedAt.Time().Add(-100 * 24 * time.Hour))
	after, err := attest.FromReport(&shifted)
	if err != nil {
		t.Fatalf("FromReport (shifted): %v", err)
	}
	if params.EvidenceHash != after.EvidenceHash {
		t.Fatalf("retrieval time changed the hash: %s != %s", params.EvidenceHash, after.EvidenceHash)
	}
}

// TestPreimageBytesInvariantUnderTimestampShift is the precision probe: the
// nanosecond field of ScannedAt must be as invisible to the preimage as the
// date is, because FromReport renders ScannedAt at whole-second precision for
// Params — a consumer must never be able to recover sub-second scan timing
// from anything the attestation path exposes.
func TestPreimageBytesInvariantUnderTimestampShift(t *testing.T) {
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

	params0, err := attest.FromReport(report(func(r *mechanics.Report) { r.ScannedAt = mechanics.NewCanonicalTime(base) }))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}

	// +1 nanosecond, +1 second, +1 day: three instants, one byte sequence.
	for name, d := range map[string]time.Duration{
		"nanosecond": time.Nanosecond,
		"second":     time.Second,
		"day":        24 * time.Hour,
	} {
		paramsN, err := attest.FromReport(report(func(r *mechanics.Report) {
			r.ScannedAt = mechanics.NewCanonicalTime(base.Add(d))
		}))
		if err != nil {
			t.Fatalf("FromReport (+%s): %v", name, err)
		}
		if paramsN.Preimage != params0.Preimage {
			t.Errorf("+%s shift changed the preimage bytes; the clock must not be hashed", name)
		}
		if paramsN.EvidenceHash != params0.EvidenceHash {
			t.Errorf("+%s shift changed the evidence_hash; the clock must not be hashed", name)
		}
	}
}

// TestPreimageTimeHashesClaimsNotTheClock pins the discriminating property the
// documentation promises: what is hashed is exactly the claims. Two reports
// whose only difference is the clock are identical to the hash; two reports
// differing only in a claim are not.
func TestPreimageTimeHashesClaimsNotTheClock(t *testing.T) {
	a, err := attest.FromReport(report(nil))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	b, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.ScannedAt = mechanics.NewCanonicalTime(r.ScannedAt.Time().Add(72 * time.Hour))
		r.Evidence[0].RetrievedAt = mechanics.NewCanonicalTime(r.Evidence[0].RetrievedAt.Time().Add(72 * time.Hour))
	}))
	if err != nil {
		t.Fatalf("FromReport (shifted): %v", err)
	}
	if a.EvidenceHash != b.EvidenceHash {
		t.Fatalf("clock-only difference moved the hash: %s != %s", a.EvidenceHash, b.EvidenceHash)
	}

	c, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Evidence[0].Claim = "issuer flags: auth_required=true"
	}))
	if err != nil {
		t.Fatalf("FromReport (different claim): %v", err)
	}
	if c.EvidenceHash == a.EvidenceHash {
		t.Fatal("a changed claim did not move the hash; the preimage does not commit to claims")
	}
}
