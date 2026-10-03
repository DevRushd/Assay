package differential

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/horizon"
)

// stubPrimary is a PrimaryProvider with a fixed reading or error — the seam
// that lets a test plant a deliberately wrong primary value.
type stubPrimary struct {
	flags horizon.Flags
	err   error
}

func (s stubPrimary) IssuerFlags(_ context.Context, _ string) (horizon.Flags, error) {
	return s.flags, s.err
}

// entryFor builds the base64 XDR a stand-in RPC will serve for issuer.
func entryFor(t *testing.T, issuer string, infl *[32]byte, flags uint32) (string, string) {
	t.Helper()
	key, err := LedgerKeyForAccount(issuer)
	if err != nil {
		t.Fatalf("build ledger key for %s: %v", issuer, err)
	}
	var k [32]byte
	raw, err := decodeStrKey(issuer)
	if err != nil {
		t.Fatalf("decode strkey: %v", err)
	}
	copy(k[:], raw)
	return key, base64.StdEncoding.EncodeToString(buildAccountEntryXDR(k, 1, 1, infl, flags, "example.test"))
}

const (
	primaryIssuer = clearIssuerStrKey // live-verified clear issuer
	secondaryIss2 = revocIssuerStrKey // live-verified revocable issuer
)

func TestCompareAgreement(t *testing.T) {
	key, xdr := entryFor(t, primaryIssuer, nil, 0)
	rs := newRPCServer(t, map[string]string{key: xdr})
	res := Compare(context.Background(), "AQUA", primaryIssuer,
		stubPrimary{flags: horizon.Flags{}}, New(rs.srv.URL))

	if res.State != StateAgreement {
		t.Fatalf("state = %q (%s), want agreement", res.State, res.Reason)
	}
	if res.Primary == nil || res.Secondary == nil {
		t.Fatal("both readings must be reported on agreement")
	}
	if res.PrimaryErr != "" || res.SecondaryErr != "" {
		t.Fatalf("no error may be set on agreement: %q / %q", res.PrimaryErr, res.SecondaryErr)
	}
}

func TestCompareDisagreementIsSurfacedNotResolved(t *testing.T) {
	key, xdr := entryFor(t, primaryIssuer, nil, 0x2) // ledger says revocable
	rs := newRPCServer(t, map[string]string{key: xdr})
	primary := horizon.Flags{} // scanner says clear — the bug being simulated
	res := Compare(context.Background(), "AQUA", primaryIssuer,
		stubPrimary{flags: primary}, New(rs.srv.URL))

	if res.State != StateDisagreement {
		t.Fatalf("state = %q (%s), want disagreement", res.State, res.Reason)
	}
	// The result must carry both values. A verifier has to be able to see
	// what each side said; collapsing to one reading would hide the fault.
	if res.Primary == nil || res.Secondary == nil {
		t.Fatal("disagreement must report both readings")
	}
	if res.Primary.AuthRevocable || !res.Secondary.AuthRevocable {
		t.Fatalf("both values not carried faithfully: primary %+v secondary %+v", *res.Primary, *res.Secondary)
	}
}

func TestCompareWrongPrimaryIsCaught(t *testing.T) {
	// The acceptance test from #48: a deliberately wrong primary value is
	// caught. The scanner's fetch-and-parse path misread the flags; the
	// independent derivation disagrees and the result names it.
	key, xdr := entryFor(t, primaryIssuer, nil, 0) // ledger truth: clear
	rs := newRPCServer(t, map[string]string{key: xdr})
	wrong := horizon.Flags{AuthClawbackEnabled: true} // the bug: clawback invented
	res := Compare(context.Background(), "AQUA", primaryIssuer,
		stubPrimary{flags: wrong}, New(rs.srv.URL))

	if res.State != StateDisagreement {
		t.Fatalf("a wrong primary produced state %q; the differential check did not catch the injected fault", res.State)
	}
	if !res.Primary.AuthClawbackEnabled || res.Secondary.AuthClawbackEnabled {
		t.Fatalf("result does not preserve both sides: primary %+v secondary %+v", *res.Primary, *res.Secondary)
	}
}

func TestCompareSecondaryUnavailableIsInconclusive(t *testing.T) {
	// The independent source is down: an HTTP-level failure. This must not
	// render as agreement, however complete the primary looked.
	rs := newRPCServer(t, map[string]string{})
	rs.status = 503
	res := Compare(context.Background(), "AQUA", primaryIssuer,
		stubPrimary{flags: horizon.Flags{}}, New(rs.srv.URL))

	if res.State != StateInconclusiveOneSide {
		t.Fatalf("state = %q, want inconclusive_one_side when the independent source is down", res.State)
	}
	if res.SecondaryErr == "" {
		t.Fatal("the secondary error must be carried verbatim")
	}
	if res.Primary == nil {
		t.Fatal("the primary reading is still honest and must be reported")
	}
	if !strings.Contains(res.Reason, "not agreement") {
		t.Fatalf("reason must say the result is not agreement: %q", res.Reason)
	}
}

func TestComparePrimaryUnavailableIsInconclusive(t *testing.T) {
	key, xdr := entryFor(t, primaryIssuer, nil, 0)
	rs := newRPCServer(t, map[string]string{key: xdr})
	res := Compare(context.Background(), "AQUA", primaryIssuer,
		stubPrimary{err: ErrNoPrimaryReading}, New(rs.srv.URL))

	if res.State != StateInconclusiveOneSide {
		t.Fatalf("state = %q, want inconclusive_one_side when the primary has no reading", res.State)
	}
	if res.PrimaryErr == "" || res.Secondary == nil {
		t.Fatal("the failed side's error and the honest side's reading must both be reported")
	}
}

func TestCompareBothUnavailableIsInconclusive(t *testing.T) {
	rs := newRPCServer(t, map[string]string{})
	rs.status = 503
	res := Compare(context.Background(), "AQUA", primaryIssuer,
		stubPrimary{err: ErrNoPrimaryReading}, New(rs.srv.URL))

	if res.State != StateInconclusiveBothSides {
		t.Fatalf("state = %q, want inconclusive_both_sides", res.State)
	}
	if res.PrimaryErr == "" || res.SecondaryErr == "" {
		t.Fatal("both errors must be carried")
	}
	if res.Primary != nil || res.Secondary != nil {
		t.Fatal("no reading exists; none may be reported")
	}
}

func TestCompareEntryAbsentIsInconclusiveNotAgreement(t *testing.T) {
	// An issuer with no ledger entry is a fact about the ledger, but it is
	// not a flag reading, and an empty flags struct must never leak out of
	// the secondary side to become a phantom "agrees" result.
	rs := newRPCServer(t, map[string]string{})
	rs.missing = true
	res := Compare(context.Background(), "AQUA", primaryIssuer,
		stubPrimary{flags: horizon.Flags{}}, New(rs.srv.URL))

	if res.State != StateInconclusiveOneSide {
		t.Fatalf("state = %q, want inconclusive_one_side; an absent entry is not a flag reading", res.State)
	}
	if res.SecondaryErr == "" {
		t.Fatal("the absent-entry error must be carried verbatim")
	}
}
