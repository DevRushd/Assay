package mechanics_test

import (
	"context"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
)

// Fixture account IDs. These are valid Stellar ed25519 public-key shapes used
// only as test identifiers; they carry no real ledger state.
const (
	tlTestIssuer = "GA22QHSHQEHDJS2ZOINSC77XPPQ24G5EFRJGVEIZLKC5FAW3PQ5XNSDQ"
	tlTestHolder = "GBWXEAB6QPNZWDGR7JPBPIXQJYGYQOQ7QIUOTFJ5XT2Z6TB4T7SMYB6"
)

// tlSubject returns a Subject for a clawback-capable issuer with an optional
// holder trustline already loaded. It models the post-fetch state that
// scan.SubjectWithHolder would produce.
func tlSubject(holder string, tl *horizon.TrustlineBalance, tlErr string) *mechanics.Subject {
	return &mechanics.Subject{
		Asset: mechanics.Asset{Code: "TESTTKN", Issuer: tlTestIssuer},
		Stat: &horizon.AssetStat{
			AssetCode:   "TESTTKN",
			AssetIssuer: tlTestIssuer,
			Flags:       horizon.Flags{AuthClawbackEnabled: true, AuthRevocable: true},
		},
		Issuer: &horizon.Account{
			AccountID: tlTestIssuer,
			Flags:     horizon.Flags{AuthClawbackEnabled: true, AuthRevocable: true},
		},
		Holder:             holder,
		HolderTrustline:    tl,
		HolderTrustlineErr: tlErr,
		HolderAttemptedAt:  time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC),
		HolderFetchedAt:    time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC),
		ScannedAt:          time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC),
	}
}

func runTL(t *testing.T, s *mechanics.Subject) mechanics.Finding {
	t.Helper()
	f, err := mechanics.TrustlineCheck{}.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("TrustlineCheck.Run: %v", err)
	}
	return f
}

// TestTrustlineExposedHolder covers a holder who opened the trustline after the
// issuer enabled auth_clawback_enabled: is_clawback_enabled=true on the
// trustline, so the issuer can confiscate this holder's balance.
//
// Fixture shape: what Horizon's /accounts/{holder} balances array returns for an
// exposed trustline (verified against CAP-0035 and the Horizon accounts schema,
// https://developers.stellar.org/api/horizon/resources/accounts, 2026-09-24).
func TestTrustlineExposedHolder(t *testing.T) {
	tl := &horizon.TrustlineBalance{
		AssetCode: "TESTTKN", AssetIssuer: tlTestIssuer,
		IsAuthorized: true, IsClawbackEnabled: true,
	}
	f := runTL(t, tlSubject(tlTestHolder, tl, ""))

	if f.Undetermined {
		t.Fatal("exposed trustline must not be undetermined")
	}
	if f.Mechanics&mechanics.MechTrustlineClawbackEnabled == 0 {
		t.Error("MechTrustlineClawbackEnabled must be set for an exposed trustline")
	}
	if f.Mechanics&mechanics.MechTrustlineDeauthorized != 0 {
		t.Error("MechTrustlineDeauthorized must not be set for an authorized trustline")
	}
	// TrustlineCheck is informational: it must never set severity.
	if f.Severity != mechanics.Clear {
		t.Errorf("trustline check must not set severity; got %v", f.Severity)
	}
}

// TestTrustlineGrandfatheredHolder covers a holder who opened the trustline
// before the issuer enabled auth_clawback_enabled: is_clawback_enabled=false on
// the trustline, so the issuer CANNOT claw back this specific balance even
// though its account flag is currently set.
//
// Fixture shape: what Horizon returns for a grandfathered trustline.
func TestTrustlineGrandfatheredHolder(t *testing.T) {
	tl := &horizon.TrustlineBalance{
		AssetCode: "TESTTKN", AssetIssuer: tlTestIssuer,
		IsAuthorized: true, IsClawbackEnabled: false,
	}
	f := runTL(t, tlSubject(tlTestHolder, tl, ""))

	if f.Undetermined {
		t.Fatal("grandfathered trustline must not be undetermined")
	}
	if f.Mechanics&mechanics.MechTrustlineClawbackEnabled != 0 {
		t.Error("MechTrustlineClawbackEnabled must not be set for a grandfathered trustline")
	}
	if f.Severity != mechanics.Clear {
		t.Errorf("trustline check must not set severity; got %v", f.Severity)
	}
}

// TestTrustlineDeauthorized covers a trustline that is both clawback-exposed
// and deauthorized (the holder cannot transact).
func TestTrustlineDeauthorized(t *testing.T) {
	tl := &horizon.TrustlineBalance{
		AssetCode: "TESTTKN", AssetIssuer: tlTestIssuer,
		IsAuthorized: false, IsClawbackEnabled: true,
	}
	f := runTL(t, tlSubject(tlTestHolder, tl, ""))

	if f.Mechanics&mechanics.MechTrustlineDeauthorized == 0 {
		t.Error("MechTrustlineDeauthorized must be set for a deauthorized trustline")
	}
	if f.Mechanics&mechanics.MechTrustlineClawbackEnabled == 0 {
		t.Error("MechTrustlineClawbackEnabled must be set when is_clawback_enabled=true")
	}
}

// TestTrustlineHolderDoesNotHoldAsset: holder exists on the ledger but has no
// trustline for this asset (scan.SubjectWithHolder leaves HolderTrustline nil
// with no error when ErrNotFound is returned from the Horizon client).
func TestTrustlineHolderDoesNotHoldAsset(t *testing.T) {
	f := runTL(t, tlSubject(tlTestHolder, nil, ""))

	if !f.Undetermined {
		t.Fatal("absent trustline must be undetermined: the per-holder question cannot be answered")
	}
}

// TestTrustlineFetchError: Horizon was unreachable when fetching the holder's
// account. The finding must be undetermined with attributed evidence.
func TestTrustlineFetchError(t *testing.T) {
	f := runTL(t, tlSubject(tlTestHolder, nil, "horizon: get /accounts/...: status 429"))

	if !f.Undetermined {
		t.Fatal("a fetch error must mark the finding undetermined")
	}
	if len(f.Evidence) == 0 {
		t.Fatal("fetch error must be recorded as attributed evidence so it is auditable")
	}
	if f.Evidence[0].Claim == "" {
		t.Error("evidence claim must not be empty")
	}
}

// TestTrustlineNoHolderSkips: when no holder was requested, TrustlineCheck
// produces a clear, undetermined=false finding so it can be added to an engine
// without changing behavior when no holder is given.
func TestTrustlineNoHolderSkips(t *testing.T) {
	f := runTL(t, tlSubject("", nil, ""))

	if f.Undetermined {
		t.Fatal("no-holder path must not be undetermined: the question was not asked")
	}
	if f.Mechanics != 0 {
		t.Error("no-holder path must set no mechanic bits")
	}
	if f.Severity != mechanics.Clear {
		t.Errorf("no-holder path must not set severity; got %v", f.Severity)
	}
}

// TestTrustlineDoesNotAffectReportSeverity verifies the architectural decision
// documented in TrustlineCheck: trustline findings are informational and must
// never move the report's severity.
func TestTrustlineDoesNotAffectReportSeverity(t *testing.T) {
	tl := &horizon.TrustlineBalance{
		AssetCode: "TESTTKN", AssetIssuer: tlTestIssuer,
		IsAuthorized: true, IsClawbackEnabled: true,
	}
	s := tlSubject(tlTestHolder, tl, "")
	eng := &mechanics.Engine{Checks: []mechanics.Check{mechanics.TrustlineCheck{}}}
	rep, err := eng.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if rep.Severity != mechanics.Clear {
		t.Errorf("trustline finding must not move report severity; got %v", rep.Severity)
	}
	if rep.Base != mechanics.Clear {
		t.Errorf("trustline finding must not move base severity; got %v", rep.Base)
	}
}
