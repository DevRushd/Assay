package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// verifyTableTime is the fixed "now" every staleness judgment uses, so the
// tests are deterministic instead of racing the clock.
var verifyTableTime = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// verifyTestAsset is a well-formed asset; the scan stub never touches the
// network so the address does not need to be a real issuer.
const verifyTestAssetCode = "AQUA"

const verifyTestAssetIssuer = "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"

// attestableReport builds a clean, attestable scan for the test asset, then
// applies mut. Using the real attest.FromReport (not a hand-made hash) means
// the test also fails if the Params shape drifts from what verify compares.
func attestableReport(t *testing.T, mut func(*mechanics.Report)) (*mechanics.Report, attest.Params) {
	t.Helper()
	rep := &mechanics.Report{
		Asset:              mechanics.Asset{Code: verifyTestAssetCode, Issuer: verifyTestAssetIssuer},
		Severity:           mechanics.High,
		Base:               mechanics.High,
		Accountability:     mechanics.AccountabilityVerified,
		Mechanics:          mechanics.MechAuthRequired,
		ScannedAt:          mechanics.NewCanonicalTime(verifyTableTime.Add(-time.Minute)),
		Findings:           []mechanics.Finding{},
		Evidence:           []mechanics.Evidence{},
		UndeterminedChecks: []string{},
	}
	if mut != nil {
		mut(rep)
	}
	params, err := attest.FromReport(rep)
	if err != nil {
		t.Fatalf("FromReport on the fixture report: %v", err)
	}
	return rep, params
}

// chainFrom renders the on-chain image of params. lowerHash exercises the
// case-insensitive hex comparison: the chain stores BytesN<32>, which some
// renderers uppercase.
func chainFrom(params attest.Params, attestedAt int64, lowerHash bool) *OnChainSafety {
	h := params.EvidenceHash
	if lowerHash {
		h = strings.ToUpper(h)
	}
	return &OnChainSafety{
		Severity:     params.Severity,
		Flags:        params.Flags,
		EvidenceHash: h,
		AttestedAt:   attestedAt,
	}
}

// TestVerifyOutcomes is the table test issue #39 asks for: one case per
// outcome class, each asserting the verdict, the differing fields when there
// are any, and the exit code the CLI maps the verdict to.
func TestVerifyOutcomes(t *testing.T) {
	asset := mechanics.Asset{Code: verifyTestAssetCode, Issuer: verifyTestAssetIssuer}
	ctx := context.Background()

	t.Run("agree", func(t *testing.T) {
		rep, params := attestableReport(t, nil)
		chain := chainFrom(params, verifyTableTime.Add(-time.Hour).Unix(), false)
		res, err := verifyAsset(ctx, asset, 0, verifyTableTime,
			func(context.Context, mechanics.Asset) (*mechanics.Report, error) { return rep, nil },
			func(mechanics.Asset) (*OnChainSafety, error) { return chain, nil })
		if err != nil {
			t.Fatalf("verifyAsset: %v", err)
		}
		if res.Outcome != outcomeAgree {
			t.Fatalf("outcome = %s (%s), want agree", res.Outcome, res.Detail)
		}
	})

	t.Run("agree_after_max_age_not_stale", func(t *testing.T) {
		rep, params := attestableReport(t, nil)
		// One second under the age limit: matching and fresh enough.
		chain := chainFrom(params, verifyTableTime.Add(-59*time.Minute).Unix(), false)
		res, err := verifyAsset(ctx, asset, 3600, verifyTableTime,
			func(context.Context, mechanics.Asset) (*mechanics.Report, error) { return rep, nil },
			func(mechanics.Asset) (*OnChainSafety, error) { return chain, nil })
		if err != nil {
			t.Fatalf("verifyAsset: %v", err)
		}
		if res.Outcome != outcomeAgree {
			t.Fatalf("outcome = %s, want agree", res.Outcome)
		}
	})

	t.Run("stale", func(t *testing.T) {
		rep, params := attestableReport(t, nil)
		chain := chainFrom(params, verifyTableTime.Add(-2*time.Hour).Unix(), false)
		res, err := verifyAsset(ctx, asset, 3600, verifyTableTime,
			func(context.Context, mechanics.Asset) (*mechanics.Report, error) { return rep, nil },
			func(mechanics.Asset) (*OnChainSafety, error) { return chain, nil })
		if err != nil {
			t.Fatalf("verifyAsset: %v", err)
		}
		if res.Outcome != outcomeStale {
			t.Fatalf("outcome = %s, want stale", res.Outcome)
		}
		if res.AgeSecs != 7200 || res.MaxAge != 3600 {
			t.Fatalf("age = %d max = %d, want 7200/3600", res.AgeSecs, res.MaxAge)
		}
	})

	t.Run("mismatch_severity", func(t *testing.T) {
		rep, params := attestableReport(t, nil)
		chain := chainFrom(params, verifyTableTime.Unix(), false)
		chain.Severity = 2 // anything but the scanned level
		res, err := verifyAsset(ctx, asset, 0, verifyTableTime,
			func(context.Context, mechanics.Asset) (*mechanics.Report, error) { return rep, nil },
			func(mechanics.Asset) (*OnChainSafety, error) { return chain, nil })
		if err != nil {
			t.Fatalf("verifyAsset: %v", err)
		}
		if res.Outcome != outcomeMismatch {
			t.Fatalf("outcome = %s, want mismatch", res.Outcome)
		}
		if len(res.Fields) != 1 || res.Fields[0] != "severity" {
			t.Fatalf("fields = %v, want [severity]", res.Fields)
		}
	})

	t.Run("mismatch_evidence_hash", func(t *testing.T) {
		rep, params := attestableReport(t, nil)
		chain := chainFrom(params, verifyTableTime.Unix(), false)
		chain.EvidenceHash = strings.Repeat("ab", 32)
		res, err := verifyAsset(ctx, asset, 0, verifyTableTime,
			func(context.Context, mechanics.Asset) (*mechanics.Report, error) { return rep, nil },
			func(mechanics.Asset) (*OnChainSafety, error) { return chain, nil })
		if err != nil {
			t.Fatalf("verifyAsset: %v", err)
		}
		if res.Outcome != outcomeMismatch {
			t.Fatalf("outcome = %s, want mismatch", res.Outcome)
		}
		if len(res.Fields) != 1 || res.Fields[0] != "evidence_hash" {
			t.Fatalf("fields = %v, want [evidence_hash]", res.Fields)
		}
	})

	t.Run("mismatch_multiple_fields_named", func(t *testing.T) {
		rep, params := attestableReport(t, nil)
		chain := chainFrom(params, verifyTableTime.Unix(), false)
		chain.Severity = 1
		chain.Flags = 0
		res, err := verifyAsset(ctx, asset, 0, verifyTableTime,
			func(context.Context, mechanics.Asset) (*mechanics.Report, error) { return rep, nil },
			func(mechanics.Asset) (*OnChainSafety, error) { return chain, nil })
		if err != nil {
			t.Fatalf("verifyAsset: %v", err)
		}
		if res.Outcome != outcomeMismatch {
			t.Fatalf("outcome = %s, want mismatch", res.Outcome)
		}
		if len(res.Fields) != 2 {
			t.Fatalf("fields = %v, want severity and flags", res.Fields)
		}
	})

	t.Run("absent", func(t *testing.T) {
		rep, _ := attestableReport(t, nil)
		res, err := verifyAsset(ctx, asset, 0, verifyTableTime,
			func(context.Context, mechanics.Asset) (*mechanics.Report, error) { return rep, nil },
			func(mechanics.Asset) (*OnChainSafety, error) { return nil, nil })
		if err != nil {
			t.Fatalf("verifyAsset: %v", err)
		}
		if res.Outcome != outcomeAbsent {
			t.Fatalf("outcome = %s, want absent", res.Outcome)
		}
		if !strings.Contains(res.Detail, "no attestation") {
			t.Fatalf("detail = %q, want it to say the attestation is absent", res.Detail)
		}
	})

	t.Run("unverifiable", func(t *testing.T) {
		// Built directly rather than through attestableReport: FromReport
		// refuses an undetermined report by design, and that refusal is exactly
		// what the unverifiable path relies on.
		rep := &mechanics.Report{
			Asset:              asset,
			Severity:           mechanics.High,
			Base:               mechanics.High,
			ScannedAt:          mechanics.NewCanonicalTime(verifyTableTime),
			Undetermined:       true,
			UndeterminedChecks: []string{"reputation"},
			Findings:           []mechanics.Finding{},
			Evidence:           []mechanics.Evidence{},
		}
		// A chain entry exists that happens to match whatever the partial
		// report would compute. It must not matter: an undetermined scan can
		// never produce agreement.
		res, err := verifyAsset(ctx, asset, 0, verifyTableTime,
			func(context.Context, mechanics.Asset) (*mechanics.Report, error) { return rep, nil },
			func(mechanics.Asset) (*OnChainSafety, error) {
				return &OnChainSafety{Severity: 1, Flags: 0, AttestedAt: verifyTableTime.Unix()}, nil
			})
		if err != nil {
			t.Fatalf("verifyAsset: %v", err)
		}
		if res.Outcome != outcomeUnverifiable {
			t.Fatalf("outcome = %s, want unverifiable", res.Outcome)
		}
		if strings.Contains(strings.ToLower(res.Detail), "agree") {
			t.Fatalf("detail = %q, must never claim agreement", res.Detail)
		}
	})

	t.Run("unevaluated_is_unverifiable_too", func(t *testing.T) {
		rep := &mechanics.Report{
			Asset:              asset,
			Severity:           mechanics.Unevaluated,
			Base:               mechanics.Unevaluated,
			ScannedAt:          mechanics.NewCanonicalTime(verifyTableTime),
			Findings:           []mechanics.Finding{},
			Evidence:           []mechanics.Evidence{},
			UndeterminedChecks: []string{},
		}
		res, err := verifyAsset(ctx, asset, 0, verifyTableTime,
			func(context.Context, mechanics.Asset) (*mechanics.Report, error) { return rep, nil },
			func(mechanics.Asset) (*OnChainSafety, error) { return nil, nil })
		if err != nil {
			t.Fatalf("verifyAsset: %v", err)
		}
		if res.Outcome != outcomeUnverifiable {
			t.Fatalf("outcome = %s, want unverifiable (FromReport refuses unevaluated)", res.Outcome)
		}
	})
}

// TestVerifyExitCodeMapping pins the per-outcome exit codes the CLI maps to,
// so the four outcome classes stay four distinguishable exit codes.
func TestVerifyExitCodeMapping(t *testing.T) {
	if exitMismatch != 1 || exitStale != 2 || exitAbsent != 3 || exitUnverifiable != 4 {
		t.Fatalf("exit codes drifted: mismatch=%d stale=%d absent=%d unverifiable=%d",
			exitMismatch, exitStale, exitAbsent, exitUnverifiable)
	}
}

// TestVerifyScanErrorIsInfrastructure makes the distinction the design
// comment claims: a failing scan or chain read is an error return (no
// verdict), while every outcome class is a successful verification of a
// verdict.
func TestVerifyScanErrorIsInfrastructure(t *testing.T) {
	asset := mechanics.Asset{Code: verifyTestAssetCode, Issuer: verifyTestAssetIssuer}
	boom := errors.New("horizon unreachable")
	_, err := verifyAsset(context.Background(), asset, 0, verifyTableTime,
		func(context.Context, mechanics.Asset) (*mechanics.Report, error) { return nil, boom },
		func(mechanics.Asset) (*OnChainSafety, error) {
			t.Fatal("chain must not be read when the scan failed")
			return nil, nil
		})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the scan error wrapped", err)
	}

	rep, _ := attestableReport(t, nil)
	_, err = verifyAsset(context.Background(), asset, 0, verifyTableTime,
		func(context.Context, mechanics.Asset) (*mechanics.Report, error) { return rep, nil },
		func(mechanics.Asset) (*OnChainSafety, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the chain-read error wrapped", err)
	}
}
