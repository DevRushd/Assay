package differential

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/horizon"
)

// TestLiveDifferentialAgainstPubnet is skipped in CI unless ASSAY_LIVE_DIFF=1.
// It runs the real derivation against the real RPC endpoint and compares with
// Horizon's answer for the AQUA issuer — the only test in the repo that
// compares two genuinely independent live derivations.
func TestLiveDifferentialAgainstPubnet(t *testing.T) {
	if os.Getenv("ASSAY_LIVE_DIFF") != "1" {
		t.Skip("live differential check disabled; set ASSAY_LIVE_DIFF=1 to run")
	}
	c := New("https://rpc.ankr.com/stellar_soroban")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sec, secErr := c.AccountFlags(ctx, clearIssuerStrKey)

	// Horizon side: the primary reading, fetched live through the scanner's
	// own client (separate transport, same fact).
	h := horizon.New("")
	acct, acctErr := h.Account(ctx, clearIssuerStrKey)
	if acctErr != nil {
		t.Fatalf("horizon: %v", acctErr)
	}
	if secErr != nil {
		t.Fatalf("soroban rpc: %v", secErr)
	}
	if acct.Flags != sec {
		b, _ := json.Marshal(map[string]any{"horizon": acct.Flags, "rpc": sec})
		t.Fatalf("live derivations disagree: %s", b)
	}

	// Second live subject, exercising the inflationDest branch of the parser:
	// the ARST issuer whose Horizon record carries auth_revocable.
	sec2, secErr2 := c.AccountFlags(ctx, revocIssuerStrKey)
	acct2, acctErr2 := h.Account(ctx, revocIssuerStrKey)
	if acctErr2 != nil || secErr2 != nil {
		t.Fatalf("live second subject: horizon=%v rpc=%v", acctErr2, secErr2)
	}
	if acct2.Flags != sec2 {
		b, _ := json.Marshal(map[string]any{"horizon": acct2.Flags, "rpc": sec2})
		t.Fatalf("live derivations disagree (revocable issuer): %s", b)
	}
	if !acct2.Flags.AuthRevocable {
		t.Fatalf("fixture drift: the revocable issuer now reads %+v; update the live-verified fixtures", acct2.Flags)
	}
	_ = http.StatusOK
}
