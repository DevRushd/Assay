package scan_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/scan"
)

// networkFixture stands up a Horizon stand-in plus the other sources a scan
// touches, and wires a scanner at the requested Horizon URL with the requested
// declared network. Reuses fakeSources so the source behaviour stays in one
// place; the network under test is the Horizon base URL and the declaration.
func networkFixture(t *testing.T, horizonURL string, declared horizon.Network) *scan.Scanner {
	t.Helper()
	fs := newFakeSources(t)
	if horizonURL == "" {
		horizonURL = fs.horizon.URL
	}
	sc := scan.New()
	sc.Horizon.BaseURL = horizonURL
	sc.Expert.BaseURL = fs.expert.URL
	sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(fs.toml.URL, "http://")}
	sc.Network = declared
	return sc
}

// resolveNetwork decides, before any I/O, whether the scan can honestly name
// the ledger it is about to read. These are the acceptance criteria from #41:
// a known host binds its network, an explicit declaration is cross-checked,
// and a custom URL whose network cannot be determined is an error — not a
// default.
func TestSubjectBindsTheNetwork(t *testing.T) {
	t.Run("declared pubnet is bound onto the subject", func(t *testing.T) {
		// The fixture's Horizon is an httptest server whose 127.0.0.1 URL is
		// not a known host, so this is the private-Horizon case: the caller's
		// pubnet declaration is the authority and the scan proceeds.
		sc := networkFixture(t, "", horizon.PublicNet)
		sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
		if err != nil {
			t.Fatalf("Subject: %v", err)
		}
		if sub.Network != horizon.PublicNet {
			t.Fatalf("subject network = %q, want the pubnet passphrase", sub.Network)
		}
	})

	t.Run("explicit declaration is honoured on an unknown host", func(t *testing.T) {
		sc := networkFixture(t, "", horizon.TestNet)
		sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
		if err != nil {
			t.Fatalf("Subject: %v", err)
		}
		if sub.Network != horizon.TestNet {
			t.Fatalf("subject network = %q, want the declared testnet passphrase", sub.Network)
		}
	})

	t.Run("custom URL with no declaration is an error, not a default", func(t *testing.T) {
		sc := networkFixture(t, "https://horizon.internal.example", "")
		_, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
		if err == nil {
			t.Fatal("an undeterminable network scanned without error; the report would not know which ledger it describes")
		}
		if !errors.Is(err, horizon.ErrUnknownNetwork) {
			t.Fatalf("error = %v, want ErrUnknownNetwork", err)
		}
		if !strings.Contains(err.Error(), "horizon.internal.example") {
			t.Fatalf("error does not name the unresolved host: %v", err)
		}
	})

	t.Run("declaration contradicting the host is an error", func(t *testing.T) {
		// A misconfigured testnet attester pointed at pubnet Horizon must fail
		// loudly: writing those attestations to testnet would publish pubnet
		// facts under a testnet contract, exactly the cross-network confusion
		// #41 exists to prevent. The contradiction is checked before the first
		// fetch, so the real pubnet host is never contacted.
		sc := networkFixture(t, "https://horizon.stellar.org", horizon.TestNet)
		_, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
		if err == nil {
			t.Fatal("a scan declaring testnet against pubnet Horizon ran without error")
		}
		if errors.Is(err, horizon.ErrNotFound) {
			t.Fatalf("the contradiction was not caught before the fetch ran: %v", err)
		}
		if !strings.Contains(err.Error(), "declared") || !strings.Contains(err.Error(), "serves") {
			t.Fatalf("error does not name the contradiction: %v", err)
		}
	})

	t.Run("an undeterminable URL is refused before any network I/O", func(t *testing.T) {
		// The URL has no listener at all, so a fetch would fail with a dial
		// error. The failure must instead be the network refusal, proving
		// resolution precedes the first fetch — a report produced by an
		// undeterminable scan would carry no honest network name, so it must
		// never be produced at all.
		sc := networkFixture(t, "https://127.0.0.1:1", "")
		_, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
		if err == nil {
			t.Fatal("expected the network refusal")
		}
		if !errors.Is(err, horizon.ErrUnknownNetwork) {
			t.Fatalf("error = %v, want ErrUnknownNetwork before any dial", err)
		}
	})
}

// The network is a scan-level fact that must survive into the report, because
// attest.FromReport binds it from there.
func TestReportCarriesTheNetwork(t *testing.T) {
	sc := networkFixture(t, "", horizon.PublicNet)
	rep, err := sc.Scan(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Network != horizon.PublicNet {
		t.Fatalf("report network = %q, want the pubnet passphrase", rep.Network)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("sanity: the scan produced no findings")
	}
}

// A fresh production scanner declares pubnet, matching the pubnet Horizon it
// is wired to — the configuration docs/deployment.md records as the live
// attestation pipeline.
func TestNewDeclaresPubnet(t *testing.T) {
	sc := scan.New()
	if sc.Network != horizon.PublicNet {
		t.Fatalf("scan.New().Network = %q, want the pubnet passphrase", sc.Network)
	}
}
