package horizon_test

import (
	"errors"
	"testing"

	"github.com/use-assay/assay/internal/horizon"
)

// NetworkFor is what stands between a misconfigured Horizon and a false
// attestation: the same CODE-ISSUER can exist on two networks with different
// flags (#41), so the network name that enters the evidence preimage must be
// derived only from hosts whose identity is certain, and everything else must
// fail rather than guess.
func TestNetworkFor(t *testing.T) {
	t.Run("known hosts", func(t *testing.T) {
		for _, tc := range []struct {
			url  string
			want horizon.Network
		}{
			{"https://horizon.stellar.org", horizon.PublicNet},
			{"https://horizon.stellar.org/", horizon.PublicNet},
			{"http://horizon.stellar.org", horizon.PublicNet},
			{"https://horizon-testnet.stellar.org", horizon.TestNet},
			{"https://horizon-testnet.stellar.org:443", horizon.TestNet},
		} {
			got, err := horizon.NetworkFor(tc.url)
			if err != nil {
				t.Errorf("NetworkFor(%q): %v", tc.url, err)
				continue
			}
			if got != tc.want {
				t.Errorf("NetworkFor(%q) = %q, want %q", tc.url, got, tc.want)
			}
		}
	})

	t.Run("unknown hosts are refused, not defaulted", func(t *testing.T) {
		for _, url := range []string{
			"https://horizon.example.com",
			"https://api.stellar.example",
			"https://localhost:8000",
			"http://127.0.0.1:8000",
			"", // no base URL at all
			// A subdomain lookalike is exactly the shape a misconfiguration or
			// an interception would produce; it must not resolve to either
			// known network.
			"https://horizon.stellar.org.evil.test",
			"https://horizon-testnet.stellar.org.example.com",
		} {
			got, err := horizon.NetworkFor(url)
			if err == nil {
				t.Errorf("NetworkFor(%q) = %q; an undeterminable network must error, not default", url, got)
				continue
			}
			if !errors.Is(err, horizon.ErrUnknownNetwork) {
				t.Errorf("NetworkFor(%q) error = %v, want ErrUnknownNetwork", url, err)
			}
		}
	})

	t.Run("the default client is pubnet", func(t *testing.T) {
		got, err := horizon.New("").Network()
		if err != nil {
			t.Fatalf("Network(): %v", err)
		}
		if got != horizon.PublicNet {
			t.Fatalf("the default Horizon client reads %q, want pubnet", got)
		}
	})
}

// The passphrases are fixed by the protocol and named in the issue; a typo
// here would bind attestations to a network that does not exist.
func TestNetworkPassphraseValues(t *testing.T) {
	if string(horizon.PublicNet) != "Public Global Stellar Network ; September 2015" {
		t.Fatalf("pubnet passphrase = %q", horizon.PublicNet)
	}
	if string(horizon.TestNet) != "Test SDF Network ; September 2015" {
		t.Fatalf("testnet passphrase = %q", horizon.TestNet)
	}
}
