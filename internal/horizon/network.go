package horizon

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Network is a Stellar network passphrase.
type Network string

const (
	// PublicNet is the Stellar pubnet passphrase.
	PublicNet Network = "Public Global Stellar Network ; September 2015"
	// TestNet is the Stellar testnet passphrase.
	TestNet Network = "Test SDF Network ; September 2015"
)

// ErrUnknownNetwork reports a Horizon URL whose network cannot be established.
var ErrUnknownNetwork = errors.New("horizon: unknown network")

// NetworkFor identifies the network served by a known Horizon host.
func NetworkFor(rawURL string) (Network, error) {
	u, err := url.Parse(rawURL)
	if err == nil {
		switch strings.TrimSuffix(strings.ToLower(u.Hostname()), ".") {
		case "horizon.stellar.org":
			return PublicNet, nil
		case "horizon-testnet.stellar.org":
			return TestNet, nil
		}
	}
	return "", fmt.Errorf("%w: cannot determine network for %q", ErrUnknownNetwork, rawURL)
}

// Network identifies the network served by this client's configured URL.
func (c *Client) Network() (Network, error) {
	return NetworkFor(c.BaseURL)
}
