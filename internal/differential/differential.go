// Package differential derives ledger facts a second way and compares them
// against what the scanner produced.
//
// Every other test in this repository compares Assay against itself. A bug in
// the fetch-and-parse path — taking the wrong record, misreading a flag —
// produces a consistent, self-agreeing, wrong answer that no self-comparison
// can catch. This package is the structural defence: the issuer's
// authorization flags are re-derived through a route that shares nothing with
// the scanner's — a different protocol (JSON-RPC against Soroban RPC rather
// than REST against Horizon), a different server, and a different data format
// (hand-decoded XDR ledger entries rather than encoding/json over Horizon's
// JSON) — and the two derivations are compared.
//
// The comparison states exactly four answers, per #48:
//
//   - Agreement: both derivations ran and produced the same flags.
//   - Disagreement: both ran and differ. Both values are reported; nothing
//     here picks a winner. Resolving in favour of either side would turn a
//     detected fault into an undetectable one.
//   - InconclusiveOneSide: exactly one derivation failed (transport error,
//     absent ledger entry, malformed payload). One honest answer plus one
//     absence is not agreement.
//   - InconclusiveBothSides: neither derivation produced an answer.
//
// Scope, deliberately narrow: this is not a second scanner. It re-derives the
// one fact every severity rests on — the issuer's authorization flags — and
// nothing else. Reputation is relayed by design and is out of scope, as is
// re-running the judgment layer. Which independent sources exist and what each
// actually proves is written up in docs/differential.md; Soroban RPC was
// implemented because it is the only candidate that is independent in
// protocol, server, and encoding at once, and it was validated live against
// Horizon for issuers with all-clear and revocable flags before a line of this
// package was written.
package differential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/horizon"
)

// DefaultURL is the SDF-operated Soroban RPC instance for testnet, the network
// Assay's attestations are written to. The SDF does not currently publish a
// stable public RPC hostname for pubnet, so a pubnet differential check must
// set BaseURL explicitly to an RPC endpoint the operator trusts.
const DefaultURL = "https://soroban-testnet.stellar.org"

// MaxBody caps an RPC response read, on the same principle as the other
// fetchers: a broken or hostile server must not be able to stream an
// unbounded body at the scanner. A single account ledger entry is a few
// hundred bytes of base64.
const MaxBody = 1 << 20

// Client derives issuer flags from Soroban RPC ledger entries.
//
// It is deliberately separate from internal/horizon: independence is the
// point. Sharing a client, a transport, or a parse path with the primary
// scan would make the comparison self-referential again.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
}

// New returns a Client for the given Soroban RPC URL, defaulting to the SDF
// testnet instance.
func New(baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultURL
	}
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
		UserAgent: "assay/" + horizon.Version +
			" (+https://github.com/use-assay/Assay)",
	}
}

// Sentinel errors. Callers distinguish them with errors.Is; a failed
// independent derivation never renders as agreement — Compare maps every one
// of them to an inconclusive state.
var (
	// ErrNotAccount reports an XDR payload whose LedgerEntryData discriminant
	// is not ACCOUNT. The RPC layer answered, but with a different entry kind,
	// which is a fault in the derivation, not a flag reading.
	ErrNotAccount = errors.New("differential: ledger entry is not an account entry")
	// ErrTruncated reports an XDR payload too short to carry the fields the
	// parser reads. It is not padded or salvaged: a short payload is a fault.
	ErrTruncated = errors.New("differential: account entry XDR is truncated")
	// ErrBadAccountID reports an account identifier that is not a valid
	// ed25519 strkey, so no ledger key can be built for it.
	ErrBadAccountID = errors.New("differential: invalid account ID")
	// ErrEntryAbsent reports that the RPC answered with no entry for the
	// requested key. For an issuer account this means the account does not
	// exist on this ledger — a fact, but not a flag reading.
	ErrEntryAbsent = errors.New("differential: no ledger entry for account")
	// ErrRPC reports a transport- or protocol-level failure talking to the
	// Soroban RPC endpoint.
	ErrRPC = errors.New("differential: soroban rpc")
)

// AccountFlags derives the issuer's authorization flags from the ledger entry
// for accountID, via getLedgerEntries over Soroban RPC.
//
// It returns an error wrapping one of the sentinel errors for every way the
// derivation can fail to produce a reading; callers must treat any error as
// "inconclusive", never as "no flags".
func (c *Client) AccountFlags(ctx context.Context, accountID string) (horizon.Flags, error) {
	key, err := LedgerKeyForAccount(accountID)
	if err != nil {
		return horizon.Flags{}, err
	}

	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getLedgerEntries",
		"params":  map[string]any{"keys": []string{key}},
	})
	if err != nil {
		return horizon.Flags{}, fmt.Errorf("%w: encode request: %w", ErrRPC, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL, strings.NewReader(string(payload)))
	if err != nil {
		return horizon.Flags{}, fmt.Errorf("%w: build request: %w", ErrRPC, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return horizon.Flags{}, fmt.Errorf("%w: post %s: %w", ErrRPC, c.BaseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return horizon.Flags{}, fmt.Errorf("%w: status %d", ErrRPC, resp.StatusCode)
	}

	var body struct {
		Result *struct {
			Entries []struct {
				Key string `json:"key"`
				XDR string `json:"xdr"`
			} `json:"entries"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, MaxBody))
	if err := dec.Decode(&body); err != nil {
		return horizon.Flags{}, fmt.Errorf("%w: decode response: %w", ErrRPC, err)
	}
	if body.Error != nil {
		return horizon.Flags{}, fmt.Errorf("%w: rpc error %d: %s", ErrRPC, body.Error.Code, body.Error.Message)
	}
	if body.Result == nil || len(body.Result.Entries) == 0 {
		return horizon.Flags{}, fmt.Errorf("%w: %s", ErrEntryAbsent, accountID)
	}
	for _, e := range body.Result.Entries {
		if e.Key != key {
			continue
		}
		raw, err := base64Decode(e.XDR)
		if err != nil {
			return horizon.Flags{}, fmt.Errorf("%w: decode entry xdr: %w", ErrRPC, err)
		}
		return ParseAccountFlags(raw)
	}
	return horizon.Flags{}, fmt.Errorf("%w: response did not echo the requested key", ErrRPC)
}
