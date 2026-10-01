// Package horizon fetches asset and issuer-account state from Horizon.
//
// This package is deliberately small and dependency-free: it is one of the
// fetchers earmarked for extraction into a shared ledger-access library once
// a second project needs it. Keep the signatures clean and the types local.
package horizon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// DefaultURL is the public Horizon instance for pubnet.
const DefaultURL = "https://horizon.stellar.org"

// ErrNotFound reports that Horizon has no record of the asset or account.
var ErrNotFound = errors.New("horizon: not found")

// ErrMultipleRecords reports that Horizon returned more than one record for an
// exact code+issuer query. In Stellar, an asset is uniquely identified by
// (code, issuer); returning multiple records violates that uniqueness rule.
// Choosing one would be an arbitrary guess, so Assay refuses rather than guesses.
var ErrMultipleRecords = errors.New("horizon: multiple records returned for asset")

// Version is the tool version that every outbound client reports in its
// User-Agent. Bump it alongside any scanner-version release; the API
// documents the value in release notes.
const Version = "v0.1.0"

// defaultUserAgent is how Assay identifies itself to the public Horizon
// instance. It is a courtesy to the operators of sources Assay depends on
// and makes automated traffic distinguishable from botnets and scanners.
const defaultUserAgent = "assay/" + Version + " (+https://github.com/use-assay/Assay)"

// Flags mirrors the issuer authorization flags exactly as Horizon names them.
//
// The field names are the wire names, verified against live Horizon responses
// for both /assets and /accounts. Do not rename them to something tidier: the
// whole point of this scanner is that it reports the ledger's own vocabulary.
type Flags struct {
	AuthRequired        bool `json:"auth_required"`
	AuthRevocable       bool `json:"auth_revocable"`
	AuthImmutable       bool `json:"auth_immutable"`
	AuthClawbackEnabled bool `json:"auth_clawback_enabled"`
}

// AssetStat is the subset of Horizon's /assets record that Assay reasons about.
type AssetStat struct {
	AssetType   string `json:"asset_type"`
	AssetCode   string `json:"asset_code"`
	AssetIssuer string `json:"asset_issuer"`
	ContractID  string `json:"contract_id"`
	Flags       Flags  `json:"flags"`
	Accounts    struct {
		Authorized   int `json:"authorized"`
		Unauthorized int `json:"unauthorized"`
	} `json:"accounts"`
	Links struct {
		Toml struct {
			Href string `json:"href"`
		} `json:"toml"`
	} `json:"_links"`
}

// Account is the subset of Horizon's /accounts record that Assay reasons about.
type Account struct {
	AccountID  string `json:"account_id"`
	HomeDomain string `json:"home_domain"`
	Flags      Flags  `json:"flags"`
}

// TrustlineBalance is a single credit-trustline entry from the balances array
// of Horizon's /accounts/{id} response.
//
// Field names are the Horizon wire names verified against
// https://developers.stellar.org/api/horizon/resources/accounts (2026-09-24)
// and the CAP-0035 specification. Do not rename them.
type TrustlineBalance struct {
	AssetType   string `json:"asset_type"`
	AssetCode   string `json:"asset_code"`
	AssetIssuer string `json:"asset_issuer"`
	// IsAuthorized reports whether the issuer has authorized this trustline
	// to transact (send and receive). An unauthorized trustline is frozen.
	IsAuthorized bool `json:"is_authorized"`
	// IsClawbackEnabled reports whether the issuer's clawback power applies
	// to this specific trustline. Under CAP-0035 this flag is fixed when the
	// trustline is created: a holder who opened before the issuer set
	// auth_clawback_enabled is not exposed even if the issuer's account flag
	// is currently set. SetTrustLineFlagsOp cannot add it retroactively.
	IsClawbackEnabled bool `json:"is_clawback_enabled"`
}

// Client reads from a Horizon instance.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
}

// New returns a Client for the given Horizon base URL, defaulting to pubnet.
func New(baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultURL
	}
	return &Client{
		BaseURL:   baseURL,
		HTTP:      &http.Client{Timeout: 15 * time.Second},
		UserAgent: defaultUserAgent,
	}
}

// Asset returns the asset statistics record for code/issuer.
//
// If the ledger echoes a different code or issuer than the caller asked for,
// the mismatch is fatal: every severity Assay reports comes from this record's
// flags, and a record describing another asset put under this name fakes both.
func (c *Client) Asset(ctx context.Context, code, issuer string) (*AssetStat, error) {
	q := url.Values{}
	q.Set("asset_code", code)
	q.Set("asset_issuer", issuer)

	var page struct {
		Embedded struct {
			Records []AssetStat `json:"records"`
		} `json:"_embedded"`
	}
	if err := c.get(ctx, "/assets?"+q.Encode(), &page); err != nil {
		return nil, err
	}
	if len(page.Embedded.Records) == 0 {
		return nil, fmt.Errorf("%w: asset %s-%s", ErrNotFound, code, issuer)
	}
	if len(page.Embedded.Records) > 1 {
		return nil, fmt.Errorf(
			"%w: asset %s-%s returned %d records; expected exactly one",
			ErrMultipleRecords, code, issuer, len(page.Embedded.Records),
		)
	}
	rec := page.Embedded.Records[0]
	if rec.AssetCode != code || rec.AssetIssuer != issuer {
		return nil, fmt.Errorf(
			"horizon: asset %s-%s echoed %s-%s",
			code, issuer, rec.AssetCode, rec.AssetIssuer,
		)
	}
	return &rec, nil
}

// Account returns the account record for the given account ID.
//
// The record Horizon echoes carries the very ID it serves, so asking for one
// account cannot be answered by another. A mismatch is fatal, because every
// flag Assay reads on that account is built into the scan.
func (c *Client) Account(ctx context.Context, id string) (*Account, error) {
	var a Account
	if err := c.get(ctx, "/accounts/"+url.PathEscape(id), &a); err != nil {
		return nil, err
	}
	if a.AccountID != id {
		return nil, fmt.Errorf(
			"horizon: account %s echoed %s", id, a.AccountID,
		)
	}
	return &a, nil
}

// Trustline returns the balance entry for code/issuer in the holder's account.
// It returns ErrNotFound if the holder does not hold the asset.
func (c *Client) Trustline(ctx context.Context, holder, code, issuer string) (*TrustlineBalance, error) {
	var a struct {
		Balances []TrustlineBalance `json:"balances"`
	}
	if err := c.get(ctx, "/accounts/"+url.PathEscape(holder), &a); err != nil {
		return nil, err
	}
	for i, b := range a.Balances {
		if b.AssetCode == code && b.AssetIssuer == issuer {
			return &a.Balances[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %s does not hold %s-%s", ErrNotFound, holder, code, issuer)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("horizon: get %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("horizon: get %s: status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("horizon: decode %s: %w", path, err)
	}
	return nil
}
