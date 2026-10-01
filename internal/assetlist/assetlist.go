// Package assetlist consumes SEP-0042 Stellar Asset Lists (SALs) as curation
// sources alongside StellarExpert.
//
// A SAL is a standardised, publisher-agnostic list of curated asset metadata:
// any organisation can publish one and advertise it from its SEP-1
// stellar.toml, so support here is per-format rather than per-vendor. Assay
// does not curate lists, does not judge them, and does not merge them.
// Everything this package returns is decoded, attributed to the list that
// published it, and passed through.
//
// Two properties of the format drive the rest of the design, and both are
// quoted from the spec (SEP-0042, Status Draft, Version 0.2.1,
// https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0042.md,
// retrieved 2026-09-27):
//
//   - "Inclusion of any particular asset in a list should not be considered as
//     endorsement or recommendation of any kind." Presence on a list is
//     therefore not a safety signal and must never lower a severity.
//   - "application developer should either depend only on several trustworthy
//     providers or utilize the community-maintained repository of curated
//     asset lists." One list is one provider's view; lists are kept separate
//     so a consumer can see which provider said what.
//
// Field names were verified against a real published list before being encoded
// here; see testdata/PROVENANCE.md.
package assetlist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MaxBody caps a list response.
//
// The SEP-0042 JSON schema allows at most 1000 assets per list, so a 4 MiB cap
// comfortably covers any conforming list while still stopping a broken or
// hostile server from streaming an unbounded body at the scanner. The decode
// reads at most this many bytes, so an oversized document is truncated and then
// fails to decode rather than allocating without bound. It is exported so the
// resource-exhaustion test can assert the bound rather than assume it.
const MaxBody = 4 << 20

// version is kept here so every outbound client reports the same tool version
// in its User-Agent.
const version = "v0.1.0"

// defaultUserAgent is how Assay identifies itself when fetching a published
// list. It is a courtesy to the operators of sources Assay depends on, and
// matches the identity the other clients present.
const defaultUserAgent = "assay/" + version + " (+https://github.com/use-assay/Assay)"

// Asset is one entry of a list's "assets" array.
//
// The JSON names are the SEP-0042 schema's, verified against the published
// StellarExpert Top 50 list: code, issuer, contract, name, org, domain, icon,
// decimals, comment. Do not rename them to something tidier — a list is
// external data and these are the fields its publisher wrote.
//
// A conforming entry carries either a Soroban `contract` address or the classic
// `code`+`issuer` pair, and may carry both. Fields absent from an entry are the
// empty string (or nil Decimals), which is a property of the list, not an error.
type Asset struct {
	// Contract is the asset's Soroban contract address (StrKey), when the list
	// publishes one. For a classic asset this is its Stellar Asset Contract.
	Contract string `json:"contract"`
	// Code and Issuer identify a classic asset.
	Code   string `json:"code"`
	Issuer string `json:"issuer"`
	// Name and Org are the list's own labels for the asset and its issuer.
	Name string `json:"name"`
	Org  string `json:"org"`
	// Domain is the FQDN the list says hosts the asset's stellar.toml.
	Domain string `json:"domain"`
	// Icon is an HTTPS URL or an IPFS hash.
	Icon string `json:"icon"`
	// Decimals is a pointer because 0 is a meaningful value ("no decimals to
	// display") and must stay distinguishable from "the list did not say".
	Decimals *int `json:"decimals"`
	// Comment is the list provider's free-text note. It is carried through for
	// display and is never parsed for judgment: treating prose as a verdict
	// would be re-deriving a consumed signal, which is the one thing this
	// project does not do with someone else's curation.
	Comment string `json:"comment"`
}

// List is one decoded SEP-0042 Stellar Asset List.
//
// URL and FetchedAt are provenance supplied by this package, not fields of the
// format: a list is only usable in a report if the reader can re-fetch exactly
// what was read, and only honest if they can see when it was read.
type List struct {
	// URL is the location the list was fetched from.
	URL string `json:"-"`
	// FetchedAt is when the list was retrieved.
	FetchedAt time.Time `json:"-"`

	// Name, Provider, Version, Network, Description and Feedback are the
	// list's own self-description. Name is required by the format and is what
	// identifies the source in a report; the rest are recorded as published and
	// are not required here, because real published lists omit some of them.
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Network     string `json:"network"`
	Feedback    string `json:"feedback"`

	// Assets are the list's entries, in the order the list published them.
	Assets []Asset `json:"assets"`
}

// Lookup returns the entry describing the given asset, if the list has one.
//
// Matching is by the classic code+issuer pair, and by Soroban contract address
// when one is supplied. A contract match is sound for a classic asset because
// its SAC address is derived deterministically from its code and issuer, and
// Horizon reports that same address on the asset record. Codes are compared
// exactly: Stellar asset codes are case-sensitive, so folding case here could
// match a lookalike.
//
// A list that does not contain the asset is not a failure and produces no
// error; it is an answer ("this provider does not list it") that the caller
// must keep separate from "this provider could not be read".
func (l *List) Lookup(code, issuer, contract string) (Asset, bool) {
	if l == nil {
		return Asset{}, false
	}
	for _, a := range l.Assets {
		if code != "" && a.Code == code && a.Issuer == issuer {
			return a, true
		}
		if contract != "" && a.Contract == contract {
			return a, true
		}
	}
	return Asset{}, false
}

// Client fetches published Stellar Asset Lists.
type Client struct {
	HTTP      *http.Client
	UserAgent string
}

// New returns a Client using the default HTTP settings and identity.
func New() *Client {
	return &Client{
		HTTP:      &http.Client{Timeout: 20 * time.Second},
		UserAgent: defaultUserAgent,
	}
}

// Fetch retrieves and decodes the list published at url.
//
// A list URL is configuration, so this is strict about transport: only a 200
// with a decodable body counts, and anything else returns an error naming the
// URL and the reason. It is deliberately permissive about the format's optional
// fields, because real published lists omit some of them; the one thing that
// must be present is the list's own name, which is what makes a document
// identifiable as a SAL rather than arbitrary JSON.
func (c *Client) Fetch(ctx context.Context, url string) (*List, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("assetlist: get %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("assetlist: get %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return nil, fmt.Errorf("assetlist: read %s: %w", url, err)
	}
	var l List
	if err := json.Unmarshal(body, &l); err != nil {
		return nil, fmt.Errorf("assetlist: decode %s: %w", url, err)
	}
	if l.Name == "" {
		return nil, fmt.Errorf("assetlist: %s: not a Stellar Asset List (no name)", url)
	}
	l.URL = url
	l.FetchedAt = time.Now().UTC()
	return &l, nil
}
