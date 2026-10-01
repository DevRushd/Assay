package assetlist_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/assetlist"
)

// fixture is the real published StellarExpert Top 50 list, captured verbatim.
// Its provenance, licence and the field names verified against it are recorded
// in testdata/PROVENANCE.md. Driving the decoder from a real published
// document, rather than a body built from this package's own types, is the
// point: a fixture we wrote ourselves could only prove the decoder agrees with
// itself.
const fixture = "testdata/stellar-expert-top50.json"

// The values asserted below are from the committed snapshot, so these tests are
// hermetic and cannot go red because a third-party list changed.
const (
	fixtureUSDC       = "USDC"
	fixtureUSDCIssuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
	fixtureUSDCStrKey = "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75"
)

func readFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

// serveFixture serves the captured list over a real HTTP server.
func serveFixture(t *testing.T) (*assetlist.Client, string) {
	t.Helper()
	body := readFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return assetlist.New(), srv.URL + "/list.json"
}

// TestRealPublishedListDecodes is the field-name verification: every field this
// package encodes is read back out of a real list with the value the list
// published, so a wrong JSON name would show up as an empty string rather than
// silently passing.
func TestRealPublishedListDecodes(t *testing.T) {
	c, url := serveFixture(t)
	list, err := c.Fetch(context.Background(), url)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if list.Name != "StellarExpert Top 50" {
		t.Errorf("Name = %q", list.Name)
	}
	if list.Provider != "StellarExpert" {
		t.Errorf("Provider = %q", list.Provider)
	}
	if list.Version == "" || list.Network == "" || list.Description == "" || list.Feedback == "" {
		t.Errorf("self-description fields lost: version=%q network=%q description=%q feedback=%q",
			list.Version, list.Network, list.Description, list.Feedback)
	}
	if len(list.Assets) != 50 {
		t.Fatalf("decoded %d assets, want the 50 the list publishes", len(list.Assets))
	}
	if list.URL != url {
		t.Errorf("URL = %q, want the fetch URL %q", list.URL, url)
	}
	if list.FetchedAt.IsZero() {
		t.Error("FetchedAt was not recorded, so a report could not age this list")
	}

	entry, ok := list.Lookup(fixtureUSDC, fixtureUSDCIssuer, "")
	if !ok {
		t.Fatal("USDC is in the published list but Lookup missed it")
	}
	for _, tc := range []struct{ field, got, want string }{
		{"code", entry.Code, fixtureUSDC},
		{"issuer", entry.Issuer, fixtureUSDCIssuer},
		{"contract", entry.Contract, fixtureUSDCStrKey},
		{"name", entry.Name, "USD Coin"},
		{"org", entry.Org, "Centre Consortium LLC dba Centre Consortium"},
		{"domain", entry.Domain, "centre.io"},
	} {
		if tc.got != tc.want {
			t.Errorf("entry %s = %q, want %q", tc.field, tc.got, tc.want)
		}
	}
	if entry.Decimals == nil || *entry.Decimals != 7 {
		t.Errorf("decimals = %v, want 7", entry.Decimals)
	}
	if entry.Icon == "" {
		t.Error("icon did not decode")
	}
}

// The fixture is committed data, not generated output: it has to keep parsing
// as the format describes, including fields no entry in it uses (comment).
func TestFixtureCarriesTheFormatFieldNames(t *testing.T) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(readFixture(t), &doc); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	for _, key := range []string{"name", "provider", "version", "assets"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("fixture is missing the SEP-0042 required top-level field %q", key)
		}
	}

	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(doc["assets"], &entries); err != nil {
		t.Fatalf("decode assets: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("fixture has no assets")
	}
	// Every key the real list uses must be one this package knows about; an
	// unknown key would be a field silently dropped from reports.
	known := map[string]bool{
		"code": true, "issuer": true, "contract": true, "name": true, "org": true,
		"domain": true, "icon": true, "decimals": true, "comment": true,
	}
	for _, e := range entries {
		for k := range e {
			if !known[k] {
				t.Errorf("fixture uses entry field %q, which this package does not decode", k)
			}
		}
	}
	// And the contract field must actually carry what this package assumes: a
	// StrKey contract address, not some other encoding. A conforming list
	// publishes ^C[A-Z0-9]{55}$ here.
	for _, e := range entries {
		if raw, ok := e["contract"]; ok {
			var contract string
			if err := json.Unmarshal(raw, &contract); err != nil {
				t.Fatalf("decode contract: %v", err)
			}
			if !strings.HasPrefix(contract, "C") || len(contract) != 56 {
				t.Errorf("contract %q is not a StrKey address; if this list really publishes "+
					"another encoding, that assumption needs revisiting", contract)
			}
		}
	}
}

// An asset the list does not hold is an answer, not a failure: the caller has
// to be able to tell "this provider does not list it" from "this provider could
// not be read", because only the second one is a reason to distrust the report.
func TestLookupMissIsNotAnError(t *testing.T) {
	c, url := serveFixture(t)
	list, err := c.Fetch(context.Background(), url)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, ok := list.Lookup("NOPE", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", ""); ok {
		t.Fatal("Lookup found an asset the list does not contain")
	}
}

// Contract-only entries cannot match a classic code/issuer pair, but must match
// the same asset's contract address — which Horizon reports on the asset
// record for a classic asset.
func TestLookupByContractAddress(t *testing.T) {
	c, url := serveFixture(t)
	list, err := c.Fetch(context.Background(), url)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// The USDC entry carries both identifiers; asking with the contract alone
	// must still resolve it.
	entry, ok := list.Lookup("", "", fixtureUSDCStrKey)
	if !ok {
		t.Fatal("Lookup by contract address missed a contract-carrying entry")
	}
	if entry.Code != fixtureUSDC {
		t.Errorf("contract match returned %q, want %q", entry.Code, fixtureUSDC)
	}
}

// Stellar asset codes are case-sensitive, so folding case could match a
// lookalike code published by someone else.
func TestLookupDoesNotFoldCase(t *testing.T) {
	c, url := serveFixture(t)
	list, err := c.Fetch(context.Background(), url)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, ok := list.Lookup(strings.ToLower(fixtureUSDC), fixtureUSDCIssuer, ""); ok {
		t.Fatal("a lowercase code matched an uppercase asset code")
	}
}

// A nil list is what a caller gets when nothing was configured. Handle it.
func TestLookupOnNilList(t *testing.T) {
	var list *assetlist.List
	if _, ok := list.Lookup(fixtureUSDC, fixtureUSDCIssuer, ""); ok {
		t.Fatal("a nil list reported a match")
	}
}

// User-Agent is pinned: operators of the services Assay calls filter on it.
func TestFetchUserAgent(t *testing.T) {
	want := "assay/v0.1.0 (+https://github.com/use-assay/Assay)"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != want {
			t.Errorf("User-Agent = %q, want %q", got, want)
		}
		_, _ = w.Write(readFixture(t))
	}))
	t.Cleanup(srv.Close)

	if _, err := assetlist.New().Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
}

// A URL that is not a list is a configuration error, and must say so rather
// than returning an empty list that would render as "this provider lists
// nothing".
func TestFetchRejectsNonLists(t *testing.T) {
	for _, body := range []string{
		`{}`,                           // decodes, but has no name
		`{"provider":"x","assets":[]}`, // still no name
		`[]`,                           // not an object at all
		`"a string"`,                   // not an object
		`{"name":`,                     // truncated
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		c := assetlist.New()
		if _, err := c.Fetch(context.Background(), srv.URL); err == nil {
			t.Errorf("body %q was accepted as a Stellar Asset List", body)
		}
		srv.Close()
	}
}

// Only a 200 counts. A 404 or 429 on a configured list URL is a failure the
// report has to carry verbatim, never an empty list.
func TestFetchRejectsNon200(t *testing.T) {
	for _, status := range []int{
		http.StatusNotFound,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"name":"anything"}`))
		}))
		_, err := assetlist.New().Fetch(context.Background(), srv.URL)
		srv.Close()
		if err == nil {
			t.Errorf("status %d was reported as a usable list", status)
		}
		if !strings.Contains(err.Error(), "status") {
			t.Errorf("status %d error does not name the status: %v", status, err)
		}
	}
}

// The remote denial-of-service surface: a list URL is configuration, but the
// body behind it is still remote and can be broken or hostile. streamBody
// counts exactly what it was asked for, so the cap is asserted rather than
// assumed.
type streamBody struct {
	read int64
	max  int64 // -1 means unbounded
}

func (b *streamBody) Read(p []byte) (int, error) {
	if b.max >= 0 && b.read >= b.max {
		return 0, io.EOF
	}
	n := len(p)
	if b.max >= 0 && int64(n) > b.max-b.read {
		n = int(b.max - b.read)
	}
	for i := 0; i < n; i++ {
		p[i] = ' '
	}
	b.read += int64(n)
	return n, nil
}

func (b *streamBody) Close() error { return nil }

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func clientFor(body io.ReadCloser) *assetlist.Client {
	c := assetlist.New()
	c.HTTP = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       body,
			Header:     http.Header{},
			Request:    req,
		}, nil
	})}
	return c
}

func TestOversizedListBodyIsTruncatedAtTheCap(t *testing.T) {
	body := &streamBody{max: assetlist.MaxBody * 4}

	if _, err := clientFor(body).Fetch(context.Background(), "https://example.test/list.json"); err == nil {
		t.Fatal("an oversized body decoded as a valid list")
	}
	if body.read > assetlist.MaxBody {
		t.Fatalf("client read %d bytes, past the %d-byte cap", body.read, assetlist.MaxBody)
	}
	if body.read != assetlist.MaxBody {
		t.Fatalf("client read %d bytes, want exactly the %d-byte cap", body.read, assetlist.MaxBody)
	}
}

func TestInfiniteListBodyIsBounded(t *testing.T) {
	body := &streamBody{max: -1}

	if _, err := clientFor(body).Fetch(context.Background(), "https://example.test/list.json"); err == nil {
		t.Fatal("an infinite body decoded as a valid list")
	}
	if body.read != assetlist.MaxBody {
		t.Fatalf("client read %d bytes from an infinite body, want the %d-byte cap", body.read, assetlist.MaxBody)
	}
}
