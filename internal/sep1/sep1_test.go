package sep1_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/sep1"
)

const issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

func TestClaims(t *testing.T) {
	doc, err := sep1.Parse([]byte(`
[[CURRENCIES]]
code = "USDC"
issuer = "` + issuer + `"

[[CURRENCIES]]
code = "EURC"
issuer = "GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !doc.Claims("USDC", issuer) {
		t.Error("Claims(USDC, issuer) = false, want true")
	}
	if !doc.Claims("usdc", issuer) {
		t.Error("code matching should be case-insensitive")
	}

	// A toml claiming the right code under the wrong issuer is exactly the
	// impersonation this check exists to catch, so code alone must never match.
	if doc.Claims("USDC", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA") {
		t.Error("Claims matched on code alone with a different issuer")
	}
	if doc.Claims("XLM", issuer) {
		t.Error("Claims matched an unlisted code")
	}

	var nilDoc *sep1.Doc
	if nilDoc.Claims("USDC", issuer) {
		t.Error("nil doc must not claim anything")
	}
}

// TestStatus covers the lookup the domain check uses to surface a currency
// entry's published status. It matches on code AND issuer for the same reason
// Claims does: a status is a statement about one asset, and code-alone
// matching would let any domain attach a status to someone else's code.
func TestStatus(t *testing.T) {
	const other = "GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2"

	doc, err := sep1.Parse([]byte(`
[[CURRENCIES]]
code = "USDC"
issuer = "` + issuer + `"
status = "live"

[[CURRENCIES]]
code = "EURC"
issuer = "` + other + `"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got := doc.Status("USDC", issuer); got != "live" {
		t.Errorf("Status(USDC, issuer) = %q, want %q", got, "live")
	}
	if got := doc.Status("usdc", issuer); got != "live" {
		t.Errorf("status matching should be case-insensitive on the code, got %q", got)
	}

	// An entry that publishes no status is no status, not an empty claim.
	if got := doc.Status("EURC", other); got != "" {
		t.Errorf("Status of an entry with no status = %q, want empty", got)
	}
	// Code alone must never match: that would let a domain attach a status
	// to an asset code it does not claim.
	if got := doc.Status("USDC", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"); got != "" {
		t.Errorf("Status matched on code alone with a different issuer: %q", got)
	}
	if got := doc.Status("XLM", issuer); got != "" {
		t.Errorf("Status of an unlisted code = %q, want empty", got)
	}

	var nilDoc *sep1.Doc
	if got := nilDoc.Status("USDC", issuer); got != "" {
		t.Errorf("nil doc Status() = %q, want empty", got)
	}
}

// TestOrganisationFields covers the document-level publisher fields the domain
// check relays as attributed evidence. They are document-level, not per-entry:
// ORG_NAME and ORG_URL say who publishes the stellar.toml, which is what a
// report reader wants to know about the party claiming the asset. Both are read
// exactly as published — an issuer may put any text here, including a URL that
// is not a URL — and an absent field is the empty string rather than a default,
// because empty is what keeps a document that declares no organisation from
// emitting evidence at all.
func TestOrganisationFields(t *testing.T) {
	doc, err := sep1.Parse([]byte(`
[DOCUMENTATION]
ORG_NAME = "Aquarius"
ORG_URL = "https://aqua.network/"

[[CURRENCIES]]
code = "USDC"
issuer = "` + issuer + `"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if doc.Documentation.OrgName != "Aquarius" {
		t.Errorf("OrgName = %q, want %q", doc.Documentation.OrgName, "Aquarius")
	}
	if doc.Documentation.OrgURL != "https://aqua.network/" {
		t.Errorf("OrgURL = %q, want %q", doc.Documentation.OrgURL, "https://aqua.network/")
	}

	// A document that declares neither field parses to empty strings, not to a
	// partially filled claim: the evidence built from these fields must be
	// absent rather than `ORG_NAME ""` for every issuer that never published one.
	plain, err := sep1.Parse([]byte(`
[[CURRENCIES]]
code = "USDC"
issuer = "` + issuer + `"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if plain.Documentation.OrgName != "" || plain.Documentation.OrgURL != "" {
		t.Errorf("undeclared organisation fields = (%q, %q), want both empty", plain.Documentation.OrgName, plain.Documentation.OrgURL)
	}
}

// SEP-0001 permits a currency entry that links to a separate per-currency
// TOML. Counting those entries is what lets the domain check say
// "unconfirmed" instead of wrongly saying "refuted", because a link Assay did
// not follow may name the asset in a document it never read.
func TestLinkedCurrencies(t *testing.T) {
	doc, err := sep1.Parse([]byte(`
[[CURRENCIES]]
toml = "https://example.com/.well-known/USDC.toml"

[[CURRENCIES]]
toml = "https://example.com/.well-known/EURC.toml"

[[CURRENCIES]]
code = "AQUA"
issuer = "` + issuer + `"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Two link-only entries neither of which is this asset: both are
	// unresolved, so both count.
	if got := doc.LinkedCurrencies("AQUA", issuer); got != 2 {
		t.Errorf("LinkedCurrencies(AQUA) = %d, want 2", got)
	}
	if doc.Claims("USDC", issuer) {
		t.Error("a linked entry must not be treated as an inline claim")
	}
	if !doc.Claims("AQUA", issuer) {
		t.Error("inline entries must still match alongside linked ones")
	}

	var nilDoc *sep1.Doc
	if got := nilDoc.LinkedCurrencies("AQUA", issuer); got != 0 {
		t.Errorf("nil doc LinkedCurrencies() = %d, want 0", got)
	}
}

// TestLinkedCurrenciesCountsLinkedEntryWithACode covers the shape the old
// count missed. SEP-0001 does not require a linked entry to be link-only: an
// entry may carry a toml link alongside a code and issuer. The distinction
// that matters is not the shape of the entry but whether it already claims the
// asset inline — an entry that does not is a lost claim the hedge must cover,
// and one that does is the claim itself.
func TestLinkedCurrenciesCountsLinkedEntryWithACode(t *testing.T) {
	const other = "GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2"

	cases := []struct {
		name       string
		toml       string
		wantLinked int
		wantClaims bool
	}{
		{
			name: "link with a code that does not match",
			toml: `
[[CURRENCIES]]
toml = "https://example.com/.well-known/EURC.toml"
code = "EURC"
issuer = "` + other + `"
`,
			wantLinked: 1,
			wantClaims: false,
		},
		{
			name: "link with a code that matches",
			toml: `
[[CURRENCIES]]
toml = "https://example.com/.well-known/USDC.toml"
code = "USDC"
issuer = "` + issuer + `"
`,
			wantLinked: 0,
			wantClaims: true,
		},
		{
			name: "matching link beside a non-matching one",
			toml: `
[[CURRENCIES]]
toml = "https://example.com/.well-known/USDC.toml"
code = "USDC"
issuer = "` + issuer + `"

[[CURRENCIES]]
toml = "https://example.com/.well-known/EURC.toml"
code = "EURC"
issuer = "` + other + `"

[[CURRENCIES]]
toml = "https://example.com/.well-known/XLM.toml"
`,
			wantLinked: 2,
			wantClaims: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := sep1.Parse([]byte(tc.toml))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := doc.LinkedCurrencies("USDC", issuer); got != tc.wantLinked {
				t.Errorf("LinkedCurrencies(USDC, issuer) = %d, want %d", got, tc.wantLinked)
			}
			if got := doc.Claims("USDC", issuer); got != tc.wantClaims {
				t.Errorf("Claims(USDC, issuer) = %v, want %v", got, tc.wantClaims)
			}
		})
	}
}

func TestURLFor(t *testing.T) {
	want := "https://circle.com/.well-known/stellar.toml"
	for _, in := range []string{"circle.com", "circle.com/"} {
		if got := sep1.URLFor(in); got != want {
			t.Errorf("URLFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNormalizeDomain pins the canonical form of the free-text shapes
// home_domain arrives in from the ledger. DNS is case-insensitive, lookup
// names end in a root dot, and an https URL may spell out its default port —
// all three name the same host, so all three must reduce to one string. The
// requested URL, the redirect policy and the blocklist key are all keyed on
// this value; a disagreement between them is a verification that checks one
// host and queries another.
func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"already canonical", "example.com", "example.com"},
		{"root trailing dot", "example.com.", "example.com"},
		{"upper case", "EXAMPLE.com", "example.com"},
		{"default https port", "example.com:443", "example.com"},
		{"all three at once", "EXAMPLE.com.:443", "example.com"},
		{"trailing slash", "example.com/", "example.com"},
		{"surrounding whitespace", " example.com ", "example.com"},
		// A non-default port names a different service; dropping it would
		// fetch from the wrong one.
		{"non-default port preserved", "example.com:8443", "example.com:8443"},
		// IPv6 literals carry many colons and must never be mistaken for
		// host:port.
		{"ipv6 literal untouched", "[2001:db8::1]", "[2001:db8::1]"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sep1.NormalizeDomain(tc.in); got != tc.want {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// Normalising is idempotent: the canonical form of the
			// canonical form must not move, or a second pass through
			// the scanner could key a different lookup than the first.
			if got := sep1.NormalizeDomain(sep1.NormalizeDomain(tc.in)); got != tc.want {
				t.Errorf("NormalizeDomain twice = %q, want %q (not idempotent)", got, tc.want)
			}
		})
	}
}

// TestURLForCanonicalAcrossHomeDomainShapes pins the acceptance criterion for
// evidence: whichever shape the ledger's home_domain wears, the requested URL
// recorded in the report is the single canonical one. Three spellings of one
// host must not produce three URLs a reader would have to recognise as the
// same claim.
func TestURLForCanonicalAcrossHomeDomainShapes(t *testing.T) {
	const want = "https://example.com/.well-known/stellar.toml"
	for _, in := range []string{
		"example.com",
		"example.com.",
		"EXAMPLE.com",
		"example.com:443",
		"EXAMPLE.COM.",
		"example.com/",
	} {
		if got := sep1.URLFor(in); got != want {
			t.Errorf("URLFor(%q) = %q, want canonical %q", in, got, want)
		}
	}
}

// TestFetchCanonicalRequestForHomeDomainShapes drives each free-text shape
// through Fetch and inspects the request as the remote host would receive it.
// The requested URL on the wire, and the URL recorded on the document (which
// becomes evidence), must be the canonical one for every shape — that is the
// agreement the blocklist key and redirect policy are pinned against.
func TestFetchCanonicalRequestForHomeDomainShapes(t *testing.T) {
	const want = "https://example.com/.well-known/stellar.toml"

	for _, shape := range []string{"example.com", "example.com.", "EXAMPLE.com", "example.com:443"} {
		t.Run(shape, func(t *testing.T) {
			var requested string
			rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				requested = req.URL.String()
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(validToml)),
					Header:     http.Header{},
					Request:    req,
				}, nil
			})

			f := sep1.NewFetcher()
			f.HTTP = &http.Client{Transport: rt}
			doc, err := f.Fetch(context.Background(), shape)
			if err != nil {
				t.Fatalf("Fetch(%q): %v", shape, err)
			}
			if requested != want {
				t.Errorf("Fetch(%q) requested %q, want canonical %q", shape, requested, want)
			}
			if doc.URL != want {
				t.Errorf("Fetch(%q) recorded doc.URL = %q, want canonical %q", shape, doc.URL, want)
			}
		})
	}
}

// roundTripperFunc adapts a function to http.RoundTripper.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestUserAgent pins the identity the scanner offers to domains it verifies
// against. A specific string, not merely a non-empty one, because the
// operators of the services we call filter on it. The stub transport answers
// in place of the network so the test can inspect the request exactly as the
// remote host would receive it.
func TestUserAgent(t *testing.T) {
	want := "assay/v0.1.0 (+https://github.com/use-assay/Assay)"

	var ua string
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		ua = req.Header.Get("User-Agent")
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     http.Header{},
			Request:    req,
		}, nil
	})

	f := sep1.NewFetcher()
	f.HTTP = &http.Client{Transport: rt}
	if _, err := f.Fetch(context.Background(), "example.com"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if ua != want {
		t.Errorf("User-Agent = %q, want %q", ua, want)
	}
}
