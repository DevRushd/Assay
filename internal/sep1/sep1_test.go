package sep1_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
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

func TestCanonicalFailureIgnoresHostDetails(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    error
		b    error
		want string
	}{
		{"connection refused", errors.New("dial tcp first.example:443: connect: connection refused"), errors.New("dial tcp second.example:443: connect: connection refused"), sep1.FailureConnectionRefused},
		{"dns", errors.New("dial tcp: lookup first.example: no such host"), errors.New("dial tcp: lookup second.example: no such host"), sep1.FailureDNS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sep1.CanonicalFailure(tc.a); got != tc.want {
				t.Fatalf("first error category = %q, want %q", got, tc.want)
			}
			if got := sep1.CanonicalFailure(tc.b); got != tc.want {
				t.Fatalf("second error category = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInjectedFetchErrorsProduceTheSameEvidenceHash(t *testing.T) {
	hashes := make([]string, 0, 2)
	for _, message := range []string{
		"dial tcp first.example:443: connect: connection refused",
		"dial tcp second.example:443: connect: connection refused",
	} {
		f := sep1.NewFetcher()
		f.HTTP = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New(message)
		})}
		_, err := f.Fetch(context.Background(), "issuer.example")
		if err == nil {
			t.Fatal("Fetch succeeded for injected transport failure")
		}
		report := &mechanics.Report{
			Asset:          mechanics.Asset{Code: "VELO", Issuer: issuer},
			Accountability: mechanics.AccountabilityUnverified,
			Evidence: []mechanics.Evidence{{
				Source: "stellar.toml",
				URL:    "stellar.toml",
				Claim:  "not retrievable: " + sep1.CanonicalFailure(err),
			}},
		}
		params, err := attest.FromReport(report)
		if err != nil {
			t.Fatalf("FromReport: %v", err)
		}
		hashes = append(hashes, params.EvidenceHash)
	}
	if hashes[0] != hashes[1] {
		t.Fatalf("same failure class produced different evidence hashes: %s != %s", hashes[0], hashes[1])
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
