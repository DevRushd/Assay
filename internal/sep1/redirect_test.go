package sep1_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/sep1"
)

// A hostile home_domain points the scanner at a server the issuer controls, and
// that server chooses where the fetch goes next. These tests pin the two halves
// of the redirect policy: the chain is bounded, and it may not leave the
// requested host's namespace into an unrelated host whose document would then
// be recorded as this domain's claim.

const redirectToml = "[[CURRENCIES]]\ncode = \"USDC\"\nissuer = \"" + issuer + "\"\n"

// fetcherForServer points a real Fetcher at srv, keeping NewFetcher's redirect
// policy while trusting the test server's certificate. It replaces the client
// wholesale the way NewFetcher builds it, so the policy under test is exactly
// the one the scanner uses.
func fetcherForServer(srv *httptest.Server) *sep1.Fetcher {
	f := sep1.NewFetcher()
	f.HTTP = srv.Client()
	f.HTTP.CheckRedirect = sep1.CheckRedirect
	return f
}

// TestRedirectWithinBound follows two same-site hops and expects the document
// at the end. The final URL is the one recorded, so a reader can see where the
// claim actually came from.
func TestRedirectWithinBound(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/stellar.toml":
			http.Redirect(w, r, "/hop/1", http.StatusFound)
		case "/hop/1":
			http.Redirect(w, r, "/hop/2", http.StatusFound)
		case "/hop/2":
			_, _ = io.WriteString(w, redirectToml)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	doc, err := fetcherForServer(srv).Fetch(context.Background(), domainOf(srv.URL))
	if err != nil {
		t.Fatalf("two same-site redirects within the bound: %v", err)
	}
	final := srv.URL + "/hop/2"
	if doc.URL != final {
		t.Errorf("doc.URL = %q, want the final location %q", doc.URL, final)
	}
	if !doc.Claims("USDC", issuer) {
		t.Error("document fetched through the redirect does not claim the asset")
	}
}

// TestRedirectExceedingBound serves a chain that never terminates. The fetch
// must stop at MaxRedirects rather than chase it. The error text pins the
// bound's value, not merely that some bound exists.
func TestRedirectExceedingBound(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every request redirects onward to a fresh path, so the chain has no
		// natural end.
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	_, err := fetcherForServer(srv).Fetch(context.Background(), domainOf(srv.URL))
	if err == nil {
		t.Fatal("an unbounded redirect chain was followed to completion")
	}
	if !strings.Contains(err.Error(), "stopped after 5 redirects") {
		t.Errorf("error does not report the explicit redirect bound: %v", err)
	}
}

// TestRedirectCrossHostRefused is the policy decision as a test: the fetch is
// sent to an unrelated host, and the document there must never be treated as
// this domain's claim. The error names the final host.
func TestRedirectCrossHostRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.example/.well-known/stellar.toml", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	_, err := fetcherForServer(srv).Fetch(context.Background(), domainOf(srv.URL))
	if err == nil {
		t.Fatal("a cross-host redirect was followed and its document accepted as the domain's claim")
	}
	if !strings.Contains(err.Error(), "other.example") {
		t.Errorf("error does not name the final host: %v", err)
	}
}

// TestRedirectPolicy pins the host rule directly, including the asymmetry that
// is the judgement call: descending into a subdomain is allowed, climbing to a
// parent is not. Case and the root-trailing dot must not change the answer,
// because DNS is case-insensitive and either spelling can appear in a Location.
func TestRedirectPolicy(t *testing.T) {
	req := func(u string) *http.Request {
		t.Helper()
		r, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			t.Fatalf("build request %q: %v", u, err)
		}
		return r
	}

	cases := []struct {
		name   string
		origin string
		final  string
		ok     bool
	}{
		{"same host", "circle.com", "circle.com", true},
		{"apex to www", "circle.com", "www.circle.com", true},
		{"apex to deep subdomain", "circle.com", "cdn.eu.circle.com", true},
		{"case and trailing dot", "Circle.COM.", "www.circle.com", true},
		{"www to apex refused", "www.circle.com", "circle.com", false},
		{"unrelated host refused", "evil.example", "circle.com", false},
		{"label-boundary lookalike refused", "circle.com", "notcircle.com", false},
		{"attacker subdomain of victim refused", "evil.example", "victim.example", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			via := []*http.Request{req("https://" + tc.origin + "/.well-known/stellar.toml")}
			err := sep1.CheckRedirect(req("https://"+tc.final+"/.well-known/stellar.toml"), via)
			if tc.ok && err != nil {
				t.Errorf("policy refused an allowed redirect %s -> %s: %v", tc.origin, tc.final, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("policy allowed a disallowed redirect %s -> %s", tc.origin, tc.final)
			}
		})
	}
}
