package sep1_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/sep1"
)

// Fetch is the only part of sep1 that performs network I/O, and its output
// decides accountability and sets the domain_unverified bit that is on-chain in
// every attestation. Its failure text also enters hashed evidence, so the shape
// of both the success and failure errors is load-bearing.
//
// These tests drive Fetch through a stub RoundTripper (and the redirect tests
// through an httptest loopback server), so nothing here touches the public
// network. The cases mirror real corpus assets: circle.com answered 404,
// nasdaq.finance failed DNS, hiddenstellar.com returned TOML that did not parse.

const validToml = "[[CURRENCIES]]\ncode = \"USDC\"\nissuer = \"" + issuer + "\"\n"

// fetcherReturning builds a Fetcher whose transport answers every request with
// status and body, or fails with err when err is non-nil. The stub copies the
// request into the response so Fetch can read the final URL, exactly as a real
// client would.
func fetcherReturning(status int, body string, err error) *sep1.Fetcher {
	f := sep1.NewFetcher()
	f.HTTP = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     http.Header{},
			Request:    req,
		}, nil
	})}
	return f
}

// TestFetchStatusMatrix covers the valid case and the non-200 invalid cases.
// Every non-200 must be an error carrying the status, and must not produce a
// document: an empty or partial document treated as an answer is the failure
// this matrix exists to prevent.
func TestFetchStatusMatrix(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr string // substring of the error; empty means the fetch succeeds
	}{
		{"200 with a valid document", http.StatusOK, validToml, ""},
		{"404 not found", http.StatusNotFound, "not found", "status 404"},
		{"500 server error", http.StatusInternalServerError, "boom", "status 500"},
		{"403 forbidden", http.StatusForbidden, "forbidden", "status 403"},
		{"301 is not followed by a bare client", http.StatusMovedPermanently, "", "status 301"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := fetcherReturning(tc.status, tc.body, nil).
				Fetch(context.Background(), "example.com")

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("200 with a valid document returned an error: %v", err)
				}
				if doc == nil {
					t.Fatal("successful fetch returned a nil document")
				}
				if !doc.Claims("USDC", issuer) {
					t.Error("parsed document does not claim the asset it was served")
				}
				if want := sep1.URLFor("example.com"); doc.URL != want {
					t.Errorf("doc.URL = %q, want the location fetched from %q", doc.URL, want)
				}
				if doc.FetchedAt.IsZero() {
					t.Error("successful fetch recorded no retrieval time")
				}
				return
			}

			if err == nil {
				t.Fatalf("status %d was reported as a successful fetch", tc.status)
			}
			if doc != nil {
				t.Error("a failed fetch returned a document")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error does not carry the status: %v", err)
			}
			// The error must name the requested location, not only the status,
			// or it cannot be recorded as attributed evidence.
			if !strings.Contains(err.Error(), sep1.URLFor("example.com")) {
				t.Errorf("error does not name the requested URL: %v", err)
			}
		})
	}
}

// TestFetchMalformedTOMLIsAParseErrorNotAFetchError covers hiddenstellar.com:
// the domain answered 200 with a body that is not valid TOML. The failure must
// be distinguishable from a transport or status failure, because the two say
// different things and only one of them means "we never read the document".
func TestFetchMalformedTOMLIsAParseErrorNotAFetchError(t *testing.T) {
	const malformed = "[[CURRENCIES]]\ncode = \"unterminated\n"

	doc, err := fetcherReturning(http.StatusOK, malformed, nil).
		Fetch(context.Background(), "example.com")
	if err == nil {
		t.Fatal("malformed TOML was accepted as a valid document")
	}
	if doc != nil {
		t.Error("a parse failure returned a document")
	}
	if !strings.Contains(err.Error(), "sep1: parse") {
		t.Errorf("parse failure is not labelled as a parse failure: %v", err)
	}
	// A parse error must never masquerade as a fetch error: the fetch did
	// complete, so reporting it as a transport/status failure would say the
	// source never answered when it did.
	if strings.Contains(err.Error(), "sep1: fetch") || strings.Contains(err.Error(), "status") {
		t.Errorf("parse failure is indistinguishable from a fetch failure: %v", err)
	}
}

// TestFetchTransportFailureWrapsTheCause covers nasdaq.finance: DNS did not
// resolve, so there is no response at all. The underlying error must survive
// wrapped, because it is recorded verbatim into TomlErr and enters hashed
// evidence (issue #24).
func TestFetchTransportFailureWrapsTheCause(t *testing.T) {
	sentinel := errors.New("dial tcp: lookup nasdaq.finance: no such host")

	doc, err := fetcherReturning(0, "", sentinel).
		Fetch(context.Background(), "nasdaq.finance")
	if err == nil {
		t.Fatal("a transport failure was reported as a successful fetch")
	}
	if doc != nil {
		t.Error("a transport failure returned a document")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("the underlying failure was not preserved: %v", err)
	}
	if !strings.Contains(err.Error(), "sep1: fetch") {
		t.Errorf("transport failure is not labelled as a fetch failure: %v", err)
	}
}

// TestFetchNoDomain covers the missing-input state. It is handled before any
// request is built, so this test performs no I/O by construction.
func TestFetchNoDomain(t *testing.T) {
	doc, err := sep1.NewFetcher().Fetch(context.Background(), "")
	if !errors.Is(err, sep1.ErrNoDomain) {
		t.Fatalf("Fetch(\"\") error = %v, want ErrNoDomain", err)
	}
	if doc != nil {
		t.Error("Fetch(\"\") returned a document")
	}
}

// TestMaxBodyCapIsExplicit pins the cap's value rather than assuming the
// resource-exhaustion tests happen to agree with it. One MiB is the contract
// the truncation tests assert; if it changes, this fails first and names it.
func TestMaxBodyCapIsExplicit(t *testing.T) {
	if sep1.MaxBody != 1<<20 {
		t.Fatalf("MaxBody = %d, want %d (1 MiB)", sep1.MaxBody, 1<<20)
	}
}
