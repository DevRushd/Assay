package sep1_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/sep1"
)

// A hostile home_domain points the scanner at a server the issuer controls.
// These tests assert that an oversized or slow response cannot exhaust the
// scanner: the read is capped, and a slow or non-terminating response is
// bounded by the client timeout and recorded as a failure.

// streamBody is a Response.Body that can produce more bytes than any caller
// should read. A client that does not cap its read will consume memory without
// bound; streamBody.read counts exactly what it was asked for.
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

func fetcherFor(body *streamBody) *sep1.Fetcher {
	f := sep1.NewFetcher()
	f.HTTP = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       body,
			Header:     http.Header{},
			Request:    req,
		}, nil
	})}
	return f
}

// TestExhaustSep1OversizedBodyIsTruncated serves a body four times the cap and
// asserts the client never asks for more than the cap. The read count is the
// assertion: memory is bounded because the read is bounded, not assumed to be.
func TestExhaustSep1OversizedBodyIsTruncated(t *testing.T) {
	body := &streamBody{max: sep1.MaxBody * 4}

	if _, err := fetcherFor(body).Fetch(context.Background(), "example.com"); err != nil {
		t.Fatalf("Fetch on an oversized body: %v", err)
	}
	if body.read != sep1.MaxBody {
		t.Fatalf("client read %d bytes, want exactly the %d-byte cap", body.read, sep1.MaxBody)
	}
}

// TestExhaustSep1InfiniteBodyIsBounded is the same bound against a body with no
// natural end: the read must still stop at the cap.
func TestExhaustSep1InfiniteBodyIsBounded(t *testing.T) {
	body := &streamBody{max: -1}

	if _, err := fetcherFor(body).Fetch(context.Background(), "example.com"); err != nil {
		t.Fatalf("Fetch on an infinite body: %v", err)
	}
	if body.read != sep1.MaxBody {
		t.Fatalf("client read %d bytes from an infinite body, want the %d-byte cap", body.read, sep1.MaxBody)
	}
}

// TestExhaustSep1NonTerminatingResponseIsBounded serves headers and then never
// sends a body. The fetch must fail within the timeout rather than hang.
//
// The requested domain is public-looking and the transport rewrites it to the
// httptest server, so the host policy does not refuse the fetch before it is
// made and the timeout is what the test actually measures.
func TestExhaustSep1NonTerminatingResponseIsBounded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Declare a body larger than anything this handler will ever write, so
		// the response can never be read as a complete zero-byte document.
		// Without it the server may finalize the flushed response just before
		// the client's timeout fires, and the fetch would race between an error
		// and a clean empty EOF — the assertion below must not depend on which
		// side of that race wins.
		w.Header().Set("Content-Length", "1024")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	f := sep1.NewFetcher()
	client := srv.Client()
	client.Transport = rewriteTo{base: client.Transport, host: domainOf(srv.URL)}
	client.Timeout = 200 * time.Millisecond
	f.HTTP = client

	start := time.Now()
	if _, err := f.Fetch(context.Background(), "non-terminating.example"); err == nil {
		t.Fatal("a response that never ends was reported as a successful fetch")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("non-terminating response was not bounded by the timeout: took %s", elapsed)
	}
}

// TestExhaustSep1SlowDripIsBounded serves a byte every 50ms. A drip that never
// completes must be cut off by the timeout, not followed forever.
func TestExhaustSep1SlowDripIsBounded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(50 * time.Millisecond):
				_, _ = w.Write([]byte("a"))
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
	}))
	t.Cleanup(srv.Close)

	f := sep1.NewFetcher()
	client := srv.Client()
	client.Transport = rewriteTo{base: client.Transport, host: domainOf(srv.URL)}
	client.Timeout = 200 * time.Millisecond
	f.HTTP = client

	start := time.Now()
	if _, err := f.Fetch(context.Background(), "slow-drip.example"); err == nil {
		t.Fatal("a slow-drip response was reported as a successful fetch")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("slow-drip response was not bounded by the timeout: took %s", elapsed)
	}
}

// rewriteTo sends every request to host while leaving the URL path and scheme
// untouched, so the fetcher's host policy still sees the requested domain. The
// base transport is preserved so the httptest server's TLS configuration is
// used.
type rewriteTo struct {
	base http.RoundTripper
	host string
}

func (t rewriteTo) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	u := *req.URL
	u.Host = t.host
	req.URL = &u
	return t.base.RoundTrip(req)
}

func domainOf(u string) string {
	return strings.TrimPrefix(u, "https://")
}
