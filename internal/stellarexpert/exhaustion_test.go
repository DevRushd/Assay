package stellarexpert_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/stellarexpert"
)

// The StellarExpert client decodes a response body the issuer does not control
// directly, but the endpoint is remote and can still be broken or hostile. This
// is the remote denial-of-service surface when Assay runs as a server: an
// oversized or slow response must not be able to exhaust it.

// streamBody is a Response.Body that can produce more bytes than any caller
// should read. streamBody.read counts exactly what it was asked for, so the
// cap can be asserted rather than assumed.
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

// roundTripperFunc adapts a function to http.RoundTripper, so a test can serve
// a response body it controls without a network socket.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func clientFor(body *streamBody) *stellarexpert.Client {
	c := stellarexpert.New("https://example.test")
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

const address = "GBBS25EGYQPGEZCGCFBKG4OAGFXU6DSOQBGTHELLJT3HZXZJ34HWS6XV"

// boundedReads is the most bytes the client may read from one remote response:
// MaxBody bytes per attempt, and the body is re-read once per retry attempt.
const boundedAttempts = 3 // stellarexpert.DefaultRetryOptions().Attempts

// boundedReads is the most bytes the client may read from one remote response:
// MaxBody bytes per attempt, and the body is re-read once per retry attempt.
const boundedReads = stellarexpert.MaxBody * boundedAttempts

// TestExhaustStellarExpertOversizedBodyIsTruncated serves a body four times the
// cap. The decode must fail on the truncated document and the client must never
// read more than MaxBody bytes in a single attempt.
func TestExhaustStellarExpertOversizedBodyIsTruncated(t *testing.T) {
	body := &streamBody{max: stellarexpert.MaxBody * 4}

	if _, err := clientFor(body).Directory(context.Background(), address); err == nil {
		t.Fatal("an oversized body decoded as a valid response")
	}
	// Each attempt is capped at MaxBody; with the retry loop the body may be
	// read once per attempt.
	if body.read > boundedReads {
		t.Fatalf("client read %d bytes, past the %d-byte cap", body.read, boundedReads)
	}
	if body.read < stellarexpert.MaxBody {
		t.Fatalf("client read %d bytes, want at least the %d-byte cap", body.read, stellarexpert.MaxBody)
	}
}

// TestExhaustStellarExpertInfiniteBodyIsBounded is the same bound against a
// body with no natural end.
func TestExhaustStellarExpertInfiniteBodyIsBounded(t *testing.T) {
	body := &streamBody{max: -1}

	if _, err := clientFor(body).Directory(context.Background(), address); err == nil {
		t.Fatal("an infinite body decoded as a valid response")
	}
	if body.read > boundedReads {
		t.Fatalf("client read %d bytes from an infinite body, want the %d-byte cap",
			body.read, boundedReads)
	}
	if body.read < stellarexpert.MaxBody {
		t.Fatalf("client read %d bytes from an infinite body, want at least the %d-byte cap",
			body.read, stellarexpert.MaxBody)
	}
}

// TestExhaustStellarExpertNonTerminatingResponseIsBounded serves headers and
// then never sends a body. The lookup must fail within the timeout.
func TestExhaustStellarExpertNonTerminatingResponseIsBounded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	c := stellarexpert.New(srv.URL)
	client := srv.Client()
	client.Timeout = 200 * time.Millisecond
	c.HTTP = client

	start := time.Now()
	if _, err := c.Directory(context.Background(), address); err == nil {
		t.Fatal("a response that never ends was reported as a successful lookup")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("non-terminating response was not bounded by the timeout: took %s", elapsed)
	}
}

// TestExhaustStellarExpertSlowDripIsBounded serves a byte every 50ms.
func TestExhaustStellarExpertSlowDripIsBounded(t *testing.T) {
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

	c := stellarexpert.New(srv.URL)
	client := srv.Client()
	client.Timeout = 200 * time.Millisecond
	c.HTTP = client

	start := time.Now()
	if _, err := c.Directory(context.Background(), address); err == nil {
		t.Fatal("a slow-drip response was reported as a successful lookup")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("slow-drip response was not bounded by the timeout: took %s", elapsed)
	}
}
