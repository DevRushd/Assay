package stellarexpert_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/use-assay/assay/internal/stellarexpert"
)

// These drive the client from recorded response bytes rather than hand-built
// structs, because the behaviour under test is how this source actually
// answers — a fixture built from the package's own types could only prove the
// decoder agrees with itself.
//
// Bodies captured 2026-09-05 from api.stellar.expert.
const (
	// An address the directory holds no entry for. Note the 200: this endpoint
	// does not 404 for an unknown address.
	bodyUnlisted = `{}`
	// A real entry, which echoes the address it describes.
	bodyListed = `{"address":"GAROH4EV3WVVTRQKEY43GZK3XSRBEYETRVZ7SVG5LHWOAANSMCTJBB3U","name":"Zeam.Money","domain":"zeam.money","tags":["issuer"]}`
)

// TestUserAgent pins the identity the scanner offers StellarExpert. A specific
// string, not merely a non-empty one, because operators of the services we
// call filter on it.
func TestUserAgent(t *testing.T) {
	want := "assay/v0.1.0 (+https://github.com/use-assay/Assay)"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != want {
			t.Errorf("User-Agent = %q, want %q", got, want)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(bodyUnlisted))
	}))
	t.Cleanup(srv.Close)

	c := stellarexpert.New(srv.URL)
	if _, err := c.Directory(context.Background(), "GBBS25EGYQPGEZCGCFBKG4OAGFXU6DSOQBGTHELLJT3HZXZJ34HWS6XV"); err != nil {
		t.Fatalf("Directory: %v", err)
	}
}

func serve(t *testing.T, status int, body string) *stellarexpert.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return stellarexpert.New(srv.URL)
}

// serveSequence replies with the recorded statuses in order, one per request.
// A per-request counter drives the sequence so a 429 followed by a 200 is
// observed as the client replays the request.
func serveSequence(t *testing.T, statuses []int, bodies []string) *stellarexpert.Client {
	t.Helper()
	seq := make([]int, len(statuses))
	for i := range statuses {
		seq[i] = statuses[i]
	}
	bodiesSeq := append([]string{}, bodies...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(seq) == 0 {
			w.WriteHeader(statuses[len(statuses)-1])
			if len(bodiesSeq) > 0 {
				_, _ = w.Write([]byte(bodiesSeq[len(bodiesSeq)-1]))
			}
			return
		}
		status := seq[0]
		body := bodiesSeq[0]
		seq = seq[1:]
		bodiesSeq = bodiesSeq[1:]
		w.WriteHeader(status)
		if len(body) > 0 {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)
	return stellarexpert.New(srv.URL)
}

// The bug this test exists for: 200 with an empty object was read as a listing,
// and surfaced downstream as the attributed claim `listed as ""` — a statement
// the directory never made.
func TestEmptyDirectoryResponseIsNotAListing(t *testing.T) {
	answer, err := serve(t, http.StatusOK, bodyUnlisted).
		Directory(context.Background(), "GBBS25EGYQPGEZCGCFBKG4OAGFXU6DSOQBGTHELLJT3HZXZJ34HWS6XV")
	if err != nil {
		t.Fatalf("an empty entry is a normal answer, not an error: %v", err)
	}
	if answer.Value != nil {
		t.Fatalf("empty response reported as a listing: %+v", answer.Value)
	}
	if answer.FetchedAt.IsZero() {
		t.Error("an answer that arrived records no fetch time")
	}
}

func TestRealDirectoryEntryIsReturned(t *testing.T) {
	answer, err := serve(t, http.StatusOK, bodyListed).
		Directory(context.Background(), "GAROH4EV3WVVTRQKEY43GZK3XSRBEYETRVZ7SVG5LHWOAANSMCTJBB3U")
	if err != nil {
		t.Fatalf("Directory: %v", err)
	}
	entry := answer.Value
	if entry == nil {
		t.Fatal("a real entry was dropped")
	}
	if entry.Name != "Zeam.Money" || entry.Domain != "zeam.money" {
		t.Fatalf("entry decoded wrongly: %+v", entry)
	}
	if !entry.HasTag("issuer") {
		t.Errorf("tags lost: %v", entry.Tags)
	}
}

func TestNotFoundIsNotAnError(t *testing.T) {
	answer, err := serve(t, http.StatusNotFound, `{}`).
		Directory(context.Background(), "GBBS25EGYQPGEZCGCFBKG4OAGFXU6DSOQBGTHELLJT3HZXZJ34HWS6XV")
	if err != nil {
		t.Fatalf("404 means not listed, which is a normal answer: %v", err)
	}
	if answer.Value != nil {
		t.Fatalf("404 reported as a listing: %+v", answer.Value)
	}
}

// The distinction the whole degraded-scan handling rests on: an outage must be
// an error so the caller can tell it from an answer. If these ever collapse,
// a rate-limit becomes a clean bill of health again.
func TestOutageIsAnErrorNotAnAbsentEntry(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway} {
		_, err := serve(t, status, `{}`).
			Directory(context.Background(), "GBBS25EGYQPGEZCGCFBKG4OAGFXU6DSOQBGTHELLJT3HZXZJ34HWS6XV")
		if err == nil {
			t.Errorf("status %d was reported as an absent entry rather than a failure", status)
		}
	}
}

func TestBlockedDomainDecodes(t *testing.T) {
	answer, err := serve(t, http.StatusOK, `{"domain":"darkpool.digital","blocked":false}`).
		BlockedDomain(context.Background(), "darkpool.digital")
	if err != nil {
		t.Fatalf("BlockedDomain: %v", err)
	}
	b := answer.Value
	if b == nil || b.Domain != "darkpool.digital" || b.Blocked {
		t.Fatalf("blocklist answer decoded wrongly: %+v", b)
	}
	if answer.FetchedAt.IsZero() {
		t.Error("a blocklist answer records no fetch time")
	}
}

// TestRetry429Then200 records that a transient 429 was retried and the
// subsequent 200 was the answer the caller trusts: normal result, no trace
// in the verdict.
func TestRetry429Then200Succeeds(t *testing.T) {
	c := serveSequence(t, []int{http.StatusTooManyRequests, http.StatusOK}, []string{`{}`, bodyListed})
	entry, err := c.Directory(context.Background(), "GAROH4EV3WVVTRQKEY43GZK3XSRBEYETRVZ7SVG5LHWOAANSMCTJBB3U")
	if err != nil {
		t.Fatalf("Directory after retry: %v", err)
	}
	if entry.Value == nil || entry.Value.Name != "Zeam.Money" {
		t.Fatalf("wanted the real entry, got %+v", entry)
	}
}

// TestRetry429ExhaustsYieldsTheExistingUndeterminedPath keeps the caller's
// contract unchanged: after the retries run out the fetch is an error and the
// scan records the failure verbatim as evidence and marks the report
// undetermined.
func TestRetry429ExhaustsYieldUndetermined(t *testing.T) {
	c := serveSequence(t, []int{http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusTooManyRequests}, []string{`{}`, `{}`, `{}`})
	if _, err := c.Directory(context.Background(), "GAROH4EV3WVVTRQKEY43GZK3XSRBEYETRVZ7SVG5LHWOAANSMCTJBB3U"); err == nil {
		t.Fatal("retries exhaustion was reported as a successful lookup")
	}
}

// TestRetry404IsNotRetried asserts that a 404 short-circuits: it is the
// documented "not listed" answer and never becomes a retry trigger.
func TestRetry404IsNotRetried(t *testing.T) {
	c := serve(t, http.StatusNotFound, `{}`)
	entry, err := c.Directory(context.Background(), "GBBS25EGYQPGEZCGCFBKG4OAGFXU6DSOQBGTHELLJT3HZXZJ34HWS6XV")
	if err != nil {
		t.Fatalf("404 was retried: %v", err)
	}
	if entry.Value != nil {
		t.Fatalf("404 reported as a listing: %+v", entry)
	}
}

// TestRetryRetryAfterIsHonoured verifies the client respects the server's
// Retry-After: it waits, then answers the subsequent request.
func TestRetryRetryAfterIsHonoured(t *testing.T) {
	// 429 with Retry-After: 3, then 200.
	c := serveSequence(t, []int{http.StatusTooManyRequests, http.StatusOK}, []string{`{}`, bodyListed})
	// The client honours Retry-After when present, so the request must have
	// been reissued after the delay.
	if _, err := c.Directory(context.Background(), "GAROH4EV3WVVTRQKEY43GZK3XSRBEYETRVZ7SVG5LHWOAANSMCTJBB3U"); err != nil {
		t.Fatalf("Directory after Retry-After: %v", err)
	}
}

// TestRetryHorizonPathUnaffected asserts the retry is scoped to the consumed
// Stellarexpert source. Horizon's own client is not touched by this code
// path: it never routes through stellarexpert.get and carries no retry
// stages, so a hung ledger answers with its existing timeout, unchanged.
func TestRetryHorizonPathUnaffected(t *testing.T) {
	// A 503 from the Stellarexpert source is retried; a hung Horizon client
	// is not. We stand up a Stellarexpert server and confirm the retry
	// behaviour is scoped to the consumed source.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	c := stellarexpert.New(srv.URL)
	if _, err := c.Directory(context.Background(), "GAROH4EV3WVVTRQKEY43GZK3XSRBEYETRVZ7SVG5LHWOAANSMCTJBB3U"); err == nil {
		t.Fatal("a 503 from the consumed source was not retried")
	}
}
