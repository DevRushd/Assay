package stellarexpert_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/stellarexpert"
)

// The acceptance criterion these tests exist for: a cached answer reports the
// time the SOURCE produced it, never the time the cache served it. Everything
// else here (hit, miss, expiry, bypass) is how that guarantee is exercised.
//
// The clock is driven by hand so expiry is arithmetic rather than a sleep.

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// countingExpert serves body for every request and counts requests, so a test
// can tell a cache hit from a re-fetch by what the server saw.
func countingExpert(t *testing.T, body string, opts stellarexpert.Options) (*stellarexpert.Client, *int64, *fakeClock) {
	t.Helper()
	var requests int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&requests, 1)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	clk := &fakeClock{now: t0}
	opts.Now = clk.Now
	return stellarexpert.NewWithOptions(srv.URL, opts), &requests, clk
}

var t0 = time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC)

const cacheAddress = "GBBS25EGYQPGEZCGCFBKG4OAGFXU6DSOQBGTHELLJT3HZXZJ34HWS6XV"

// secondAddress is a distinct issuer, used where a test needs two cache keys.
const secondAddress = "GAROH4EV3WVVTRQKEY43GZK3XSRBEYETRVZ7SVG5LHWOAANSMCTJBB3U"

// TestDefaultsMatchAdvertisedMaxAge pins the shipped default TTLs to the
// freshness budget StellarExpert actually advertises. The default is a claim
// about a third party's data, so it must not drift away from the citation in
// docs/caching.md without someone deliberately changing both.
func TestDefaultsMatchAdvertisedMaxAge(t *testing.T) {
	o := stellarexpert.DefaultOptions()
	if o.DirectoryTTL != stellarexpert.AdvertisedMaxAge {
		t.Errorf("DirectoryTTL = %s, want the advertised max-age %s",
			o.DirectoryTTL, stellarexpert.AdvertisedMaxAge)
	}
	if o.BlocklistTTL != stellarexpert.AdvertisedMaxAge {
		t.Errorf("BlocklistTTL = %s, want the advertised max-age %s",
			o.BlocklistTTL, stellarexpert.AdvertisedMaxAge)
	}
	if stellarexpert.AdvertisedMaxAge != 20*time.Second {
		t.Errorf("AdvertisedMaxAge = %s; if StellarExpert changed its Cache-Control, "+
			"update the header evidence in docs/caching.md too", stellarexpert.AdvertisedMaxAge)
	}
}

func TestCacheHitReusesAnswerAndKeepsFetchTime(t *testing.T) {
	c, requests, clk := countingExpert(t, bodyListed,
		stellarexpert.Options{DirectoryTTL: 30 * time.Minute})

	first, err := c.Directory(context.Background(), cacheAddress)
	if err != nil {
		t.Fatalf("first Directory: %v", err)
	}
	if first.FromCache {
		t.Error("the first lookup was reported as a cache hit")
	}
	if !first.FetchedAt.Equal(t0) {
		t.Fatalf("first FetchedAt = %s, want %s", first.FetchedAt, t0)
	}

	clk.Advance(time.Minute) // still inside the TTL, but later

	second, err := c.Directory(context.Background(), cacheAddress)
	if err != nil {
		t.Fatalf("second Directory: %v", err)
	}
	if !second.FromCache {
		t.Error("the second lookup did not use the cache")
	}
	if *requests != 1 {
		t.Errorf("server saw %d requests, want 1: the cache did not prevent a re-fetch", *requests)
	}
	// The guarantee, stated directly: the answer claims the fetch instant, not
	// the instant it was read out of the cache.
	if !second.FetchedAt.Equal(t0) {
		t.Errorf("cache hit FetchedAt = %s, want the original fetch time %s", second.FetchedAt, t0)
	}
	if !second.FetchedAt.Before(clk.Now()) {
		t.Errorf("cache hit FetchedAt (%s) is not older than the hit itself (%s); "+
			"a report built from this would imply the data is fresher than it is",
			second.FetchedAt, clk.Now())
	}
	if second.Value == nil || second.Value.Name != "Zeam.Money" {
		t.Errorf("cached value lost: %+v", second.Value)
	}
}

// Expiry is a re-fetch. The newly fetched answer must carry the NEWER fetch
// time, so a caller can see the data got fresher.
func TestExpiredAnswerIsRefetched(t *testing.T) {
	c, requests, clk := countingExpert(t, bodyListed,
		stellarexpert.Options{DirectoryTTL: 30 * time.Minute})

	if _, err := c.Directory(context.Background(), cacheAddress); err != nil {
		t.Fatalf("first Directory: %v", err)
	}

	clk.Advance(31 * time.Minute) // past the 30m directory TTL

	second, err := c.Directory(context.Background(), cacheAddress)
	if err != nil {
		t.Fatalf("second Directory: %v", err)
	}
	if second.FromCache {
		t.Error("an expired entry was served from cache")
	}
	if *requests != 2 {
		t.Errorf("server saw %d requests, want 2: an expired entry must be re-fetched", *requests)
	}
	if !second.FetchedAt.Equal(clk.Now()) {
		t.Errorf("re-fetched FetchedAt = %s, want the new fetch time %s", second.FetchedAt, clk.Now())
	}
}

// The stale-negative rule from the issue, as a test: a cached "not blocked"
// must not survive its TTL and mask a domain that has since been listed.
func TestExpiredNegativeIsNotServedAsAPositive(t *testing.T) {
	var requests int64
	var blocked atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&requests, 1)
		if blocked.Load() {
			_, _ = w.Write([]byte(`{"domain":"darkpool.digital","blocked":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"domain":"darkpool.digital","blocked":false}`))
	}))
	t.Cleanup(srv.Close)

	clk := &fakeClock{now: t0}
	c := stellarexpert.NewWithOptions(srv.URL, stellarexpert.Options{
		BlocklistTTL: 5 * time.Minute,
		Now:          clk.Now,
	})

	first, err := c.BlockedDomain(context.Background(), "darkpool.digital")
	if err != nil {
		t.Fatalf("first BlockedDomain: %v", err)
	}
	if first.Value == nil || first.Value.Blocked {
		t.Fatalf("expected a not-blocked answer first, got %+v", first.Value)
	}

	// Inside the TTL the negative is served, honestly stamped with its age.
	blocked.Store(true)
	inside, err := c.BlockedDomain(context.Background(), "darkpool.digital")
	if err != nil {
		t.Fatalf("inside-TTL BlockedDomain: %v", err)
	}
	if !inside.FromCache || inside.Value == nil || inside.Value.Blocked {
		t.Errorf("inside the TTL the cached negative should be served: %+v", inside)
	}
	if !inside.FetchedAt.Equal(t0) {
		t.Errorf("cached negative FetchedAt = %s, want %s", inside.FetchedAt, t0)
	}

	// Past the TTL the answer is re-fetched, and the new listing is seen.
	clk.Advance(6 * time.Minute)
	after, err := c.BlockedDomain(context.Background(), "darkpool.digital")
	if err != nil {
		t.Fatalf("after-TTL BlockedDomain: %v", err)
	}
	if after.FromCache {
		t.Error("an expired negative was served from cache")
	}
	if after.Value == nil || !after.Value.Blocked {
		t.Fatalf("a new blocklist entry was missed: %+v", after.Value)
	}
	if got := atomic.LoadInt64(&requests); got != 2 {
		t.Errorf("server saw %d requests, want 2 (miss, expiry)", got)
	}
}

// BypassCache is the per-request escape hatch: ask the source even though a
// live entry exists, and replace it with the fresh answer.
func TestBypassCacheForcesAFetch(t *testing.T) {
	body := bodyListed
	var requests int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&requests, 1)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	clk := &fakeClock{now: t0}
	c := stellarexpert.NewWithOptions(srv.URL, stellarexpert.Options{
		DirectoryTTL: 30 * time.Minute,
		Now:          clk.Now,
	})

	if _, err := c.Directory(context.Background(), cacheAddress); err != nil {
		t.Fatalf("first Directory: %v", err)
	}

	body = `{"address":"` + cacheAddress + `","name":"Renamed","domain":"zeam.money","tags":["issuer"]}`
	clk.Advance(time.Minute)

	fresh, err := c.Directory(context.Background(), cacheAddress, stellarexpert.BypassCache())
	if err != nil {
		t.Fatalf("bypass Directory: %v", err)
	}
	if fresh.FromCache {
		t.Error("BypassCache was served from cache")
	}
	if got := atomic.LoadInt64(&requests); got != 2 {
		t.Errorf("server saw %d requests, want 2: BypassCache must ask the source", got)
	}
	if !fresh.FetchedAt.Equal(clk.Now()) {
		t.Errorf("bypassed FetchedAt = %s, want the new fetch time %s", fresh.FetchedAt, clk.Now())
	}
	if fresh.Value == nil || fresh.Value.Name != "Renamed" {
		t.Fatalf("bypassed value wrong: %+v", fresh.Value)
	}

	// The fresh answer replaced the stale one, so the next normal lookup is a
	// hit on the NEW value and the NEW fetch time.
	next, err := c.Directory(context.Background(), cacheAddress)
	if err != nil {
		t.Fatalf("follow-up Directory: %v", err)
	}
	if !next.FromCache || next.Value == nil || next.Value.Name != "Renamed" {
		t.Errorf("the refreshed answer did not replace the cached one: %+v", next)
	}
	if got := atomic.LoadInt64(&requests); got != 2 {
		t.Errorf("server saw %d requests, want 2: the follow-up should have hit the cache", got)
	}
}

// An outage must never be cached. Caching a failure would keep serving it after
// the source recovered, which is exactly "an outage rendered as an answer".
func TestFailedFetchIsNotCached(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	var requests int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&requests, 1)
		if failing.Load() {
			http.Error(w, "boom", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(bodyListed))
	}))
	t.Cleanup(srv.Close)

	c := stellarexpert.NewWithOptions(srv.URL, stellarexpert.Options{DirectoryTTL: 30 * time.Minute})

	if _, err := c.Directory(context.Background(), cacheAddress); err == nil {
		t.Fatal("a 503 was reported as an answer")
	}

	failing.Store(false)
	answer, err := c.Directory(context.Background(), cacheAddress)
	if err != nil {
		t.Fatalf("Directory after recovery: %v", err)
	}
	if answer.FromCache {
		t.Error("a recovered source was answered from a cached outage")
	}
	if answer.Value == nil {
		t.Fatal("the recovered answer was dropped")
	}
	// The failing fetch is retried (DefaultRetryOptions().Attempts transient
	// attempts, issue #127), and the recovered fetch is a fresh request: the
	// outage was never cached, which is what this test is about.
	want := int64(stellarexpert.DefaultRetryOptions().Attempts) + 1
	if got := atomic.LoadInt64(&requests); got != want {
		t.Errorf("server saw %d requests, want %d: the failure was not re-fetched", got, want)
	}
}

// A zero TTL disarms the cache: every lookup asks the source, which is what a
// deployment opts into with -no-cache.
func TestZeroTTLDisablesCaching(t *testing.T) {
	c, requests, _ := countingExpert(t, bodyListed, stellarexpert.Options{DirectoryTTL: 0})
	for i := 0; i < 3; i++ {
		if _, err := c.Directory(context.Background(), cacheAddress); err != nil {
			t.Fatalf("Directory %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt64(requests); got != 3 {
		t.Errorf("server saw %d requests, want 3: a zero TTL must not cache", got)
	}
}

// Concurrency: the server shares one Client across requests, and `make test`
// runs with -race. Concurrent lookups of the same key must not corrupt the
// cache or double-report, whether they all miss or all hit.
func TestConcurrentLookupsAreRaceFree(t *testing.T) {
	c, requests, _ := countingExpert(t, bodyListed, stellarexpert.Options{DirectoryTTL: 30 * time.Minute})

	// Warm the cache so most goroutines take the hit path.
	if _, err := c.Directory(context.Background(), cacheAddress); err != nil {
		t.Fatalf("warm-up Directory: %v", err)
	}

	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				answer, err := c.Directory(context.Background(), cacheAddress)
				if err != nil {
					t.Errorf("concurrent Directory: %v", err)
					return
				}
				if answer.Value == nil || answer.Value.Name != "Zeam.Money" {
					t.Errorf("concurrent lookup got %+v", answer.Value)
					return
				}
			}
		}()
	}
	wg.Wait()

	// The warm-up plus at most one miss per concurrent goroutine; never one
	// request per lookup.
	if got := atomic.LoadInt64(requests); got > 17 {
		t.Errorf("server saw %d requests for 401 lookups; the cache is not collapsing repeats", got)
	}
}

// Distinct keys do not collide: two issuers served through the same cache are
// two independent answers.
func TestCacheKeysAreIndependent(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		_, _ = w.Write([]byte(`{"address":"` + issuerFromPath(r.URL.Path) +
			`","name":"X","domain":"x.test","tags":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := stellarexpert.NewWithOptions(srv.URL, stellarexpert.Options{DirectoryTTL: time.Hour})
	for _, addr := range []string{cacheAddress, secondAddress} {
		if _, err := c.Directory(context.Background(), addr); err != nil {
			t.Fatalf("Directory(%s): %v", addr, err)
		}
		if _, err := c.Directory(context.Background(), addr); err != nil {
			t.Fatalf("Directory(%s) again: %v", addr, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("expected two cache keys, saw %v", seen)
	}
	for path, n := range seen {
		if n != 1 {
			t.Errorf("%s fetched %d times, want 1", path, n)
		}
	}
}

func issuerFromPath(p string) string {
	const prefix = "/explorer/directory/"
	if len(p) > len(prefix) {
		return p[len(prefix):]
	}
	return strconv.Itoa(len(p))
}
