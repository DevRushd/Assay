package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/api"
)

// newProbeServer returns a Server whose scanner is wired to the given stub
// upstream roots, plus the handler. Passing nil roots leaves the scanner's
// clients at their production defaults; a test that does that must not let the
// prober run a real round.
func newProbeServer(horizonRoot, expertRoot string) (*api.Server, http.Handler) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := api.NewServer(log)
	srv.Scanner.Horizon.BaseURL = horizonRoot
	srv.Scanner.Expert.BaseURL = expertRoot
	return srv, srv.Handler()
}

// probeClock is a controllable clock for cache tests.
type probeClock struct {
	mu   sync.Mutex
	now  time.Time
	hits int
}

func newProbeClock(start time.Time) *probeClock { return &probeClock{now: start} }

func (c *probeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits++
	return c.now
}

func (c *probeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// upstreamStub is one stub upstream: it counts requests and can be made to
// fail, hang, or return any status.
type upstreamStub struct {
	status atomic.Int32 // 0 means 200
	mu     sync.Mutex
	calls  int
}

func newUpstreamStub() *upstreamStub { return &upstreamStub{} }

func (s *upstreamStub) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *upstreamStub) FailWith(status int32) { s.status.Store(status) }

func (s *upstreamStub) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if status := s.status.Load(); status != 0 {
		w.WriteHeader(int(status))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// readyBody is the decoded /readyz response.
type readyBody struct {
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	AgeSecs   int64  `json:"age_secs"`
	Upstreams []struct {
		Name       string `json:"name"`
		Kind       string `json:"kind"`
		Reachable  bool   `json:"reachable"`
		ProbeError string `json:"probe_error"`
		ProbeURL   string `json:"probe_url"`
	} `json:"upstreams"`
}

func getReadyz(h http.Handler) (*httptest.ResponseRecorder, readyBody) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	var body readyBody
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func upstreamNamed(t *testing.T, body readyBody, name string) (kind string, reachable bool, probeErr string) {
	t.Helper()
	for _, u := range body.Upstreams {
		if u.Name == name {
			return u.Kind, u.Reachable, u.ProbeError
		}
	}
	t.Fatalf("no upstream named %q in %+v", name, body.Upstreams)
	return "", false, ""
}

// TestHealthzStaysStaticLiveness pins that /healthz checks nothing: it must
// answer 200 even with both upstreams pointing at servers that refuse every
// request. Liveness is "the process is up", not "the world is fine".
func TestHealthzStaysStaticLiveness(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer dead.Close()

	srv, h := newProbeServer(dead.URL, dead.URL)
	// The prober is left nil here on purpose: /healthz must not touch it.

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "ok" {
		t.Fatalf("body = %q, want \"ok\"", got)
	}
	if srv == nil {
		t.Fatal("unreachable")
	}
}

// TestReadyzAllUpstreamsReachable covers the valid state: both checkable
// upstreams answer, so readiness is ready and both report reachable.
func TestReadyzAllUpstreamsReachable(t *testing.T) {
	horizon := newUpstreamStub()
	expert := newUpstreamStub()
	hSrv := httptest.NewServer(horizon)
	defer hSrv.Close()
	eSrv := httptest.NewServer(expert)
	defer eSrv.Close()

	_, h := newProbeServer(hSrv.URL, eSrv.URL)
	rec, body := getReadyz(h)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body.Status != "ready" {
		t.Fatalf("status = %q, want ready", body.Status)
	}
	if len(body.Upstreams) != 2 {
		t.Fatalf("reported %d upstreams, want 2", len(body.Upstreams))
	}
	for _, u := range body.Upstreams {
		if !u.Reachable {
			t.Errorf("%s: reachable = false, want true (probe_error %q)", u.Name, u.ProbeError)
		}
	}
	if horizon.Calls() != 1 || expert.Calls() != 1 {
		t.Fatalf("upstream calls = horizon %d, expert %d, want 1 each", horizon.Calls(), expert.Calls())
	}
}

// TestReadyzConsumedSourceDown covers the unavailable-but-servable state: with
// StellarExpert unreachable, readiness is degraded, the Horizon entry still
// reports reachable, and the failure is reported per source.
func TestReadyzConsumedSourceDown(t *testing.T) {
	horizon := newUpstreamStub()
	expert := newUpstreamStub()
	hSrv := httptest.NewServer(horizon)
	defer hSrv.Close()
	eSrv := httptest.NewServer(expert)

	_, h := newProbeServer(hSrv.URL, eSrv.URL)
	expert.FailWith(http.StatusServiceUnavailable)

	rec, body := getReadyz(h)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if body.Status != "degraded" {
		t.Fatalf("status = %q, want degraded", body.Status)
	}
	_, hOK, _ := upstreamNamed(t, body, "horizon")
	if !hOK {
		t.Error("horizon reported unreachable; only the consumed source is down")
	}
	_, eOK, eErr := upstreamNamed(t, body, "stellar.expert/directory")
	if eOK {
		t.Error("stellar.expert reported reachable; the stub returns 503")
	}
	if eErr == "" {
		t.Error("probe_error empty; a failing probe must say why")
	}
	if body.Reason == "" {
		t.Error("reason empty for a degraded answer; a consumer must be able to tell why")
	}
}

// TestReadyzHorizonDown covers the invalid state: with Horizon unreachable,
// readiness is unavailable — a materially different state from a consumed
// source being down.
func TestReadyzHorizonDown(t *testing.T) {
	horizon := newUpstreamStub()
	expert := newUpstreamStub()
	hSrv := httptest.NewServer(horizon)
	defer hSrv.Close()
	eSrv := httptest.NewServer(expert)

	_, h := newProbeServer(hSrv.URL, eSrv.URL)
	horizon.FailWith(http.StatusBadGateway)
	expert.FailWith(http.StatusServiceUnavailable)

	rec, body := getReadyz(h)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if body.Status != "unavailable" {
		t.Fatalf("status = %q, want unavailable", body.Status)
	}
	_, hOK, hErr := upstreamNamed(t, body, "horizon")
	if hOK {
		t.Error("horizon reported reachable; the stub returns 502")
	}
	if hErr == "" {
		t.Error("probe_error empty for horizon")
	}
	// Both down at once still names the worse state: unavailable wins, and
	// the per-source entries carry the detail.
	_, eOK, _ := upstreamNamed(t, body, "stellar.expert/directory")
	if eOK {
		t.Error("stellar.expert reported reachable")
	}
} // TestReadyzTransportFailureIsNeverHealthy covers probe failure at the
// transport level: a server that hangs past the probe budget yields a
// deadline-exceeded error per source and never a ready answer.
func TestReadyzTransportFailureIsNeverHealthy(t *testing.T) {
	// The handler outlasts the probe budget; it watches the request context
	// so it returns as soon as the probe client gives up instead of keeping
	// the test server busy.
	horizon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(30 * time.Second):
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer horizon.Close()
	eSrv := httptest.NewServer(newUpstreamStub())
	defer eSrv.Close()

	srv, h := newProbeServer(horizon.URL, eSrv.URL)
	prober := api.NewHealthProber(srv)
	// Keep the test fast: the probe budget is production's 3s, the test's is
	// well under a second.
	prober.HTTP = &http.Client{Timeout: 100 * time.Millisecond}
	srv.Health = prober

	rec, body := getReadyz(h)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if body.Status != "unavailable" {
		t.Fatalf("status = %q, want unavailable; a failing probe must never report healthy", body.Status)
	}
	_, _, hErr := upstreamNamed(t, body, "horizon")
	if hErr == "" {
		t.Error("probe_error empty; the timeout must be reported verbatim")
	}
}

// TestReadyzCoalescesAndCaches covers the no-load-on-third-parties criteria:
// repeated scraping within the TTL produces one probe round, and the cached
// answer's age is reported honestly.
func TestReadyzCoalescesAndCaches(t *testing.T) {
	horizon := newUpstreamStub()
	expert := newUpstreamStub()
	hSrv := httptest.NewServer(horizon)
	defer hSrv.Close()
	eSrv := httptest.NewServer(expert)

	srv, _ := newProbeServer(hSrv.URL, eSrv.URL)
	prober := api.NewHealthProber(srv)
	start := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	clock := newProbeClock(start)
	prober.Now = clock.Now
	srv.Health = prober

	h := srv.Handler()

	rec1, body1 := getReadyz(h)
	if body1.Status != "ready" || rec1.Code != http.StatusOK {
		t.Fatalf("first probe: status %d %q, want 200 ready", rec1.Code, body1.Status)
	}
	firstChecked := body1.Upstreams

	// Scrape repeatedly while the clock stands still: every answer comes from
	// the cache, no upstream sees another request.
	for i := 0; i < 5; i++ {
		rec, body := getReadyz(h)
		if body.Status != "ready" || rec.Code != http.StatusOK {
			t.Fatalf("cached probe %d: status %d %q", i, rec.Code, body.Status)
		}
	}

	// Age is reported honestly as the clock moves inside the TTL.
	clock.Advance(20 * time.Second)
	_, body := getReadyz(h)
	if body.AgeSecs != 20 {
		t.Fatalf("age_secs = %d, want 20", body.AgeSecs)
	}

	// And the cached answer is still the same round's answer.
	if len(body.Upstreams) != len(firstChecked) {
		t.Fatalf("cached answer changed shape: %d vs %d", len(body.Upstreams), len(firstChecked))
	}

	if horizon.Calls() != 1 || expert.Calls() != 1 {
		t.Fatalf("upstream calls = horizon %d, expert %d, want 1 each across 7 requests", horizon.Calls(), expert.Calls())
	}
}

// TestReadyzRateLimitFloorsRealProbes covers MinInterval: past the cache TTL
// but inside the rate-limit window, the stale cached answer is served rather
// than a new round run — and age_secs admits the staleness.
func TestReadyzRateLimitFloorsRealProbes(t *testing.T) {
	horizon := newUpstreamStub()
	expert := newUpstreamStub()
	hSrv := httptest.NewServer(horizon)
	defer hSrv.Close()
	eSrv := httptest.NewServer(expert)

	srv, _ := newProbeServer(hSrv.URL, eSrv.URL)
	prober := api.NewHealthProber(srv)
	// TTL shorter than the min interval: between the two, the min interval
	// decides, which is the rate-limit property under test.
	prober.CacheTTL = time.Second
	prober.MinInterval = time.Minute
	start := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	clock := newProbeClock(start)
	prober.Now = clock.Now
	srv.Health = prober

	h := srv.Handler()

	if _, body := getReadyz(h); body.Status != "ready" {
		t.Fatalf("first probe: %q", body.Status)
	}

	clock.Advance(30 * time.Second) // past the TTL, inside the min interval
	rec, body := getReadyz(h)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; the rate-limited answer is still a completed round", rec.Code)
	}
	if body.Status != "ready" {
		t.Fatalf("status = %q, want ready", body.Status)
	}
	if body.AgeSecs != 30 {
		t.Fatalf("age_secs = %d, want 30", body.AgeSecs)
	}

	if horizon.Calls() != 1 {
		t.Fatalf("horizon calls = %d, want 1: the rate limit must floor real probes", horizon.Calls())
	}
}

// TestReadyzConcurrentScrapesCoalesce covers the coalescing property under
// real concurrency: many simultaneous /readyz calls produce one probe round.
func TestReadyzConcurrentScrapesCoalesce(t *testing.T) {
	horizon := newUpstreamStub()
	expert := newUpstreamStub()
	// The stub delays each answer briefly so the concurrent scrapers overlap
	// inside one round instead of serializing into several.
	slow := http.NewServeMux()
	slow.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		horizon.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	}))
	hSrv := httptest.NewServer(slow)
	defer hSrv.Close()
	eSrv := httptest.NewServer(expert)
	defer eSrv.Close()

	srv, _ := newProbeServer(hSrv.URL, eSrv.URL)
	prober := api.NewHealthProber(srv)
	srv.Health = prober
	h := srv.Handler()

	const scrapers = 8
	var wg sync.WaitGroup
	statuses := make([]string, scrapers)
	for i := 0; i < scrapers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, body := getReadyz(h)
			statuses[i] = body.Status
		}(i)
	}
	wg.Wait()

	for i, st := range statuses {
		if st != "ready" {
			t.Errorf("scraper %d got %q, want ready", i, st)
		}
	}
	if horizon.Calls() != 1 {
		t.Fatalf("horizon calls = %d, want 1: concurrent scrapes must coalesce", horizon.Calls())
	}
	if expert.Calls() != 1 {
		t.Fatalf("expert calls = %d, want 1", expert.Calls())
	}
}

// TestReadyzCancelledProbeIsUnknown covers the unknown state: a caller whose
// context ends mid-round is reported unknown, never healthy, and the
// cancelled round leaves no cached answer behind.
func TestReadyzCancelledProbeIsUnknown(t *testing.T) {
	// The stub holds each probe until released or until the request context
	// ends, so the server never waits on a leaked handler at cleanup.
	release := make(chan struct{})
	horizon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer horizon.Close()
	eSrv := httptest.NewServer(newUpstreamStub())
	defer eSrv.Close()

	srv, _ := newProbeServer(horizon.URL, eSrv.URL)
	prober := api.NewHealthProber(srv)
	srv.Health = prober
	h := srv.Handler()

	ctx, cancel := context.WithCancel(context.Background())

	// Leader: blocked inside the round by the stub.
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		rec, body := getReadyzWithCtx(h, ctx)
		if body.Status != "unknown" {
			t.Errorf("leader: status = %q, want unknown", body.Status)
		}
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("leader: HTTP status = %d, want 503", rec.Code)
		}
	}()
	// Give the leader time to start the round, then cancel it.
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-leaderDone

	// Release the stub so the next round answers, and confirm the cancelled
	// round left nothing cached: this caller runs a fresh round.
	close(release)
	_, body := getReadyz(h)
	if body.Status != "ready" {
		t.Fatalf("post-cancel probe: %q, want ready from a fresh round", body.Status)
	}
}

// getReadyzWithCtx issues /readyz with a caller-supplied context.
func getReadyzWithCtx(h http.Handler, ctx context.Context) (*httptest.ResponseRecorder, readyBody) {
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body readyBody
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}
