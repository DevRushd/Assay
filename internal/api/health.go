package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Everything in this file answers one question — "can Assay do its job right
// now?" — and reports it per upstream rather than as one number.
//
// /healthz stays a static liveness endpoint: the process is up. /readyz is the
// readiness endpoint and actually asks the upstreams. The two are kept
// separate because a failing probe must never report healthy, while a dying
// process must still be able to say so.

// The states /readyz can report. They mirror the vocabulary
// docs/transitions.md uses for observations, applied to the server itself.
const (
	// readyStateReady means every checkable upstream answered within its
	// probe budget. Assay can classify assets.
	readyStateReady = "ready"
	// readyStateDegraded means at least one consumed upstream is unreachable.
	// Scans still serve, and each source's status is reported so the consumer
	// can judge what a verdict is missing. The reputation axis is the one
	// that goes undetermined first, and this state is how a StellarExpert
	// outage is told apart from a Horizon outage.
	readyStateDegraded = "degraded"
	// readyStateUnavailable means Horizon is unreachable. Every scan begins
	// with the ledger, so there is no classification to make and the server
	// is not ready in any sense a load balancer should use.
	readyStateUnavailable = "unavailable"
	// readyStateUnknown means the probe itself could not be observed to
	// succeed or fail — the request ended mid-round, or a joined round
	// produced nothing usable. It is reported as unknown, never as healthy.
	readyStateUnknown = "unknown"
)

// readyzTimeout bounds a single upstream probe. It stays well under the
// clients' own request timeouts so /readyz answers before a caller's probe
// interval gives up on it.
const readyzTimeout = 3 * time.Second

// defaultCacheTTL is how long a completed readiness answer is served as-is.
// Health checking must not itself become load on third parties: a scraper
// hitting /readyz every second would otherwise turn into a request per second
// against every upstream. Within the TTL the cached answer is served
// verbatim, failures included, and age_secs carries the honest staleness.
const defaultCacheTTL = 30 * time.Second

// defaultMinInterval is the floor on how often a real upstream round trip may
// happen, independent of the cache TTL. It rate-limits the probes: no matter
// how the endpoint is scraped or what TTL a caller configures, an upstream
// sees at most one probe round per this interval. When a caller asks inside
// the window and a cached answer exists, the cached answer is served even if
// past its TTL — age_secs admits the staleness.
const defaultMinInterval = 10 * time.Second

// probeUserAgent is how the prober identifies itself. Health checking must be
// distinguishable from scanning in every upstream's logs.
const probeUserAgent = "assay-healthcheck/1.0"

// probeMaxBody caps a probe response read. A probe is a reachability check,
// not a data fetch, so this is deliberately small.
const probeMaxBody = 1 << 12 // 4 KiB

// The two upstream kinds. A third-party outage of a consumed source must not
// look the same as the ledger being gone, because one means "verdicts miss
// one axis" and the other means "there are no verdicts".
const (
	kindHorizon  = "horizon"
	kindConsumed = "consumed"
)

// upstream is one third-party source /readyz reports on.
type upstream struct {
	// Name is the identifier the report uses, matching the Source labels the
	// evidence already carries ("horizon", "stellar.expert/*").
	Name string
	// Kind separates the two failure modes: kindHorizon down is an invalid
	// state (unavailable); kindConsumed down is a degraded state (scans still
	// serve, reputation undetermined).
	Kind string
	// ProbeURL is the documented, read-only endpoint the reachability probe
	// hits. Probing the API root rather than a data endpoint keeps the probe
	// off the data paths and costs the source the minimum it can answer.
	ProbeURL string
}

// probeEndpoints returns the reachability probes for the production upstreams,
// derived from the clients the server is actually wired to, so the readiness
// report describes the same hosts scans use.
//
// Only checkable upstreams appear here. Arbitrary issuer domains (the
// stellar.toml targets) cannot be probed: the host depends on the asset being
// scanned, there is no single endpoint that stands for all of them, and
// probing a curated list of domains would move the blocklist problem into the
// health checker. Their reachability is already attributed per scan in the
// evidence a report carries.
func probeEndpoints(s *Server) []upstream {
	var ups []upstream
	if s.Scanner != nil {
		if s.Scanner.Horizon != nil {
			ups = append(ups, upstream{
				Name:     "horizon",
				Kind:     kindHorizon,
				ProbeURL: s.Scanner.Horizon.BaseURL,
			})
		}
		if s.Scanner.Expert != nil {
			ups = append(ups, upstream{
				Name:     "stellar.expert/directory",
				Kind:     kindConsumed,
				ProbeURL: s.Scanner.Expert.BaseURL,
			})
		}
	}
	return ups
}

// HealthProber reports per-upstream reachability for /readyz.
//
// It is a struct rather than a constructor-return value so a caller can swap
// the HTTP client (tests) or the intervals (an operator who wants fresher
// answers) without a factory. The zero value is not usable; build one with
// NewHealthProber.
type HealthProber struct {
	// HTTP sends the probes. Nil means net/http's default transport.
	HTTP *http.Client
	// CacheTTL is how long a completed readiness answer is served as-is.
	// Zero selects defaultCacheTTL.
	CacheTTL time.Duration
	// MinInterval is the floor on real upstream round trips. Zero selects
	// defaultMinInterval.
	MinInterval time.Duration
	// Now, when set, overrides the clock. Tests use it; production leaves it
	// nil.
	Now func() time.Time

	// upstreams is the set of upstreams this prober reports on, captured when
	// the prober is built.
	upstreams []upstream

	mu      sync.Mutex
	last    time.Time  // start of the most recent real probe round
	cached  *Readiness // the most recent completed round
	running *probeFlight
}

// probeFlight is one in-flight probe round. Waiters join the leader instead
// of starting their own round, so concurrent scrapers coalesce into a single
// set of upstream requests.
type probeFlight struct {
	done chan struct{}
}

// NewHealthProber returns a prober wired to the same upstreams the server's
// scanner reads from.
func NewHealthProber(s *Server) *HealthProber {
	return &HealthProber{upstreams: probeEndpoints(s)}
}

// now is the prober's clock, overridable in tests.
func (p *HealthProber) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Readiness is the body of GET /readyz.
//
// The states are deliberately coarse; the per-upstream detail is where an
// operator reads why. No status here can report healthy on a failing probe:
// a probe error is a per-source error field and moves the status to degraded,
// unavailable, or unknown — never ready.
type Readiness struct {
	Status string `json:"status"`
	// Reason names what moved the status when it is not ready. Omitted when
	// every checkable upstream answered.
	Reason string `json:"reason,omitempty"`
	// CheckedAt is when the reported round actually ran, which may be older
	// than this request if the answer came from the cache.
	CheckedAt time.Time `json:"checked_at"`
	// AgeSecs is how old the reported round is. Within the cache window this
	// is the honest staleness of the answer a consumer is reading.
	AgeSecs int64 `json:"age_secs"`
	// Upstreams reports one entry per checkable source, in the fixed order
	// the prober was built with, so a diff between two answers is stable.
	Upstreams []UpstreamStatus `json:"upstreams"`
}

// UpstreamStatus is one source's reachability as the readiness round measured
// it. Measured, not assumed: a source that was not probed in this round
// reports ProbeError, and nothing here is derived from a scan or from a prior
// round's success.
type UpstreamStatus struct {
	Name string `json:"name"`
	// Kind is "horizon" or "consumed", the distinction the readiness status
	// is computed from: horizon down is unavailable; a consumed source down
	// is degraded with scans still serving.
	Kind string `json:"kind"`
	// Reachable reports whether the probe round trip succeeded within the
	// probe budget.
	Reachable bool `json:"reachable"`
	// ProbeError carries the failure verbatim when Reachable is false, so an
	// operator can tell DNS failure from timeout from a refused connection
	// without this server having interpreted it.
	ProbeError string `json:"probe_error,omitempty"`
	// ProbeURL is the endpoint that was hit, so the probe is reproducible
	// from the report alone.
	ProbeURL string `json:"probe_url"`
}

// Run answers one readiness request.
//
// Semantics, per the issue:
//
//   - valid state — all checkable upstreams reachable: ready.
//   - unavailable state — a consumed source unreachable: degraded, reported
//     per source; Assay still serves scans, which will be undetermined on the
//     reputation axis.
//   - invalid state — Horizon unreachable: unavailable, a materially
//     different state, because scans cannot succeed at all.
//   - unknown state — the probe itself failing to be observed (a cancelled
//     request, an unobservable round) is reported as unknown, never as
//     healthy.
//
// The result is cached and concurrent callers coalesce into one round, so
// health checking does not itself generate load on third parties.
func (p *HealthProber) Run(ctx context.Context) Readiness {
	p.mu.Lock()

	ttl := p.CacheTTL
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	minInt := p.MinInterval
	if minInt <= 0 {
		minInt = defaultMinInterval
	}
	now := p.now()

	// Serve the cached answer while it is fresh, or while the rate limit says
	// a new round may not start yet (even if past its TTL; age_secs admits
	// the staleness). This is what keeps a scraped /readyz from turning into
	// load on third parties.
	if p.cached != nil && (now.Sub(p.last) < ttl || now.Sub(p.last) < minInt) {
		ans := *p.cached
		stampAge(&ans, now)
		p.mu.Unlock()
		return ans
	}

	// Coalesce: if a round is already running, wait for it rather than
	// starting a second one.
	if p.running != nil {
		flight := p.running
		p.mu.Unlock()
		select {
		case <-flight.done:
			// The leader stores the answer and closes done under the lock, so
			// by the time this waiter holds the lock the newest completed
			// round is either stored or was cancelled. Serve what is stored;
			// report unknown rather than fabricating a status.
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.cached != nil {
				ans := *p.cached
				stampAge(&ans, now)
				return ans
			}
			return unknownReadiness(now)
		case <-ctx.Done():
			// The caller gave up. Nothing is reported — in particular not
			// healthy. The next caller runs the round.
			return Readiness{Status: readyStateUnknown, CheckedAt: now}
		}
	}

	// This caller leads the round.
	flight := &probeFlight{done: make(chan struct{})}
	p.running = flight
	p.mu.Unlock()

	ans := p.probeAll(ctx, now)
	if ctx.Err() != nil {
		// The request ended before the round could be observed. A cancelled
		// round must not be read as upstreams being down, and its partial
		// answer must not be served or cached as readiness.
		p.mu.Lock()
		if flight == p.running {
			p.running = nil
		}
		close(flight.done)
		p.mu.Unlock()
		return unknownReadiness(now)
	}

	p.mu.Lock()
	if flight == p.running {
		p.running = nil
	}
	p.last = now
	p.cached = &ans
	close(flight.done)
	p.mu.Unlock()

	return ans
}

// stampAge sets AgeSecs from the prober's clock at serve time, clamped at
// zero so a skewed clock cannot print an age in the future.
func stampAge(ans *Readiness, now time.Time) {
	age := int64(now.Sub(ans.CheckedAt).Seconds())
	if age < 0 {
		age = 0
	}
	ans.AgeSecs = age
}

// probeAll performs one real probe round. It runs the probes concurrently so
// one slow upstream cannot stretch /readyz past every other caller's patience.
func (p *HealthProber) probeAll(ctx context.Context, now time.Time) Readiness {
	ups := p.upstreams
	results := make([]UpstreamStatus, len(ups))

	client := p.HTTP
	if client == nil {
		client = http.DefaultClient
	}

	var wg sync.WaitGroup
	for i, u := range ups {
		wg.Add(1)
		go func(i int, u upstream) {
			defer wg.Done()
			results[i] = p.probeOne(ctx, client, u)
		}(i, u)
	}
	wg.Wait()

	horizonDown := false
	consumedDown := false
	for _, r := range results {
		if r.Reachable {
			continue
		}
		switch r.Kind {
		case kindHorizon:
			horizonDown = true
		case kindConsumed:
			consumedDown = true
		}
	}

	ans := Readiness{
		CheckedAt: now,
		Upstreams: results,
	}
	switch {
	case horizonDown:
		ans.Status = readyStateUnavailable
		ans.Reason = "horizon is unreachable: scans cannot classify assets, so the server is not ready"
	case consumedDown:
		ans.Status = readyStateDegraded
		ans.Reason = "a consumed upstream is unreachable: scans are still served, but reputation evidence may be undetermined"
	default:
		ans.Status = readyStateReady
	}
	return ans
}

// probeOne probes a single upstream with its own timeout so a hanging source
// costs the round its budget, not more.
func (p *HealthProber) probeOne(ctx context.Context, client *http.Client, u upstream) UpstreamStatus {
	st := UpstreamStatus{
		Name:     u.Name,
		Kind:     u.Kind,
		ProbeURL: u.ProbeURL,
	}

	probeCtx, cancel := context.WithTimeout(ctx, readyzTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, u.ProbeURL, nil)
	if err != nil {
		st.ProbeError = err.Error()
		return st
	}
	req.Header.Set("User-Agent", probeUserAgent)

	// The probe measures whether the source can answer. A transport error or
	// a 5xx is a failed probe and is carried verbatim; it must never be read
	// as healthy. Anything below 500 — including a 3xx redirect or a 4xx —
	// is a host that answered, which is what reachability means here. A
	// consumed source answering 5xx degrades readiness per source rather
	// than failing the server, and a Horizon 5xx is the invalid state the
	// issue calls out: scans cannot succeed at all.
	resp, err := client.Do(req)
	if err != nil {
		st.ProbeError = err.Error()
		return st
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain a bounded amount so the connection is reusable without reading
	// an unbounded body.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, probeMaxBody))
	if resp.StatusCode >= http.StatusInternalServerError {
		st.ProbeError = fmt.Sprintf("status %d", resp.StatusCode)
		return st
	}
	st.Reachable = true
	return st
}

// unknownReadiness is the answer when a round could not be observed. It is
// never healthy.
func unknownReadiness(now time.Time) Readiness {
	return Readiness{
		Status:    readyStateUnknown,
		Reason:    "the readiness round could not be observed; reported as unknown rather than as healthy",
		CheckedAt: now,
	}
}

// handleReadyz serves GET /readyz: the per-upstream readiness check.
//
// The HTTP status code tracks the body's status so a load balancer or a
// `curl -f` can act on it without parsing JSON:
//
//	200 ready; 503 degraded (serving, missing an axis), unavailable, or
//	unknown.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	prober := s.Health
	if prober == nil {
		prober = NewHealthProber(s)
	}
	ans := prober.Run(r.Context())

	code := http.StatusOK
	if ans.Status != readyStateReady {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, ans)
}
