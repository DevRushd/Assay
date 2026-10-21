package api

import (
	"sync"
	"time"
)

// RateLimiter is a per-client token bucket.
//
// Assay's upstreams are shared public infrastructure (Horizon, StellarExpert),
// and the caching philosophy in docs/caching.md exists because degrading those
// fetches degrades every scan at once. An inbound limiter protects the same
// resources from the other side: it refuses a caller before the request
// becomes N upstream fetches, rather than after. It answers with a retry
// time, never with a fabricated result — a refused request is an error the
// caller can schedule around, not an answer it might believe.
//
// Buckets are keyed by client address and refilled continuously at a fixed
// rate with a bounded burst, so one client cannot starve another: each key
// carries its own allowance and idles out of memory when unused.
type RateLimiter struct {
	mu    sync.Mutex
	burst float64
	rate  float64 // tokens per second
	// now is the clock, overridable so a test can drive refill without
	// sleeping.
	now func() time.Time

	clients map[string]*limiterBucket
}

// limiterBucket is one client's allowance: its token count and the time the
// count was last advanced.
type limiterBucket struct {
	tokens float64
	last   time.Time
}

// limiterIdleEvict is how long a client's bucket may go unused before it is
// dropped, and limiterMaxClients is the hard cap on tracked buckets. Together
// they bound the limiter's own memory: a flood of distinct addresses evicts
// stale ones instead of growing the map without limit.
const (
	limiterIdleEvict  = 10 * time.Minute
	limiterMaxClients = 4096
)

// NewRateLimiter returns a limiter allowing a burst of burst requests and
// perSecond requests per second thereafter.
func NewRateLimiter(burst int, perSecond float64) *RateLimiter {
	return &RateLimiter{
		burst:   float64(burst),
		rate:    perSecond,
		now:     time.Now,
		clients: make(map[string]*limiterBucket),
	}
}

// Allow reports whether a request from key may proceed now, and how long the
// caller should wait before the next token exists when it may not.
func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.clients[key]
	if !ok {
		l.evictIdleLocked(now)
		b = &limiterBucket{tokens: l.burst, last: now}
		l.clients[key] = b
	}
	// Refill for the time that passed since the bucket was last advanced,
	// capped at the burst so idleness buys at most one burst, not infinity.
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	// The request would consume a token that does not exist; the wait is the
	// time until one accrues, rounded up to a whole second for Retry-After.
	wait := time.Duration((1-b.tokens)/l.rate*float64(time.Second)) + time.Second
	return false, wait
}

// evictIdleLocked drops buckets that have not been used recently and, when a
// flood of distinct keys has filled the table anyway, the oldest ones first.
// Callers must hold l.mu.
func (l *RateLimiter) evictIdleLocked(now time.Time) {
	if len(l.clients) < limiterMaxClients {
		for key, b := range l.clients {
			if now.Sub(b.last) > limiterIdleEvict {
				delete(l.clients, key)
			}
		}
		return
	}
	// Over the cap: evict every idle-expired bucket, then if still over,
	// drop buckets wholesale until under the cap. Which bucket is dropped
	// next is map order — arbitrary but safe: a dropped bucket restarts at a
	// full burst only when its client asks again, and the cap exists so that
	// asking in a flood is exactly what does not keep state around.
	for key, b := range l.clients {
		if now.Sub(b.last) > limiterIdleEvict {
			delete(l.clients, key)
		}
	}
	for key := range l.clients {
		if len(l.clients) <= limiterMaxClients {
			break
		}
		delete(l.clients, key)
	}
}
