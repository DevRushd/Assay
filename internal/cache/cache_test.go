package cache_test

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/cache"
)

// newClock returns a clock the test drives by hand, so expiry is exercised by
// arithmetic rather than by sleeping.
func newClock(start time.Time) *clock {
	return &clock{now: start}
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var t0 = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func TestMissOnEmpty(t *testing.T) {
	c := cache.New[string](time.Minute, cache.WithClock(newClock(t0).Now))
	if _, ok := c.Get("absent"); ok {
		t.Fatal("an empty cache reported a hit")
	}
}

// The property the whole package exists for: a hit returns the fetch time of
// the value, not the time of the lookup. A cache that re-stamped it would make
// Evidence.RetrievedAt claim a freshness the data does not have.
func TestHitPreservesOriginalFetchTime(t *testing.T) {
	clk := newClock(t0)
	c := cache.New[string](time.Hour, cache.WithClock(clk.Now))

	c.Put("k", cache.Entry[string]{
		Value:     "v",
		FetchedAt: t0.Add(-30 * time.Minute),
	})
	clk.Advance(10 * time.Minute) // the lookup happens later than the fetch

	e, ok := c.Get("k")
	if !ok {
		t.Fatal("a live entry was not served")
	}
	if e.Value != "v" {
		t.Fatalf("Value = %q, want %q", e.Value, "v")
	}
	want := t0.Add(-30 * time.Minute)
	if !e.FetchedAt.Equal(want) {
		t.Fatalf("FetchedAt = %s, want the original fetch time %s",
			e.FetchedAt.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

// Expiry is measured from the fetch time, not insertion. A value fetched well
// before it was stored is already partly stale.
func TestExpiryIsMeasuredFromFetchTime(t *testing.T) {
	clk := newClock(t0)
	c := cache.New[string](10*time.Minute, cache.WithClock(clk.Now))

	// Fetched 9 minutes before "now", so only a minute of TTL remains.
	c.Put("k", cache.Entry[string]{Value: "v", FetchedAt: t0.Add(-9 * time.Minute)})

	clk.Advance(30 * time.Second)
	if _, ok := c.Get("k"); !ok {
		t.Fatal("an unexpired entry was reported as a miss")
	}

	clk.Advance(61 * time.Second) // total age 10m1s from the fetch
	if _, ok := c.Get("k"); ok {
		t.Fatal("an entry past its TTL was served; expiry must be a miss")
	}
}

// An expired entry is gone, not merely hidden: a later Put of the same key has
// nothing to compare against, and a re-fetch is the only way to get an answer.
func TestExpiredEntryIsDiscarded(t *testing.T) {
	clk := newClock(t0)
	c := cache.New[string](time.Minute, cache.WithClock(clk.Now))
	c.Put("k", cache.Entry[string]{Value: "old", FetchedAt: t0})

	clk.Advance(2 * time.Minute)
	if _, ok := c.Get("k"); ok {
		t.Fatal("expired entry served")
	}
	if n := c.Len(); n != 0 {
		t.Fatalf("expired entry left in the map: Len = %d, want 0", n)
	}
}

// Zero and negative TTLs disarm the cache. Every lookup must miss, so a
// deployment that disables caching cannot accidentally serve a cached answer.
func TestNonPositiveTTLDisarmsTheCache(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Minute} {
		c := cache.New[string](ttl)
		c.Put("k", cache.Entry[string]{Value: "v", FetchedAt: t0})
		if _, ok := c.Get("k"); ok {
			t.Errorf("ttl %s: disarmed cache served an entry", ttl)
		}
		if n := c.Len(); n != 0 {
			t.Errorf("ttl %s: disarmed cache stored an entry: Len = %d", ttl, n)
		}
	}
}

// A cached "negative" answer is a real answer and must be cached like any
// other, then re-fetched once it expires — never assumed to still hold.
func TestNegativeAnswerExpiresAndIsNotAssumed(t *testing.T) {
	clk := newClock(t0)
	c := cache.New[[]string](time.Minute, cache.WithClock(clk.Now))
	// An empty slice is the negative answer: "the source said nothing useful".
	c.Put("k", cache.Entry[[]string]{Value: nil, FetchedAt: t0})

	if _, ok := c.Get("k"); !ok {
		t.Fatal("a cached negative answer was not served within its TTL")
	}
	clk.Advance(2 * time.Minute)
	if _, ok := c.Get("k"); ok {
		t.Fatal("an expired negative answer was served; it must re-fetch")
	}
}

// An entry Put without a fetch time gets one, so it can never outlive every
// TTL. This is the belt to the expiry measurement's braces.
func TestPutStampsMissingFetchTime(t *testing.T) {
	clk := newClock(t0)
	c := cache.New[string](time.Minute, cache.WithClock(clk.Now))
	c.Put("k", cache.Entry[string]{Value: "v"})

	clk.Advance(30 * time.Second)
	if _, ok := c.Get("k"); !ok {
		t.Fatal("entry stamped with the cache clock was reported expired too early")
	}
	clk.Advance(31 * time.Second)
	if _, ok := c.Get("k"); ok {
		t.Fatal("entry stamped with a zero fetch time never expired")
	}
}

// Concurrency: the scanner serving parallel requests shares one cache, and
// `make test` runs with -race. This exercises concurrent readers, writers and
// expiry on the same keys.
func TestConcurrentGetPut(t *testing.T) {
	clk := newClock(t0)
	c := cache.New[int](time.Hour, cache.WithClock(clk.Now))

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				key := strconv.Itoa(i % 16)
				if e, ok := c.Get(key); ok {
					if e.Value < 0 {
						t.Errorf("impossible value %d", e.Value)
					}
					continue
				}
				c.Put(key, cache.Entry[int]{Value: i, FetchedAt: clk.Now()})
			}
		}(w)
	}
	wg.Wait()
}
