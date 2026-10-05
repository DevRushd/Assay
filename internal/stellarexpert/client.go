// Package stellarexpert consumes StellarExpert's curated reputation data.
//
// Assay does not build a reputation layer and does not second-guess this one.
// Everything this package returns is passed through to the report as attributed
// evidence, carrying the source URL and retrieval time. Nothing here is
// re-derived, re-scored, or restated as an Assay conclusion.
//
// Endpoints verified live against api.stellar.expert:
//
//	GET /explorer/directory/{address}                 -> curated address entry
//	GET /explorer/directory/blocked-domains/{domain}  -> {"domain":..,"blocked":bool}
//
// Answers from these endpoints are cached for a bounded time and returned with
// the instant the source produced them, never the instant a cache served them.
// See docs/caching.md.
//
// This is an extraction candidate for a shared ledger-access library.
package stellarexpert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/cache"
)

// DefaultURL is the public StellarExpert API root.
const DefaultURL = "https://api.stellar.expert"

// version is kept here so every outbound client reports the same tool
// version in its User-Agent. Bump it alongside any scanner-version release;
// the API documents the value in release notes.
const version = "v0.1.0"

// defaultUserAgent is how Assay identifies itself to the public StellarExpert
// API. It is a courtesy to the operators of sources Assay depends on and makes
// automated traffic distinguishable from botnets and scanners.
const defaultUserAgent = "assay/" + version + " (+https://github.com/use-assay/Assay)"

// MaxBody caps a curated-endpoint response. Real responses are a few KB; like
// the SEP-1 toml cap this stops a broken or hostile server from streaming an
// unbounded body at the scanner. The decode reads at most this many bytes, so
// an oversized document is truncated and then fails to decode rather than
// allocating without bound. It is exported so the resource-exhaustion tests
// can assert the bound rather than assume it.
const MaxBody = 1 << 20 // 1 MiB

// RetryOptions bounds exponential backoff with jitter for transient failures.
// Retry-After takes precedence when the server advertises it.
type RetryOptions struct {
	Attempts        int
	InitialDelay    time.Duration
	MaxDelay        time.Duration
	MaxTotalLatency time.Duration
}

// DefaultRetryOptions caps total added latency at ~2s, well inside the
// outer 30s scan budget, and honours the Retry-After we actually observed on
// api.stellar.expert.
func DefaultRetryOptions() *RetryOptions {
	return &RetryOptions{
		Attempts:        3,
		InitialDelay:    250 * time.Millisecond,
		MaxDelay:        500 * time.Millisecond,
		MaxTotalLatency: 2 * time.Second,
	}
}

// Backoff returns the next delay after an attempt failed, with full jitter:
// a uniform draw in [0, min(MaxDelay, InitialDelay * 2^attempt)].
func (o *RetryOptions) Backoff(attempt int, retryAfter time.Duration) time.Duration {
	target := o.InitialDelay * time.Duration(math.Pow(2, float64(attempt)))
	if target > o.MaxDelay {
		target = o.MaxDelay
	}
	if retryAfter > 0 && retryAfter < target {
		target = retryAfter
	}
	if target <= 0 {
		target = o.InitialDelay
	}
	n := rand.Int63()
	if n < 0 {
		n = -n
	}
	target = time.Duration(n % int64(target))
	return target
}

// AdvertisedMaxAge is the freshness budget StellarExpert publishes for the
// endpoints Assay consumes.
//
// Its OpenAPI document advises caching outright: "The effective API request
// rate may be a subject to rate limiting. In such cases the server returns 429
// HTTP status code error. To avoid potential problems caused by those
// limitations it is advised to consider response caching or group queries on
// the caller side in case of heavy API utilization."
// (https://stellar.expert/openapi, retrieved 2026-09-27.) The responses carry
// the concrete number: both endpoints Assay reads answer with
//
//	cache-control: max-age=20
//
// (verified live 2026-09-27 on /explorer/directory/{address} and
// /explorer/directory/blocked-domains/{domain}). Assay takes that as the
// operator's own statement of how long an answer stays current, so the default
// cache lifetime is exactly that and never longer. A deployment may shorten it,
// or disable caching with -no-cache; extending it past the advertised window is
// opting into staler claims than the source is willing to stand behind.
const AdvertisedMaxAge = 20 * time.Second

// DefaultDirectoryTTL bounds how long a curated directory answer may be served
// from cache, measured from the fetch that produced it. A directory entry can
// carry the malicious/unsafe tag that escalates severity, which is why the
// default does not exceed AdvertisedMaxAge.
const DefaultDirectoryTTL = AdvertisedMaxAge

// DefaultBlocklistTTL bounds how long a blocklist answer may be served from
// cache. It is a separate knob from the directory's because the
// blocklist answers the single most decisive question Assay asks — is this
// issuer's domain a known bad actor — and entries appear ad hoc as reports
// arrive rather than on a review schedule, so the window in which a new entry
// could be missed is kept small. Its default matches the directory's, and
// neither exceeds the window StellarExpert advertises; a deployment that wants
// a tighter blocklist window can set it lower, or to zero. See docs/caching.md.
const DefaultBlocklistTTL = AdvertisedMaxAge

// Options configures a Client, including its cache policy.
type Options struct {
	// DirectoryTTL is how long a directory answer may be served from cache,
	// measured from the fetch that produced it. Zero disables directory
	// caching.
	DirectoryTTL time.Duration
	// BlocklistTTL is how long a blocklist answer may be served from cache.
	// Zero disables blocklist caching.
	BlocklistTTL time.Duration
	// Now overrides the clock the cache uses for expiry. nil means time.Now.
	// Tests set it to exercise expiry without sleeping.
	Now func() time.Time
}

// DefaultOptions returns the production cache policy described by
// DefaultDirectoryTTL and DefaultBlocklistTTL.
func DefaultOptions() Options {
	return Options{
		DirectoryTTL: DefaultDirectoryTTL,
		BlocklistTTL: DefaultBlocklistTTL,
	}
}

// Answer is one curated source's reply about one subject, together with when
// the source produced it.
//
// It replaces a bare pointer result so that the time a claim belongs to travels
// with the claim. Evidence.RetrievedAt is a statement about when data was
// fetched, so a caller must be able to ask the source's answer how old it is
// without assuming the answer arrived just now.
type Answer[T any] struct {
	// Value is the decoded answer. It is nil when the source answered that it
	// holds no entry, which is a real answer — "not listed" — and not a
	// failure. A nil Value with a nil error means exactly that.
	Value *T
	// FetchedAt is when the UPSTREAM source produced this answer. On a cache
	// hit it is the time of the original fetch, never the time of the hit:
	// re-stamping it here would make Assay assert a freshness the data does
	// not have, in reports and in evidence_hash preimages that a third party
	// re-derives.
	FetchedAt time.Time
	// FromCache reports whether this answer was served without asking the
	// source again. FetchedAt already carries the honest age, so this is
	// informational; it is exported so a caller can log it and a test can
	// assert the cache actually engaged.
	FromCache bool
}

// fetchedAt exposes the answer's fetch time to the shared cache path.
func (a Answer[T]) fetchedAt() time.Time { return a.FetchedAt }

// LookupOption adjusts a single lookup.
type LookupOption func(*lookupOptions)

type lookupOptions struct {
	bypass bool
}

// BypassCache makes one lookup skip the cache entirely: it asks the source and
// stores the fresh answer in place of whatever was there.
//
// It exists for the caller who has a reason to distrust the cached copy — an
// explicit refresh, a suspected escalation, a report about to be attested —
// without having to rebuild the Client or disable caching for everything else.
func BypassCache() LookupOption {
	return func(o *lookupOptions) { o.bypass = true }
}

// stamped is the minimal contract a cached answer satisfies: it can report the
// instant its data was fetched, which the cache needs to measure expiry from
// the data's age rather than from its insertion.
type stamped interface {
	fetchedAt() time.Time
}

// DirectoryEntry is a curated entry from StellarExpert's address directory,
// the data set standardized by SEP-0037.
type DirectoryEntry struct {
	Address string   `json:"address"`
	Name    string   `json:"name"`
	Domain  string   `json:"domain"`
	Tags    []string `json:"tags"`
}

// HasTag reports whether the entry carries the given tag.
func (e *DirectoryEntry) HasTag(tag string) bool {
	if e == nil {
		return false
	}
	for _, t := range e.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// BlockedDomain is the response from the blocked-domains lookup.
type BlockedDomain struct {
	Domain  string `json:"domain"`
	Blocked bool   `json:"blocked"`
}

// Client reads StellarExpert's curated data sets.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string

	// now is the clock used to stamp answers and measure cache expiry.
	now func() time.Time

	directory *cache.Cache[Answer[DirectoryEntry]]
	blocklist *cache.Cache[Answer[BlockedDomain]]
}

// New returns a Client for a given API root, defaulting to the public one and
// to the default cache policy. Use NewWithOptions to change either.
func New(baseURL string) *Client {
	return NewWithOptions(baseURL, DefaultOptions())
}

// NewWithOptions returns a Client for a given API root with the given cache
// policy, defaulting to the public root when baseURL is empty.
func NewWithOptions(baseURL string, opts Options) *Client {
	if baseURL == "" {
		baseURL = DefaultURL
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Client{
		BaseURL:   baseURL,
		HTTP:      &http.Client{Timeout: 15 * time.Second},
		UserAgent: defaultUserAgent,
		now:       now,
		directory: cache.New[Answer[DirectoryEntry]](opts.DirectoryTTL, cache.WithClock(now)),
		blocklist: cache.New[Answer[BlockedDomain]](opts.BlocklistTTL, cache.WithClock(now)),
	}
}

// DirectoryURL returns the public URL for an address's directory entry, used
// to attribute the claim in the report.
func (c *Client) DirectoryURL(address string) string {
	return c.BaseURL + "/explorer/directory/" + url.PathEscape(address)
}

// BlockedDomainURL returns the public URL for a blocked-domain lookup.
func (c *Client) BlockedDomainURL(domain string) string {
	return c.BaseURL + "/explorer/directory/blocked-domains/" + url.PathEscape(domain)
}

// Directory looks up an address in the curated directory.
//
// The returned Answer carries the instant the source produced it. Within the
// configured TTL a repeated lookup for the same address is served from cache
// without a request, and the Answer's FetchedAt is then the original fetch
// time — never the time of the cache hit. An answer with a nil Value and a nil
// error means the address is simply not listed, which is the common case and is
// not itself a signal in either direction; that negative is cached and expires
// like any other answer.
func (c *Client) Directory(ctx context.Context, address string, opts ...LookupOption) (Answer[DirectoryEntry], error) {
	target := c.DirectoryURL(address)
	a, hit, err := lookup(c.directory, target, opts, func() (Answer[DirectoryEntry], error) {
		var e DirectoryEntry
		found, err := c.get(ctx, target, &e)
		if err != nil {
			return Answer[DirectoryEntry]{}, err
		}
		at := c.now()

		// The directory answers an address it holds no entry for with 200 and
		// an empty object, not a 404 — verified against several unlisted
		// addresses. So a successful decode is not by itself a listing. A real
		// entry always echoes the address it describes, which is the
		// discriminator used here.
		//
		// Without this, an absent entry surfaces downstream as the attributed
		// claim `listed as "" (domain "", tags: )` — a statement this source
		// never made, attached to its name and URL.
		if !found || e.Address == "" {
			return Answer[DirectoryEntry]{FetchedAt: at}, nil
		}
		return Answer[DirectoryEntry]{Value: &e, FetchedAt: at}, nil
	})
	if err != nil {
		return Answer[DirectoryEntry]{}, err
	}
	a.FromCache = hit
	return a, nil
}

// BlockedDomain reports whether a domain appears on the malicious-domain
// blocklist, and when the source produced that answer.
//
// A "not blocked" answer is cached and expires like any other. Expiry means a
// re-fetch, never an assumption: serving an expired "not blocked" would let a
// domain that has since been listed keep reading as clean.
func (c *Client) BlockedDomain(ctx context.Context, domain string, opts ...LookupOption) (Answer[BlockedDomain], error) {
	target := c.BlockedDomainURL(domain)
	a, hit, err := lookup(c.blocklist, target, opts, func() (Answer[BlockedDomain], error) {
		var b BlockedDomain
		found, err := c.get(ctx, target, &b)
		if err != nil {
			return Answer[BlockedDomain]{}, err
		}
		at := c.now()
		if !found {
			return Answer[BlockedDomain]{FetchedAt: at}, nil
		}
		return Answer[BlockedDomain]{Value: &b, FetchedAt: at}, nil
	})
	if err != nil {
		return Answer[BlockedDomain]{}, err
	}
	a.FromCache = hit
	return a, nil
}

// lookup applies the cache policy to one fetch.
//
// Only an answer the source actually produced is cached. A failed fetch is
// returned uncached, because storing an outage would keep serving it after the
// source recovered — the same "an outage rendered as an answer" failure the
// error fields exist to prevent.
func lookup[T stamped](c *cache.Cache[T], key string, opts []LookupOption, fetch func() (T, error)) (T, bool, error) {
	var lo lookupOptions
	for _, opt := range opts {
		opt(&lo)
	}
	if !lo.bypass {
		if e, ok := c.Get(key); ok {
			return e.Value, true, nil
		}
	}
	val, err := fetch()
	if err != nil {
		var zero T
		return zero, false, err
	}
	// A bypassed fetch still stores its fresh answer: the caller asked for the
	// source's current statement, and keeping a superseded copy would only
	// serve it later. The cache no-ops when its TTL is non-positive.
	c.Put(key, cache.Entry[T]{Value: val, FetchedAt: val.fetchedAt()})
	return val, false, nil
}

// get returns found=false on 404 rather than an error, because "not listed" is
// a normal answer from these endpoints.
//
// Transient failures (429/5xx) are retried with bounded exponential backoff
// and jitter, honouring Retry-After when the server advertises it. The retry
// policy is keyed by status code so a 404 is never retried and the ledger
// source (Horizon) is never touched here. If the retries exhaust, err is the
// last transient error, which the caller records verbatim as evidence and
// reports as undetermined.
func (c *Client) get(ctx context.Context, target string, out any) (bool, error) {
	var lastErr error
	opts := DefaultRetryOptions()
	for attempt := 0; attempt < opts.Attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.UserAgent)

		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("stellarexpert: get %s: %w", target, err)
			if attempt == opts.Attempts-1 {
				return false, lastErr
			}
			t := opts.Backoff(attempt, 0)
			if !wait(ctx, t) {
				return false, ctx.Err()
			}
			continue
		}

		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
			if attempt == opts.Attempts-1 {
				return false, fmt.Errorf("stellarexpert: get %s: status %d", target, resp.StatusCode)
			}
			t := opts.Backoff(attempt, retryAfter)
			if !wait(ctx, t) {
				return false, ctx.Err()
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("stellarexpert: get %s: status %d", target, resp.StatusCode)
			if attempt == opts.Attempts-1 {
				return false, lastErr
			}
			t := opts.Backoff(attempt, 0)
			if !wait(ctx, t) {
				return false, ctx.Err()
			}
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
		if err != nil {
			lastErr = fmt.Errorf("stellarexpert: read %s: %w", target, err)
			if attempt == opts.Attempts-1 {
				return false, lastErr
			}
			t := opts.Backoff(attempt, 0)
			if !wait(ctx, t) {
				return false, ctx.Err()
			}
			continue
		}
		if err := json.Unmarshal(body, out); err != nil {
			lastErr = fmt.Errorf("stellarexpert: decode %s: %w", target, err)
			if attempt == opts.Attempts-1 {
				return false, lastErr
			}
			t := opts.Backoff(attempt, 0)
			if !wait(ctx, t) {
				return false, ctx.Err()
			}
			continue
		}
		return true, nil
	}
	return false, lastErr
}

// wait sleeps for d unless the context is cancelled or timed out first.
func wait(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// parseRetryAfter parses the Retry-After header, returning the delay in
// seconds (the documented unit for this header) or zero when absent or
// unparseable.
func parseRetryAfter(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if i, err := strconv.Atoi(s); err == nil {
		return time.Duration(i) * time.Second
	}
	t, err := time.Parse(time.RFC1123, s)
	if err != nil {
		return 0
	}
	return time.Until(t.UTC())
}
