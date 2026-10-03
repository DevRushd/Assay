package scan_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
)

func TestParseAsset(t *testing.T) {
	const issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

	t.Run("valid", func(t *testing.T) {
		for _, in := range []string{
			"USDC-" + issuer,
			"  USDC-" + issuer + "  ",
			// StellarExpert renders assets with a trailing sequence suffix.
			"USDC-" + issuer + "-1",
		} {
			a, err := scan.ParseAsset(in)
			if err != nil {
				t.Fatalf("ParseAsset(%q): %v", in, err)
			}
			if a.Code != "USDC" || a.Issuer != issuer {
				t.Errorf("ParseAsset(%q) = %+v", in, a)
			}
		}
	})

	t.Run("rejected", func(t *testing.T) {
		for _, in := range []string{
			"",
			"USDC",
			"-" + issuer,
			"USDC-NOTAKEY",
			// Lowercase is outside the base32 alphabet Stellar keys use, so
			// accepting it would let a lookalike issuer through.
			"USDC-" + "ga5zsejyb37jrc5avcia5mop4rhtm335x2kgx3ihojapp5re34k4kzvn",
			"TOOLONGASSETCODE-" + issuer,
			"US DC-" + issuer,
		} {
			if _, err := scan.ParseAsset(in); !errors.Is(err, scan.ErrBadAsset) {
				t.Errorf("ParseAsset(%q) error = %v, want ErrBadAsset", in, err)
			}
		}
	})
}

// fakeSources stands up stand-ins for Horizon, StellarExpert, and the issuer's
// stellar.toml. Every handler sleeps a different, nonzero amount so a real
// scan (not a hand-built Subject) produces genuinely staggered fetch times.
type fakeSources struct {
	horizon *httptest.Server
	expert  *httptest.Server
	toml    *httptest.Server
}

const (
	scanIssuer   = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
	scanHomeDom  = "centre.test"
	horizonDelay = 40 * time.Millisecond
	tomlDelay    = 30 * time.Millisecond
	blockedDelay = 20 * time.Millisecond
	dirDelay     = 10 * time.Millisecond
)

func newFakeSources(t *testing.T) *fakeSources {
	t.Helper()
	fs := &fakeSources{}

	fs.horizon = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(horizonDelay)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/assets":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_embedded": map[string]any{
					"records": []map[string]any{{
						"asset_type":   "credit_alphanum4",
						"asset_code":   "USDC",
						"asset_issuer": scanIssuer,
						"flags":        map[string]bool{},
					}},
				},
			})
		case "/accounts/" + scanIssuer:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"account_id":  scanIssuer,
				"home_domain": scanHomeDom,
				"flags":       map[string]bool{},
			})
		default:
			http.NotFound(w, r)
		}
	}))

	fs.expert = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/explorer/directory/blocked-domains/" + scanHomeDom:
			time.Sleep(blockedDelay)
			_, _ = w.Write([]byte(`{"domain":"` + scanHomeDom + `","blocked":false}`))
		case "/explorer/directory/" + scanIssuer:
			// The directory answers 200-with-empty-body for an unlisted address.
			time.Sleep(dirDelay)
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))

	fs.toml = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(tomlDelay)
		_, _ = w.Write([]byte("[[CURRENCIES]]\ncode=\"USDC\"\nissuer=\"" + scanIssuer + "\"\n"))
	}))

	t.Cleanup(func() {
		fs.horizon.Close()
		fs.expert.Close()
		fs.toml.Close()
	})
	return fs
}

// TestSubjectRecordsPerSourceFetchTimes is the acceptance test for per-source
// observation timestamps. It drives a real scan over sources that answer at
// provably different instants, then asserts the report's evidence carries the
// time of the source each claim came from — not one shared start-of-scan time.
func TestSubjectRecordsPerSourceFetchTimes(t *testing.T) {
	fs := newFakeSources(t)

	sc := scan.New()
	sc.Horizon.BaseURL = fs.horizon.URL
	sc.Expert.BaseURL = fs.expert.URL
	sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(fs.toml.URL, "http://")}

	start := time.Now().UTC().Add(-time.Second) // slack for clock scheduling
	sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}

	// Horizon fetches run sequentially, followed by concurrent post-account fetches.
	// Delays: dir (10ms) < blocked (20ms) < toml (30ms).
	seq := []struct {
		name string
		at   time.Time
	}{
		{"StatFetchedAt (horizon assets)", sub.StatFetchedAt},
		{"IssuerFetchedAt (horizon account)", sub.IssuerFetchedAt},
		{"DirectoryFetchedAt (directory)", sub.DirectoryFetchedAt},
		{"BlockedFetchedAt (blocklist)", sub.BlockedFetchedAt},
		{"Toml.Doc.FetchedAt (stellar.toml)", sub.Toml.FetchedAt},
	}
	for i := 1; i < len(seq); i++ {
		if !seq[i].at.After(seq[i-1].at) {
			t.Errorf("%s (%s) is not after %s (%s): timestamps are not per-source",
				seq[i].name, seq[i].at.Format(time.RFC3339Nano),
				seq[i-1].name, seq[i-1].at.Format(time.RFC3339Nano))
		}
	}
	for _, e := range seq {
		if e.at.Before(start) {
			t.Errorf("%s = %s predates the scan", e.name, e.at.Format(time.RFC3339Nano))
		}
	}

	if sub.ScannedAt.After(sub.Toml.FetchedAt) {
		t.Errorf("ScannedAt (%s) is not the scan start: it comes after the toml completion (%s)",
			sub.ScannedAt.Format(time.RFC3339Nano), sub.Toml.FetchedAt.Format(time.RFC3339Nano))
	}
	if sub.TomlAttemptedAt.After(sub.Toml.FetchedAt) {
		t.Errorf("toml attempt time %s is after its completion time %s",
			sub.TomlAttemptedAt.Format(time.RFC3339Nano), sub.Toml.FetchedAt.Format(time.RFC3339Nano))
	}

	// Engine round trip: every success evidence claim carries its own source's
	// completion time, and the report's ScannedAt is the scan start.
	rep, err := sc.Engine.Run(context.Background(), sub)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.ScannedAt.Time().Equal(sub.ScannedAt) {
		t.Errorf("Report.ScannedAt = %s, want the scan start %s",
			rep.ScannedAt.Time().Format(time.RFC3339Nano), sub.ScannedAt.Format(time.RFC3339Nano))
	}
	// Evidence times cross the JSON boundary at the canonical whole-second
	// precision (issue #52), so the comparison truncates the same way the
	// NewCanonicalTime conversion in the checks does.
	want := map[string]time.Time{
		"horizon":                        sub.StatFetchedAt.Truncate(time.Second),
		"stellar.toml":                   sub.Toml.FetchedAt.Truncate(time.Second),
		"stellar.expert/blocked-domains": sub.BlockedFetchedAt.Truncate(time.Second),
		"stellar.expert/directory":       sub.DirectoryFetchedAt.Truncate(time.Second),
	}
	for _, ev := range rep.Evidence {
		wantAt, ok := want[ev.Source]
		if !ok {
			t.Errorf("unexpected evidence source %q", ev.Source)
			continue
		}
		if ev.Attempted {
			t.Errorf("success evidence for %s is marked Attempted", ev.Source)
		}
		if !ev.RetrievedAt.Time().Equal(wantAt) {
			t.Errorf("%s evidence RetrievedAt = %s, want %s (that source's completion time)",
				ev.Source, ev.RetrievedAt.Time().Format(time.RFC3339Nano), wantAt.Format(time.RFC3339Nano))
		}
	}
}

// TestTimeout ensures each source gets its own sub-budget. A slow source does not
// cause a different source to be reported unavailable, and the timeout is attributed
// strictly to the slow source.
func TestTimeout(t *testing.T) {
	fs := newFakeSources(t)
	// Slow toml server delays 200ms
	fs.toml.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("[[CURRENCIES]]\ncode=\"USDC\"\nissuer=\"" + scanIssuer + "\"\n"))
	})

	sc := scan.New()
	sc.FetchTimeout = 50 * time.Millisecond
	sc.Horizon.BaseURL = fs.horizon.URL
	sc.Expert.BaseURL = fs.expert.URL
	sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(fs.toml.URL, "http://")}

	sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("Subject failed: %v", err)
	}

	// Slow toml timed out and recorded an error
	if sub.TomlErr == "" {
		t.Error("expected TomlErr to be set for slow source")
	}
	if !strings.Contains(sub.TomlErr, "context deadline exceeded") && !strings.Contains(sub.TomlErr, "deadline") {
		t.Errorf("TomlErr = %q, want context deadline exceeded", sub.TomlErr)
	}

	// Blocked and Directory finished normally and were not starved
	if sub.BlockedErr != "" || sub.Blocked == nil {
		t.Errorf("Blocked source affected by toml timeout: err=%q, val=%+v", sub.BlockedErr, sub.Blocked)
	}
	if sub.DirectoryErr != "" {
		t.Errorf("Directory source affected by toml timeout: err=%q", sub.DirectoryErr)
	}
}

// TestConcurrentPostAccountFetches verifies that concurrent post-account fetches
// produce complete, correctly populated Subject data.
func TestConcurrentPostAccountFetches(t *testing.T) {
	fs := newFakeSources(t)

	sc := scan.New()
	sc.Horizon.BaseURL = fs.horizon.URL
	sc.Expert.BaseURL = fs.expert.URL
	sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(fs.toml.URL, "http://")}

	sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}

	if sub.Toml == nil || sub.TomlErr != "" {
		t.Errorf("Toml = %+v, TomlErr = %q", sub.Toml, sub.TomlErr)
	}
	if sub.Blocked == nil || sub.BlockedErr != "" {
		t.Errorf("Blocked = %+v, BlockedErr = %q", sub.Blocked, sub.BlockedErr)
	}
	if sub.DirectoryErr != "" {
		t.Errorf("DirectoryErr = %q", sub.DirectoryErr)
	}
}

// TestSubjectFailureEvidenceCarriesAttemptTime covers the failure half of the
// semantics: a source that fails records the attempt time, and the resulting
// evidence is labelled Attempted so a program can tell an attempt from an
// answer without parsing the claim text.
func TestSubjectFailureEvidenceCarriesAttemptTime(t *testing.T) {
	fs := newFakeSources(t)

	// Swap the blocklist handler for a 503, and record when the scan asked.
	var attempted time.Time
	fs.expert.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/explorer/directory/blocked-domains/") {
			attempted = time.Now().UTC()
			http.Error(w, "boom", http.StatusServiceUnavailable)
			return
		}
		time.Sleep(dirDelay)
		_, _ = w.Write([]byte(`{}`))
	})

	sc := scan.New()
	sc.Horizon.BaseURL = fs.horizon.URL
	sc.Expert.BaseURL = fs.expert.URL
	sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(fs.toml.URL, "http://")}

	start := time.Now().UTC()
	sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	end := time.Now().UTC()
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}
	if sub.BlockedErr == "" {
		t.Fatal("expected the blocklist fetch to fail")
	}
	if sub.BlockedAttemptedAt.IsZero() {
		t.Fatal("failed fetch recorded no attempt time")
	}
	if !sub.BlockedFetchedAt.IsZero() {
		t.Error("failed fetch must not record a completion time")
	}
	// The attempt must be recorded inside the scan's wall-clock window, and
	// before the server goroutine saw the request it produced. (Equality is
	// not asserted against the handler's clock capture: the scan records the
	// attempt before sending, the server stamps on receipt, and the two
	// goroutines are only ordered, never simultaneous.)
	if sub.BlockedAttemptedAt.Before(start) || sub.BlockedAttemptedAt.After(end) {
		t.Errorf("recorded attempt time %s falls outside the scan window [%s, %s]",
			sub.BlockedAttemptedAt.Format(time.RFC3339Nano),
			start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))
	}
	if sub.BlockedAttemptedAt.After(attempted) {
		t.Errorf("recorded attempt time %s is after the server received the request (%s)",
			sub.BlockedAttemptedAt.Format(time.RFC3339Nano), attempted.Format(time.RFC3339Nano))
	}

	rep, err := sc.Engine.Run(context.Background(), sub)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var found bool
	for _, ev := range rep.Evidence {
		if ev.Source != "stellar.expert/blocked-domains" {
			continue
		}
		found = true
		if !ev.Attempted {
			t.Error("failure evidence is not marked Attempted; an attempt is not an answer")
		}
		if !ev.RetrievedAt.Time().Equal(sub.BlockedAttemptedAt.Truncate(time.Second)) {
			t.Errorf("failure evidence carries %s, want the attempt time %s (whole-second canonical, issue #52)",
				ev.RetrievedAt.Time().Format(time.RFC3339Nano), sub.BlockedAttemptedAt.Truncate(time.Second).Format(time.RFC3339Nano))
		}
		if !strings.Contains(ev.Claim, "not retrievable") {
			t.Errorf("failure evidence claim does not read as a failure: %q", ev.Claim)
		}
	}
	if !found {
		t.Fatal("no evidence recorded for the unreachable blocklist")
	}
}

// TestCacheHitDoesNotRefreshEvidenceTime is the acceptance test for the
// honesty half of the cache: a scan served from the reputation cache reports
// the time the source ORIGINALLY answered, never the time of the scan that
// reused the answer. A report must never imply its data is fresher than it is.
//
// It drives two real scans through the same Scanner, with a real (short) wait
// between them, so a cache-hit timestamp would be observably later than the
// original fetch time.
func TestCacheHitDoesNotRefreshEvidenceTime(t *testing.T) {
	fs := newFakeSources(t)

	var directoryRequests, blockedRequests int64
	fs.expert.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/explorer/directory/blocked-domains/"):
			atomic.AddInt64(&blockedRequests, 1)
			time.Sleep(blockedDelay)
			_, _ = w.Write([]byte(`{"domain":"` + scanHomeDom + `","blocked":false}`))
		case strings.HasPrefix(r.URL.Path, "/explorer/directory/"):
			atomic.AddInt64(&directoryRequests, 1)
			time.Sleep(dirDelay)
			_, _ = w.Write([]byte(`{"address":"` + scanIssuer +
				`","name":"Centre","domain":"centre.test","tags":["issuer"]}`))
		default:
			http.NotFound(w, r)
		}
	})

	sc := scan.New() // production defaults: the reputation cache is on
	sc.Horizon.BaseURL = fs.horizon.URL
	sc.Expert.BaseURL = fs.expert.URL
	sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(fs.toml.URL, "http://")}

	first, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("first Subject: %v", err)
	}
	if first.DirectoryFetchedAt.IsZero() || first.BlockedFetchedAt.IsZero() {
		t.Fatalf("first scan recorded no fetch times: directory=%s blocklist=%s",
			first.DirectoryFetchedAt, first.BlockedFetchedAt)
	}

	// Wall-clock room so that a stamp taken at the second scan would be
	// strictly later than the first scan's fetch times.
	time.Sleep(5 * time.Millisecond)

	second, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("second Subject: %v", err)
	}

	if got := atomic.LoadInt64(&directoryRequests); got != 1 {
		t.Errorf("directory fetched %d times across two scans, want 1 (the cache did not engage)", got)
	}
	if got := atomic.LoadInt64(&blockedRequests); got != 1 {
		t.Errorf("blocklist fetched %d times across two scans, want 1 (the cache did not engage)", got)
	}

	// The guarantee, at the Subject level: the fetch times did not move.
	if !second.DirectoryFetchedAt.Equal(first.DirectoryFetchedAt) {
		t.Errorf("cache hit re-stamped the directory fetch time: %s -> %s",
			first.DirectoryFetchedAt.Format(time.RFC3339Nano),
			second.DirectoryFetchedAt.Format(time.RFC3339Nano))
	}
	if !second.BlockedFetchedAt.Equal(first.BlockedFetchedAt) {
		t.Errorf("cache hit re-stamped the blocklist fetch time: %s -> %s",
			first.BlockedFetchedAt.Format(time.RFC3339Nano),
			second.BlockedFetchedAt.Format(time.RFC3339Nano))
	}
	// And they are OLDER than the second scan, which is the honest statement:
	// this scan reused data rather than retrieving it.
	if !second.DirectoryFetchedAt.Before(second.ScannedAt) {
		t.Errorf("directory fetch time %s is not before the second scan start %s; "+
			"the report claims data it did not fetch",
			second.DirectoryFetchedAt.Format(time.RFC3339Nano),
			second.ScannedAt.Format(time.RFC3339Nano))
	}
	if !second.BlockedFetchedAt.Before(second.ScannedAt) {
		t.Errorf("blocklist fetch time %s is not before the second scan start %s",
			second.BlockedFetchedAt.Format(time.RFC3339Nano),
			second.ScannedAt.Format(time.RFC3339Nano))
	}

	// The same guarantee where it matters most: the evidence a report and an
	// evidence_hash are built from carries the original time, not the scan's.
	rep, err := sc.Engine.Run(context.Background(), second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := map[string]time.Time{
		"stellar.expert/directory":       first.DirectoryFetchedAt,
		"stellar.expert/blocked-domains": first.BlockedFetchedAt,
	}
	seen := map[string]bool{}
	for _, ev := range rep.Evidence {
		at, ok := want[ev.Source]
		if !ok {
			continue
		}
		seen[ev.Source] = true
		if ev.Attempted {
			t.Errorf("%s evidence marked Attempted on a cache hit", ev.Source)
		}
		if !ev.RetrievedAt.Equal(at) {
			t.Errorf("%s evidence RetrievedAt = %s, want the original fetch time %s",
				ev.Source, ev.RetrievedAt.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano))
		}
	}
	for source := range want {
		if !seen[source] {
			t.Errorf("no evidence recorded for %s; the assertion above proved nothing", source)
		}
	}
}

// singleHostTransport routes every request to one test host, so the sep1
// Fetcher — whose target URL is derived from the issuer's home_domain — can be
// pointed at an httptest server without changing sep1.URLFor.
type singleHostTransport struct{ host string }

func (t *singleHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	u := *req.URL
	u.Scheme = "http"
	u.Host = t.host
	req.URL = &u
	return http.DefaultTransport.RoundTrip(req)
}

// TestSubjectRecordsSkippedBlocklistWhenNoHomeDomain covers the missing state
// at the scanner: with no home_domain there is no domain to key the blocklist
// on, so the lookup must not be attempted and the skip must be recorded rather
// than left as an empty result. An empty result reads downstream as "the lookup
// ran and found no entry" — and a blocklist hit escalates severity, so an
// unread lookup must not be allowed to look like a clean one.
func TestSubjectRecordsSkippedBlocklistWhenNoHomeDomain(t *testing.T) {
	horizonSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/assets":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_embedded": map[string]any{"records": []map[string]any{{
					"asset_type":   "credit_alphanum4",
					"asset_code":   "USDC",
					"asset_issuer": scanIssuer,
					"flags":        map[string]bool{},
				}}},
			})
		case "/accounts/" + scanIssuer:
			// No home_domain at all — the VELO shape.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"account_id": scanIssuer,
				"flags":      map[string]bool{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(horizonSrv.Close)

	var blockedRequests int32
	expertSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/explorer/directory/blocked-domains/") {
			atomic.AddInt32(&blockedRequests, 1)
		}
		// The directory answers 200-with-empty-body for an unlisted address.
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(expertSrv.Close)

	sc := scan.New()
	sc.Horizon.BaseURL = horizonSrv.URL
	sc.Expert.BaseURL = expertSrv.URL

	sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}
	if sub.BlockedSkipped == "" {
		t.Fatal("no home_domain did not record that the blocklist lookup was skipped")
	}
	if sub.Blocked != nil || sub.BlockedErr != "" {
		t.Fatalf("skipped lookup left Blocked=%+v BlockedErr=%q, want both empty", sub.Blocked, sub.BlockedErr)
	}
	if got := atomic.LoadInt32(&blockedRequests); got != 0 {
		t.Fatalf("the blocklist endpoint was queried %d times with no domain to key on", got)
	}

	// The gap must reach the report as undetermined, not as a clean result.
	rep, err := sc.Engine.Run(context.Background(), sub)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.Undetermined {
		t.Fatal("a scan whose blocklist could not be consulted must be undetermined")
	}
	var named bool
	for _, id := range rep.UndeterminedChecks {
		if id == "reputation" {
			named = true
		}
	}
	if !named {
		t.Fatalf("reputation not named in UndeterminedChecks: %v", rep.UndeterminedChecks)
	}
}

func mustParse(t *testing.T, s string) mechanics.Asset {
	t.Helper()
	a, err := scan.ParseAsset(s)
	if err != nil {
		t.Fatalf("ParseAsset(%q): %v", s, err)
	}
	return a
}
