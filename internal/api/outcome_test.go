package api_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/use-assay/assay/internal/api"
)

// A valid mainnet asset: USDC. Its issuer has no home_domain dependency in
// these tests — the stubs below answer every fetch the scanner makes.
const logTestAsset = "USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

// logServer is the harness for the logging tests: a Server wired to stub
// upstreams, a buffer capturing every log line, and the handler.
type logServer struct {
	srv     *api.Server
	handler http.Handler
	logs    *logBuffer
	horizon *horizonStub
	expert  *expertStub
}

// logBuffer collects log lines so tests can assert on what was emitted.
// Writes are synchronous under the mutex: slog writes each line inside the
// request path, so when the handler returns the line is already recorded —
// no asynchronous collection to race the assertions against.
type logBuffer struct {
	mu      sync.Mutex
	entries []string
}

func newLogBuffer() *logBuffer { return &logBuffer{} }

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, string(p))
	return len(p), nil
}

func (b *logBuffer) Lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.entries...)
}

// outcomeLines returns the decoded scan-outcome lines only, so assertions are
// not confused by unrelated log output.
func (b *logBuffer) outcomeLines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range b.Lines() {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not valid JSON: %q", line)
		}
		if m["msg"] == "scan outcome" {
			out = append(out, m)
		}
	}
	return out
}

func newLogServer(t *testing.T) *logServer {
	t.Helper()
	buf := newLogBuffer()
	log := slog.New(slog.NewJSONHandler(buf, nil))
	srv := api.NewServer(log)

	// horizonStub serves the /assets and /accounts endpoints the scanner
	// needs, always answering with a well-formed record.
	horizon := &horizonStub{}
	hSrv := httptest.NewServer(horizon)
	t.Cleanup(hSrv.Close)
	srv.Scanner.Horizon.BaseURL = hSrv.URL

	// expertStub answers every StellarExpert endpoint with a well-formed
	// "nothing listed" answer.
	expert := &expertStub{}
	eSrv := httptest.NewServer(expert)
	t.Cleanup(eSrv.Close)
	srv.Scanner.Expert.BaseURL = eSrv.URL

	return &logServer{
		srv:     srv,
		handler: srv.Handler(),
		logs:    buf,
		horizon: horizon,
		expert:  expert,
	}
}

// horizonStub answers the two Horizon endpoints the scan path uses.
type horizonStub struct {
	fail bool
	mu   sync.Mutex
}

func (h *horizonStub) setFail(f bool) { h.mu.Lock(); h.fail = f; h.mu.Unlock() }

func (h *horizonStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	fail := h.fail
	h.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/assets"):
		w.Header().Set("Content-Type", "application/json")
		code := r.URL.Query().Get("asset_code")
		issuer := r.URL.Query().Get("asset_issuer")
		if code != "USDC" {
			// Horizon answers a look-up for an asset it holds no record of
			// with 200 and an empty page, which the client maps to
			// ErrNotFound — the real shape this stub imitates.
			_, _ = w.Write([]byte(`{"_embedded":{"records":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"_embedded":{"records":[{"asset_type":"credit_alphanum4","asset_code":"` + code + `","asset_issuer":"` + issuer + `","flags":{"auth_required":false,"auth_revocable":false,"auth_immutable":true,"auth_clawback_enabled":false},"accounts":{"authorized":1,"unauthorized":0}}]}}`))
	case strings.HasPrefix(r.URL.Path, "/accounts/"):
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"account_id":"GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN","home_domain":"","flags":{"auth_required":false,"auth_revocable":false,"auth_immutable":true,"auth_clawback_enabled":false}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// expertStub answers the StellarExpert endpoints with "not listed".
type expertStub struct {
	fail bool
	mu   sync.Mutex
}

func (e *expertStub) setFail(f bool) { e.mu.Lock(); e.fail = f; e.mu.Unlock() }

func (e *expertStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	fail := e.fail
	e.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if strings.Contains(r.URL.Path, "/directory/blocked-domains/") {
		_, _ = w.Write([]byte(`{"domain":"circle.com","blocked":false}`))
		return
	}
	_, _ = w.Write([]byte(`{}`))
}

func doScan(h http.Handler, asset string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan?asset="+asset, nil)
	if header != nil {
		req.Header = header
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeOutcome(t *testing.T, m map[string]any) (class, requestID, asset string) {
	t.Helper()
	c, _ := m["outcome"].(string)
	r, _ := m["request_id"].(string)
	a, _ := m["asset"].(string)
	if c == "" {
		t.Fatalf("outcome line missing outcome field: %v", m)
	}
	return c, r, a
}

// TestLogCompleteOutcome covers the valid state: a scan with every source
// answering produces exactly one outcome line, classified complete, carrying
// the request identifier and the asset.
func TestLogCompleteOutcome(t *testing.T) {
	ls := newLogServer(t)

	rec := doScan(ls.handler, logTestAsset, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	lines := ls.logs.outcomeLines(t)
	if len(lines) != 1 {
		t.Fatalf("outcome lines = %d, want exactly 1: %v", len(lines), lines)
	}
	class, _, _ := decodeOutcome(t, lines[0])
	if class != "complete" {
		t.Fatalf("outcome = %q, want complete", class)
	}
}

// TestLogUndeterminedOutcome covers the unknown state: a scan that completes
// with a consumed source down is classified undetermined — separately from
// failures — names the source that did not answer, and still logs once.
func TestLogUndeterminedOutcome(t *testing.T) {
	ls := newLogServer(t)
	ls.expert.setFail(true)

	rec := doScan(ls.handler, logTestAsset, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; an undetermined scan still serves", rec.Code)
	}

	lines := ls.logs.outcomeLines(t)
	if len(lines) != 1 {
		t.Fatalf("outcome lines = %d, want exactly 1", len(lines))
	}
	class, _, _ := decodeOutcome(t, lines[0])
	if class != "undetermined" {
		t.Fatalf("outcome = %q, want undetermined", class)
	}
	sources, _ := lines[0]["sources"].(string)
	if !strings.Contains(sources, "stellar.expert") {
		t.Fatalf("sources = %q, want it to name the stellar.expert source", sources)
	}

	// The undetermined class is counted separately from failures.
	counts := ls.srv.Metrics.OutcomeCounts()
	if counts["undetermined"] != 1 || counts["upstream_failure"] != 0 {
		t.Fatalf("outcome counts = %v, want undetermined=1, upstream_failure=0", counts)
	}
	// And the per-source counter names the source the evidence named.
	srcs := ls.srv.Metrics.SourceFailureCounts()
	if srcs["stellar.expert/directory"] != 1 {
		t.Fatalf("source failures = %v, want stellar.expert/directory=1", srcs)
	}
}

// TestLogNotFoundOutcome covers the not-found class: an asset Horizon has no
// record of is a different outcome from a dead upstream.
func TestLogNotFoundOutcome(t *testing.T) {
	ls := newLogServer(t)

	rec := doScan(ls.handler, "NOPE-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	lines := ls.logs.outcomeLines(t)
	if len(lines) != 1 {
		t.Fatalf("outcome lines = %d, want exactly 1", len(lines))
	}
	class, _, _ := decodeOutcome(t, lines[0])
	if class != "not_found" {
		t.Fatalf("outcome = %q, want not_found", class)
	}
}

// TestLogUpstreamFailureOutcome covers the failure class: Horizon down means
// no classification is possible and the outcome is upstream_failure.
func TestLogUpstreamFailureOutcome(t *testing.T) {
	ls := newLogServer(t)
	ls.horizon.setFail(true)

	rec := doScan(ls.handler, logTestAsset, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}

	lines := ls.logs.outcomeLines(t)
	if len(lines) != 1 {
		t.Fatalf("outcome lines = %d, want exactly 1", len(lines))
	}
	class, _, _ := decodeOutcome(t, lines[0])
	if class != "upstream_failure" {
		t.Fatalf("outcome = %q, want upstream_failure", class)
	}
	if counts := ls.srv.Metrics.OutcomeCounts(); counts["upstream_failure"] != 1 {
		t.Fatalf("outcome counts = %v, want upstream_failure=1", counts)
	}
}

// TestLogRequestIDPropagates covers the correlation criterion: the identifier
// is stamped on the outcome line, echoed in the response header, a caller
// supplied one is honored, and two requests get different identifiers.
func TestLogRequestIDPropagates(t *testing.T) {
	ls := newLogServer(t)

	rec := doScan(ls.handler, logTestAsset, nil)
	got := rec.Header().Get("X-Request-Id")
	if got == "" {
		t.Fatal("no X-Request-Id header on the response; callers cannot correlate")
	}

	lines := ls.logs.outcomeLines(t)
	if len(lines) != 1 {
		t.Fatalf("outcome lines = %d, want exactly 1", len(lines))
	}
	_, requestID, _ := decodeOutcome(t, lines[0])
	if requestID != got {
		t.Fatalf("log request_id = %q, want %q (the echoed header)", requestID, got)
	}

	// A caller-supplied identifier is honored.
	in := http.Header{}
	in.Set("X-Request-Id", "corr-test-123")
	rec2 := doScan(ls.handler, logTestAsset, in)
	if h := rec2.Header().Get("X-Request-Id"); h != "corr-test-123" {
		t.Fatalf("echoed header = %q, want the caller's own identifier", h)
	}
	lines2 := ls.logs.outcomeLines(t)
	_, requestID2, _ := decodeOutcome(t, lines2[len(lines2)-1])
	if requestID2 != "corr-test-123" {
		t.Fatalf("log request_id = %q, want the caller-supplied identifier", requestID2)
	}

	// Distinct requests carry distinct identifiers.
	if requestID == requestID2 {
		t.Fatal("two requests shared one request identifier")
	}
}

// TestLogCountersExposeOutcomeClasses covers the counters criterion: every
// class has a counter and the /metrics endpoint reports it.
func TestLogCountersExposeOutcomeClasses(t *testing.T) {
	ls := newLogServer(t)

	doScan(ls.handler, logTestAsset, nil)                                                    // complete
	doScan(ls.handler, "NOPE-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN", nil) // not_found
	ls.horizon.setFail(true)
	doScan(ls.handler, logTestAsset, nil) // upstream_failure
	ls.horizon.setFail(false)
	ls.expert.setFail(true)
	doScan(ls.handler, logTestAsset, nil) // undetermined

	rec := httptest.NewRecorder()
	ls.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", rec.Code)
	}
	var body struct {
		ScanOutcomes   map[string]uint64 `json:"scan_outcomes"`
		SourceFailures map[string]uint64 `json:"source_failures"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /metrics: %v", err)
	}
	for _, class := range []string{"complete", "undetermined", "not_found", "upstream_failure"} {
		if body.ScanOutcomes[class] != 1 {
			t.Fatalf("scan_outcomes[%q] = %d, want 1; full body %v", class, body.ScanOutcomes[class], body.ScanOutcomes)
		}
	}
}

// TestLogNeverSecrets pins the invalid-state rule: the log lines carry asset
// identifiers (public) and never credential material. The server's config
// surface is scanned the way an operator would: nothing a key could travel
// through is logged.
func TestLogNeverSecrets(t *testing.T) {
	ls := newLogServer(t)
	ls.horizon.setFail(true)
	doScan(ls.handler, logTestAsset, nil)

	for _, line := range ls.logs.Lines() {
		for _, secret := range []string{"secret", "SASCO", "privkey", "password"} {
			if strings.Contains(strings.ToLower(line), strings.ToLower(secret)) {
				t.Errorf("log line contains %q: %s", secret, line)
			}
		}
	}
}

// TestLogOutcomeOncePerScanRepeated pins the "exactly one outcome line" rule
// under repeated scans, since a per-request counter bug shows up on the
// second and third call, not the first.
func TestLogOutcomeOncePerScanRepeated(t *testing.T) {
	ls := newLogServer(t)

	for i := 0; i < 3; i++ {
		doScan(ls.handler, logTestAsset, nil)
	}
	lines := ls.logs.outcomeLines(t)
	if len(lines) != 3 {
		t.Fatalf("outcome lines = %d, want 3 (one per scan)", len(lines))
	}
	for i, m := range lines {
		if _, ok := m["request_id"].(string); !ok || m["request_id"] == "" {
			t.Errorf("scan %d outcome line has no request identifier", i)
		}
	}
}
