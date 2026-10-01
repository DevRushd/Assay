package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/api"
	"github.com/use-assay/assay/internal/history"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/temporal"
)

const (
	aquaCode   = "AQUA"
	aquaIssuer = "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"
	aquaID     = aquaCode + "-" + aquaIssuer
)

// historyBody is the subset of the response these tests read. It is declared
// here rather than reusing the server's unexported type on purpose: the test
// should fail if the wire shape changes, not track it automatically.
type historyBody struct {
	Asset struct {
		Code   string `json:"code"`
		Issuer string `json:"issuer"`
	} `json:"asset"`
	State  string `json:"state"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`

	Observations []struct {
		At                 time.Time `json:"at"`
		Mechanics          int       `json:"mechanics"`
		BaseSeverity       string    `json:"base_severity"`
		Severity           string    `json:"severity"`
		Undetermined       bool      `json:"undetermined"`
		UndeterminedChecks []string  `json:"undetermined_checks"`
	} `json:"observations"`

	Transitions []struct {
		State          string   `json:"state"`
		Reason         string   `json:"reason"`
		AddedNames     []string `json:"added_names"`
		RemovedNames   []string `json:"removed_names"`
		Attribution    string   `json:"attribution"`
		SeverityBefore string   `json:"severity_before"`
		SeverityAfter  string   `json:"severity_after"`
	} `json:"transitions"`

	LatestAt      *time.Time `json:"latest_at"`
	LatestAgeSecs *int64     `json:"latest_age_secs"`
	Retention     int        `json:"retention"`
}

func newHistoryServer() *api.Server {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.NewServer(log)
}

func historyAt(day int) time.Time { return time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC) }

// historyObs builds a complete observation for AQUA at a given day.
func historyObs(day int, bits mechanics.Mechanic, base, sev mechanics.Severity) temporal.Observation {
	return temporal.Observation{
		Asset:     mechanics.Asset{Code: aquaCode, Issuer: aquaIssuer},
		At:        historyAt(day),
		Mechanics: bits,
		Base:      base,
		Severity:  sev,
	}
}

func getHistory(t *testing.T, srv *api.Server) (*httptest.ResponseRecorder, historyBody) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/history?asset="+aquaID, nil)
	srv.Handler().ServeHTTP(rec, req)

	var body historyBody
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode history: %v\nbody: %s", err, rec.Body.String())
		}
	}
	return rec, body
}

func mustAppend(t *testing.T, srv *api.Server, o temporal.Observation) {
	t.Helper()
	if err := srv.History.Append(o); err != nil {
		t.Fatalf("Append: %v", err)
	}
}

// No observations is an explicit empty result: HTTP 200, state "missing", a
// reason, and empty (not null) arrays. It must never be a 404 or a bare 200
// with nothing in it, because a consumer has to tell "we have never looked"
// apart from "the request failed".
func TestHistoryEmpty(t *testing.T) {
	srv := newHistoryServer()
	rec, body := getHistory(t, srv)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; an empty history is a result, not an error", rec.Code)
	}
	if body.State != "missing" {
		t.Errorf("state = %q, want %q", body.State, "missing")
	}
	if body.Reason == "" {
		t.Error("empty history carried no reason; it is then indistinguishable from a silent failure")
	}
	if body.Count != 0 {
		t.Errorf("count = %d, want 0", body.Count)
	}
	if body.Observations == nil {
		t.Error("observations decoded to nil, so the body rendered null instead of []")
	}
	if len(body.Observations) != 0 {
		t.Errorf("observations = %d entries, want 0", len(body.Observations))
	}
	if body.Transitions == nil {
		t.Error("transitions decoded to nil, so the body rendered null instead of []")
	}
	if body.Asset.Code != aquaCode || body.Asset.Issuer != aquaIssuer {
		t.Errorf("asset not echoed: %+v", body.Asset)
	}
}

// Bad input fails before any store read, like the scan endpoint.
func TestHistoryRejectsBadInput(t *testing.T) {
	for _, tc := range []struct{ name, query string }{
		{"missing asset", "/api/v1/history"},
		{"empty asset", "/api/v1/history?asset="},
		{"not an asset", "/api/v1/history?asset=hello"},
		{"bad issuer", "/api/v1/history?asset=AQUA-NOPE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newHistoryServer().Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.query, nil))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
		})
	}
}

// A single observation is a history of one. It is "valid" — nothing about it is
// missing or undetermined — but it yields no transition, because a transition
// is the difference between two points and there is only one.
func TestHistorySingleObservation(t *testing.T) {
	srv := newHistoryServer()
	mustAppend(t, srv, historyObs(1, 0, mechanics.Clear, mechanics.Clear))

	rec, body := getHistory(t, srv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body.State != "valid" {
		t.Errorf("state = %q, want %q", body.State, "valid")
	}
	if body.Count != 1 || len(body.Observations) != 1 {
		t.Fatalf("got %d observations, want 1", len(body.Observations))
	}
	if len(body.Transitions) != 0 {
		t.Errorf("a single observation produced %d transitions, want 0", len(body.Transitions))
	}
	if body.LatestAt == nil || !body.LatestAt.Equal(historyAt(1)) {
		t.Errorf("latest_at = %v, want %v", body.LatestAt, historyAt(1))
	}
	if body.LatestAgeSecs == nil {
		t.Error("latest_age_secs missing; a consumer cannot judge staleness without it")
	}
	if body.Retention != history.DefaultRetention {
		t.Errorf("retention = %d, want %d", body.Retention, history.DefaultRetention)
	}
}

// Two observations produce one derived transition, in time order, attributed to
// the axis that moved.
func TestHistoryMultipleWithTransition(t *testing.T) {
	srv := newHistoryServer()
	mustAppend(t, srv, historyObs(1, 0, mechanics.Clear, mechanics.Clear))
	mustAppend(t, srv, historyObs(2, mechanics.MechClawbackEnabled, mechanics.High, mechanics.High))

	rec, body := getHistory(t, srv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body.State != "valid" {
		t.Errorf("state = %q, want %q", body.State, "valid")
	}
	if len(body.Observations) != 2 {
		t.Fatalf("got %d observations, want 2", len(body.Observations))
	}
	if !body.Observations[0].At.Equal(historyAt(1)) || !body.Observations[1].At.Equal(historyAt(2)) {
		t.Errorf("observations are not in time order: %v", body.Observations)
	}
	if len(body.Transitions) != 1 {
		t.Fatalf("got %d transitions, want 1", len(body.Transitions))
	}

	tr := body.Transitions[0]
	if tr.State != "valid" {
		t.Errorf("transition state = %q, want %q (%s)", tr.State, "valid", tr.Reason)
	}
	if !contains(tr.AddedNames, "auth_clawback_enabled") {
		t.Errorf("added_names = %v, want the clawback capability", tr.AddedNames)
	}
	if len(tr.RemovedNames) != 0 {
		t.Errorf("removed_names = %v, want none", tr.RemovedNames)
	}
	if tr.Attribution != "capability" {
		t.Errorf("attribution = %q, want %q", tr.Attribution, "capability")
	}
	if tr.SeverityBefore != "clear" || tr.SeverityAfter != "high" {
		t.Errorf("severity moved %q -> %q, want clear -> high", tr.SeverityBefore, tr.SeverityAfter)
	}
}

// An undetermined observation is returned marked, not dropped, and it makes the
// whole history "unknown": a source that did not answer could have hidden
// exactly the change being asked about, so no transition may be derived from it.
func TestHistoryUndeterminedObservation(t *testing.T) {
	srv := newHistoryServer()
	mustAppend(t, srv, historyObs(1, 0, mechanics.Clear, mechanics.Clear))

	partial := historyObs(2, 0, mechanics.Clear, mechanics.Clear)
	partial.Undetermined = true
	partial.UndeterminedChecks = []string{"reputation"}
	mustAppend(t, srv, partial)

	rec, body := getHistory(t, srv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body.State != "unknown" {
		t.Errorf("state = %q, want %q", body.State, "unknown")
	}
	if body.Reason == "" {
		t.Error("unknown history carried no reason")
	}
	if body.Count != 2 {
		t.Fatalf("count = %d, want the undetermined observation included", body.Count)
	}
	if !body.Observations[1].Undetermined {
		t.Error("undetermined observation was not marked")
	}
	if !contains(body.Observations[1].UndeterminedChecks, "reputation") {
		t.Errorf("undetermined_checks = %v, want reputation", body.Observations[1].UndeterminedChecks)
	}
	if len(body.Transitions) != 1 {
		t.Fatalf("got %d transitions, want 1", len(body.Transitions))
	}
	if body.Transitions[0].State != "unknown" {
		t.Errorf("transition state = %q, want %q; a partial observation cannot yield a derived change",
			body.Transitions[0].State, "unknown")
	}
}

// Arrival order must not leak into the response: history is ordered by time.
func TestHistoryOrdersObservationsByTime(t *testing.T) {
	srv := newHistoryServer()
	mustAppend(t, srv, historyObs(3, 0, mechanics.Clear, mechanics.Clear))
	mustAppend(t, srv, historyObs(1, 0, mechanics.Clear, mechanics.Clear))
	mustAppend(t, srv, historyObs(2, 0, mechanics.Clear, mechanics.Clear))

	_, body := getHistory(t, srv)
	if len(body.Observations) != 3 {
		t.Fatalf("got %d observations, want 3", len(body.Observations))
	}
	for i, want := range []int{1, 2, 3} {
		if !body.Observations[i].At.Equal(historyAt(want)) {
			t.Fatalf("observation %d at %v, want day %d", i, body.Observations[i].At, want)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
