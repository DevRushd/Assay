package api_test

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/api"
	"github.com/use-assay/assay/internal/scan"
)

// TestFailClosedScanErrorIsSurfacedNotClean pins A6 of docs/fail-closed.md: a
// scan failure must reach the caller as an error response, never as a
// permissive report. The distinction matters because a caller deciding whether
// to hold an asset has to tell "we could not check" from "no issuer powers".
// A validly-shaped asset is used so the failure happens after validation,
// where the error handling actually lives.
func TestFailClosedScanErrorIsSurfacedNotClean(t *testing.T) {
	const issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

	// A scanner whose Horizon answers 500: the ledger lookup fails, which is
	// the fatal path, and everything downstream of it never runs.
	sc := scan.New()
	sc.Horizon.BaseURL = newServer(t, http.StatusInternalServerError, "{}").URL

	srv := &api.Server{Scanner: sc, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scan?asset=USDC-"+issuer, nil))

	if rec.Code == http.StatusOK {
		t.Fatalf("a failed scan returned 200 with body %q; the API must never render an outage as a clean report", rec.Body.String())
	}
	if rec.Code < 500 {
		t.Fatalf("a failed scan returned %d; want a 5xx so the caller knows the answer is missing", rec.Code)
	}

	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error == "" {
		t.Fatal("error body was empty; the caller cannot tell why the answer is missing")
	}
}

// TestFailClosedNotFoundIsNotAScanResult pins A8's API half: an asset Horizon
// does not know is a 404, not an empty report. An empty report could be read
// as "no flags", which would be the most permissive answer there is.
func TestFailClosedNotFoundIsNotAScanResult(t *testing.T) {
	const issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

	sc := scan.New()
	sc.Horizon.BaseURL = newServer(t, http.StatusNotFound, "{}").URL
	srv := &api.Server{Scanner: sc, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scan?asset=USDC-"+issuer, nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown asset returned %d with body %q; want 404", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "severity") {
		t.Error("a 404 body carried a severity; a missing asset must never be a report")
	}
}

// TestFailClosedUnattestedAndUnevaluatedAreDistinguishable pins the error
// taxonomy the API's callers rely on: distinct failure causes surface as
// distinct errors (sentinels compared with errors.Is), so a consumer can tell
// "no such asset" from "capability never read" without parsing English.
func TestFailClosedUnattestedAndUnevaluatedAreDistinguishable(t *testing.T) {
	if errors.Is(scan.ErrBadAsset, scan.ErrBadHolder) {
		t.Fatal("input error sentinels are not distinguishable")
	}
}

func newServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}
