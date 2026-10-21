package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/api"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// exposureAccount is the held account under test — a wallet, not an issuer.
// It is a real, valid G... address so the handler's account validation is
// exercised for success, not just for rejection.
const exposureAccount = "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"

// exposureIssuer issues every asset in the test account's balances.
const exposureIssuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

// exposureHorizonStub answers the three Horizon endpoints an exposure request
// touches: the holder's /accounts/{id} (with a balances array), the issuer's
// /accounts/{id} (flags), and /assets lookups. Assets named in missingAssets
// are answered with Horizon's empty-page shape, which the client maps to
// ErrNotFound — the per-asset failure path under test.
type exposureHorizonStub struct {
	trustlines    []string // asset codes the holder's balances array contains
	missingAssets map[string]bool
	// accountMissing answers every /accounts request with Horizon's 404, the
	// shape for an account the ledger does not know.
	accountMissing bool
}

func (h *exposureHorizonStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.accountMissing && strings.HasPrefix(r.URL.Path, "/accounts/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/assets"):
		code := r.URL.Query().Get("asset_code")
		issuer := r.URL.Query().Get("asset_issuer")
		if h.missingAssets[code] {
			// Horizon's real answer for an asset it has no record of:
			// 200 with an empty page.
			_, _ = w.Write([]byte(`{"_embedded":{"records":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"_embedded":{"records":[{"asset_type":"credit_alphanum4","asset_code":"` + code + `","asset_issuer":"` + issuer + `","flags":{"auth_required":false,"auth_revocable":true,"auth_immutable":false,"auth_clawback_enabled":false},"accounts":{"authorized":1,"unauthorized":0}}]}}`))
	case strings.HasSuffix(r.URL.Path, exposureAccount):
		// The holder's account: a native balance (not a trustline) followed
		// by one balance per trustline under test.
		balances := `{"asset_type":"native","balance":"25.0000000"}`
		for _, code := range h.trustlines {
			balances += `,{"asset_type":"credit_alphanum4","asset_code":"` + code +
				`","asset_issuer":"` + exposureIssuer + `","is_authorized":true,"is_clawback_enabled":false}`
		}
		_, _ = w.Write([]byte(`{"account_id":"` + exposureAccount +
			`","home_domain":"example.com","flags":{"auth_required":false,"auth_revocable":false,"auth_immutable":false,"auth_clawback_enabled":false},"balances":[` + balances + `]}`))
	case strings.HasPrefix(r.URL.Path, "/accounts/"):
		id := strings.TrimPrefix(r.URL.Path, "/accounts/")
		_, _ = w.Write([]byte(`{"account_id":"` + id + `","home_domain":"example.com","flags":{"auth_required":false,"auth_revocable":true,"auth_immutable":false,"auth_clawback_enabled":false}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// newExposureServer wires a server whose every upstream is this process, so
// exposure tests never touch the network. The expert stub and the toml
// round-tripper are the ones outcome_test.go already defines for the package.
func newExposureServer(t *testing.T, stub *exposureHorizonStub) http.Handler {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := api.NewServer(log)

	hSrv := httptest.NewServer(stub)
	t.Cleanup(hSrv.Close)
	srv.Scanner.Horizon.BaseURL = hSrv.URL

	eSrv := httptest.NewServer(&expertStub{})
	t.Cleanup(eSrv.Close)
	srv.Scanner.Expert = stellarexpert.NewWithOptions(eSrv.URL, stellarexpert.Options{})

	srv.Scanner.Toml.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("[[CURRENCIES]]\n")),
			Request:    req,
		}, nil
	})}

	return srv.Handler()
}

// exposureRequest issues a GET with an explicit client address, so the rate
// limit test can tell two clients apart deterministically.
func exposureRequest(h http.Handler, query, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, query, nil)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// exposurePage is the response shape, declared locally because the handler's
// types are unexported; asserting on the decoded JSON is also what a consumer
// actually sees.
type exposurePage struct {
	Account    string `json:"account"`
	Total      int    `json:"total"`
	Limit      int    `json:"limit"`
	Count      int    `json:"count"`
	NextCursor *int   `json:"next_cursor"`
	Assets     []struct {
		Asset struct {
			Code   string `json:"code"`
			Issuer string `json:"issuer"`
		} `json:"asset"`
		Severity           string          `json:"severity"`
		Undetermined       bool            `json:"undetermined"`
		UndeterminedChecks []string        `json:"undetermined_checks"`
		Finding            json.RawMessage `json:"finding"`
		Reason             string          `json:"reason"`
	} `json:"assets"`
}

func decodeExposure(t *testing.T, rec *httptest.ResponseRecorder) exposurePage {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var page exposurePage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v; body %s", err, rec.Body.String())
	}
	return page
}

// TestExposureRejectsBadInput covers every path that must fail before any
// upstream is asked, keeping the test hermetic — the same pattern as
// TestScanRejectsBadInput.
func TestExposureRejectsBadInput(t *testing.T) {
	h := newExposureServer(t, &exposureHorizonStub{})

	for i, tc := range []struct{ name, query string }{
		{"missing account", "/api/v1/exposure"},
		{"empty account", "/api/v1/exposure?account="},
		{"not an account", "/api/v1/exposure?account=hello"},
		{"bad account", "/api/v1/exposure?account=GNOPE"},
		{"zero limit", "/api/v1/exposure?account=" + exposureAccount + "&limit=0"},
		{"non-numeric limit", "/api/v1/exposure?account=" + exposureAccount + "&limit=many"},
		{"negative cursor", "/api/v1/exposure?account=" + exposureAccount + "&cursor=-1"},
		{"non-numeric cursor", "/api/v1/exposure?account=" + exposureAccount + "&cursor=later"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A distinct client address per case: the endpoint is rate-limited
			// before it validates, and one address would spend the shared
			// burst partway through the table.
			addr := "198.51.100." + strconv.Itoa(i+1) + ":4000"
			rec := exposureRequest(h, tc.query, addr)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.Error == "" {
				t.Error("error body was empty; a caller must be able to tell why it failed")
			}
		})
	}
}

// TestExposurePaginatesAndBounds is the bound acceptance criterion: the page
// default holds, the cap clamps an oversized request, and the cursor walks
// the listing to a final page with no next_cursor.
func TestExposurePaginatesAndBounds(t *testing.T) {
	var codes []string
	for i := 1; i <= 12; i++ {
		codes = append(codes, "TL"+strconv.Itoa(i))
	}
	h := newExposureServer(t, &exposureHorizonStub{trustlines: codes})

	// Default page: 10 of 12, cursor at the end of the page.
	rec := exposureRequest(h, "/api/v1/exposure?account="+exposureAccount, "")
	page := decodeExposure(t, rec)
	if page.Total != 12 || page.Count != 10 || page.Limit != 10 {
		t.Errorf("default page: total=%d count=%d limit=%d, want 12/10/10", page.Total, page.Count, page.Limit)
	}
	if page.NextCursor == nil || *page.NextCursor != 10 {
		t.Errorf("next_cursor = %v, want 10", page.NextCursor)
	}

	// Second page: the remainder, and no cursor beyond it.
	rec = exposureRequest(h, "/api/v1/exposure?account="+exposureAccount+"&cursor=10", "")
	page = decodeExposure(t, rec)
	if page.Count != 2 {
		t.Errorf("second page count = %d, want 2", page.Count)
	}
	if page.NextCursor != nil {
		t.Errorf("last page next_cursor = %d, want absent", *page.NextCursor)
	}

	// Oversized limit is clamped to the cap, not rejected, and the applied
	// limit is reported so the caller can plan the next page.
	rec = exposureRequest(h, "/api/v1/exposure?account="+exposureAccount+"&limit=999", "")
	page = decodeExposure(t, rec)
	if page.Limit != 50 {
		t.Errorf("limit = %d, want the cap 50", page.Limit)
	}
	if page.Count != 12 || page.NextCursor != nil {
		t.Errorf("clamped page count=%d next_cursor=%v, want 12 entries and no cursor", page.Count, page.NextCursor)
	}

	// The native balance in the fixture is not a trustline: total counts
	// credit trustlines only.
	if page.Total != 12 {
		t.Errorf("total = %d, want 12 (the native balance must not count)", page.Total)
	}
}

// TestExposureHasNoAggregateScore pins the "never aggregate" criterion to the
// wire: the response has no field that could be read as a portfolio score,
// and each entry carries only per-asset facts.
func TestExposureHasNoAggregateScore(t *testing.T) {
	h := newExposureServer(t, &exposureHorizonStub{trustlines: []string{"TLAA", "TLBB"}})

	rec := exposureRequest(h, "/api/v1/exposure?account="+exposureAccount, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantTop := map[string]bool{
		"account": true, "total": true, "limit": true, "count": true, "assets": true,
	}
	for key := range raw {
		if !wantTop[key] {
			t.Errorf("unexpected top-level field %q: exposure must not publish anything beyond the listing", key)
		}
	}
	if _, ok := raw["next_cursor"]; ok && string(raw["next_cursor"]) != "null" {
		// Present only when more pages exist; either way it must be a cursor.
		var c int
		if err := json.Unmarshal(raw["next_cursor"], &c); err != nil {
			t.Errorf("next_cursor is not a cursor: %s", raw["next_cursor"])
		}
	}

	var page exposurePage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, a := range page.Assets {
		if len(a.Finding) == 0 {
			t.Errorf("%s: finding absent on a fully answered scan", a.Asset.Code)
		}
		if a.Undetermined {
			t.Errorf("%s: undetermined on a fully answered scan", a.Asset.Code)
		}
		if a.Severity == "unevaluated" {
			t.Errorf("%s: severity unevaluated though every source answered", a.Asset.Code)
		}
	}
}

// TestExposureSurfacesUndeterminedPerAsset covers the per-asset failure: one
// asset's Horizon record is missing while the rest answer, and the page must
// mark exactly that asset undetermined — no page-wide failure, no asset
// rendered as clear because a neighbour answered.
func TestExposureSurfacesUndeterminedPerAsset(t *testing.T) {
	h := newExposureServer(t, &exposureHorizonStub{
		trustlines:    []string{"TLAA", "TLXX", "TLBB"},
		missingAssets: map[string]bool{"TLXX": true},
	})

	rec := exposureRequest(h, "/api/v1/exposure?account="+exposureAccount, "")
	page := decodeExposure(t, rec)
	if page.Count != 3 {
		t.Fatalf("count = %d, want 3 (a per-asset failure must not drop entries)", page.Count)
	}
	for _, a := range page.Assets {
		switch a.Asset.Code {
		case "TLXX":
			if !a.Undetermined {
				t.Error("failed asset is not marked undetermined")
			}
			if a.Reason == "" {
				t.Error("failed asset has no reason; the caller cannot tell why it is undetermined")
			}
			if len(a.Finding) != 0 {
				t.Error("failed asset carries a finding that was never computed")
			}
			if a.Severity != "unevaluated" {
				t.Errorf("failed asset severity = %q, want unevaluated (never a permissive answer)", a.Severity)
			}
		default:
			if a.Undetermined {
				t.Errorf("%s: answered asset marked undetermined", a.Asset.Code)
			}
			if a.Reason != "" {
				t.Errorf("%s: reason set though the scan succeeded: %q", a.Asset.Code, a.Reason)
			}
		}
	}
}

// TestExposureAccountNotFound maps Horizon's 404 for an unknown account to
// the endpoint's own 404, distinguishing "no such wallet" from an upstream
// failure the caller should retry.
func TestExposureAccountNotFound(t *testing.T) {
	h := newExposureServer(t, &exposureHorizonStub{accountMissing: true})

	rec := exposureRequest(h, "/api/v1/exposure?account="+exposureAccount, "203.0.113.9:4000")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

// TestExposureRateLimited pins the rate-limit criterion: a client that spends
// the burst is refused with a retry time, and another client's bucket is
// untouched — the limit is per client, not a global lockout.
func TestExposureRateLimited(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := api.NewServer(log)
	// Burst of 2 and an effectively frozen refill: the third request from
	// the same address must be refused without sleeping in the test.
	srv.ExposureLimiter = api.NewRateLimiter(2, 0.000001)
	hSrv := httptest.NewServer(&exposureHorizonStub{trustlines: []string{"TLAA"}})
	t.Cleanup(hSrv.Close)
	srv.Scanner.Horizon.BaseURL = hSrv.URL
	eSrv := httptest.NewServer(&expertStub{})
	t.Cleanup(eSrv.Close)
	srv.Scanner.Expert = stellarexpert.NewWithOptions(eSrv.URL, stellarexpert.Options{})
	srv.Scanner.Toml.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("[[CURRENCIES]]\n")),
			Request:    req,
		}, nil
	})}
	h := srv.Handler()

	q := "/api/v1/exposure?account=" + exposureAccount
	for i := 1; i <= 2; i++ {
		rec := exposureRequest(h, q, "203.0.113.7:4000")
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200; body %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := exposureRequest(h, q, "203.0.113.7:4000")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After: a refused caller is told to stop, not when to return")
	}

	// A different client still has its own burst.
	rec = exposureRequest(h, q, "203.0.113.8:4000")
	if rec.Code != http.StatusOK {
		t.Fatalf("other client: status = %d, want 200", rec.Code)
	}
}
