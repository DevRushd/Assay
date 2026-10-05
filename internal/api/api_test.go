package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/api"
)

func newTestServer() http.Handler {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.NewServer(log).Handler()
}

// TestScanRejectsBadInput covers the paths that fail before any network call,
// so the test stays hermetic.
func TestScanRejectsBadInput(t *testing.T) {
	h := newTestServer()

	for _, tc := range []struct{ name, query string }{
		{"missing asset", "/api/v1/scan"},
		{"empty asset", "/api/v1/scan?asset="},
		{"not an asset", "/api/v1/scan?asset=hello"},
		{"bad issuer", "/api/v1/scan?asset=USDC-NOPE"},
		{"invalid max_age_secs", "/api/v1/scan?asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&max_age_secs=notanumber"},
		{"negative max_age_secs", "/api/v1/scan?asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&max_age_secs=-10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.query, nil))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
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

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestUIServed(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// The UI must present severity and accountability as separate things. If
	// someone collapses them into one score, this fails loudly.
	for _, want := range []string{"Severity — issuer capability", "Accountability — who stands behind it"} {
		if !strings.Contains(body, want) {
			t.Errorf("UI missing %q", want)
		}
	}
}

func TestUnknownPathIs404(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestScanUndeterminedHeaderContract(t *testing.T) {
	// A scan on a nonexistent or unreachable asset returns undetermined or fails;
	// we can verify the header contract is set properly on responses.
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scan?asset=UNKNOWN-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA", nil))
	if rec.Code == http.StatusOK {
		if got := rec.Header().Get("X-Assay-Undetermined"); got != "true" && got != "false" {
			t.Errorf("X-Assay-Undetermined header missing or invalid: %q", got)
		}
	}
}
