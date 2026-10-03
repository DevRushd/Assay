package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/use-assay/assay/internal/api"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"strings"
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

	if !strings.Contains(body, "@media (max-width: 640px) { .axes { grid-template-columns: 1fr; } }") {
		t.Fatal("UI does not stack the severity and accountability cards at 640px")
	}
	if !strings.Contains(body, "<div class=\"axes\">") || strings.Count(body, "class=\"card\"") < 2 {
		t.Fatal("UI does not structurally render two separate axis cards")
	}
}

func TestReportEnvelopeKeepsSeverityAndAccountabilitySeparate(t *testing.T) {
	report := mechanics.Report{
		Severity:       mechanics.Critical,
		Base:           mechanics.High,
		Escalated:      true,
		Accountability: mechanics.AccountabilityVerified,
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode report envelope: %v", err)
	}
	for _, field := range []string{"severity", "accountability", "base_severity", "escalated"} {
		if _, ok := envelope[field]; !ok {
			t.Errorf("report envelope missing %q", field)
		}
	}

	var severity, accountability string
	if err := json.Unmarshal(envelope["severity"], &severity); err != nil {
		t.Fatalf("decode severity: %v", err)
	}
	if err := json.Unmarshal(envelope["accountability"], &accountability); err != nil {
		t.Fatalf("decode accountability: %v", err)
	}
	severityNames := map[string]bool{"clear": true, "low": true, "medium": true, "high": true, "critical": true}
	if severityNames[accountability] {
		t.Fatalf("accountability %q intersects severity names", accountability)
	}
	if !severityNames[severity] {
		t.Fatalf("severity %q is not a severity level", severity)
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
