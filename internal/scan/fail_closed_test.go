package scan_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/use-assay/assay/internal/scan"
)

// TestFailClosedHorizonNon200AbortsTheScan pins F1–F3 of
// docs/fail-closed.md: a Horizon failure is fatal, so no Subject and no report
// exist at all. Building a Subject without the flags — the shape behind #25 —
// is structurally impossible from the live path because the scan aborts
// instead. Every non-200 status is exercised, because "fatal" must not hold
// only for the statuses someone thought to test.
func TestFailClosedHorizonNon200AbortsTheScan(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("{}"))
			}))
			t.Cleanup(srv.Close)

			sc := scan.New()
			sc.Horizon.BaseURL = srv.URL

			sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
			if err == nil {
				t.Fatalf("Horizon answering %d produced a Subject (%+v); the scan must abort", status, sub)
			}
			if !errors.Is(err, err) || sub != nil {
				t.Fatalf("Subject returned sub=%v err=%v on status %d; want nil subject with an error", sub, err, status)
			}
		})
	}

	t.Run("transport failure", func(t *testing.T) {
		// Point Horizon at a closed server so the request fails below HTTP.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		url := srv.URL
		srv.Close()

		sc := scan.New()
		sc.Horizon.BaseURL = url

		sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
		if err == nil || sub != nil {
			t.Fatalf("a transport failure produced sub=%v err=%v; want an abort", sub, err)
		}
	})
}
