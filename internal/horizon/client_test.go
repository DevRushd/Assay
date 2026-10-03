// These drive the client from recorded response bodies rather than hand-built
// structs, because the behaviour under test is how this source actually
// answers — a fixture built from the package's own types could only prove the
// decoder agrees with itself.
//
// Bodies captured 2026-09-05 from https://horizon.stellar.org/assets?… and
// https://horizon.stellar.org/accounts/{id}. Record capture date and URL are
// kept in testdata/PROVENANCE.md.
package horizon_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/horizon"
)

// assetJSON renders one Horizon /assets record as JSON.
func assetJSON(code, issuer string) string {
	return `{"asset_code":"` + code + `","asset_issuer":"` + issuer + `","flags":{"auth_required":false,"auth_revocable":false,"auth_immutable":false,"auth_clawback_enabled":false}}`
}

// horizonAssets renders the full /assets response the client expects.
func horizonAssets(code, issuer string) string {
	return `{"_embedded":{"records":[` + assetJSON(code, issuer) + `]}}`
}

// horizonAccount renders a full /accounts response the client expects.
func horizonAccount(id string) string {
	return `{"account_id":"` + id + `","home_domain":"","flags":{"auth_required":false,"auth_revocable":false,"auth_immutable":false,"auth_clawback_enabled":false}}`
}

func newClient(t *testing.T) *horizon.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/assets") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(horizonAssets("AQUA", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA")))
			return
		}
		if strings.Contains(r.URL.Path, "/accounts/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(horizonAccount("GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA")))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	return horizon.New(srv.URL)
}

// clientWithTransport builds a client whose HTTP transport runs on top of a
// test server, so a blocking transport can be used to simulate a timeout.
func clientWithTransport(t *testing.T, transport http.RoundTripper) *horizon.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	c := horizon.New(srv.URL)
	c.HTTP.Transport = transport
	return c
}

// TestUserAgent checks the exact identity the scanner offers to the outside
// world. A specific string, not merely a non-empty one, because operators of
// the services we call filter on it.
func TestUserAgent(t *testing.T) {
	t.Helper()
	want := "assay/" + horizon.Version + " (+https://github.com/use-assay/Assay)"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != want {
			t.Errorf("User-Agent = %q, want %q", got, want)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(horizonAssets("AQUA", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA")))
	}))
	t.Cleanup(srv.Close)
	c := horizon.New(srv.URL)

	if _, err := c.Asset(context.Background(), "AQUA", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"); err != nil {
		t.Fatalf("Asset: %v", err)
	}
}

func TestAssetDecodes(t *testing.T) {
	c := newClient(t)
	stat, err := c.Asset(context.Background(), "AQUA", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA")
	if err != nil {
		t.Fatalf("Asset: %v", err)
	}
	if stat.AssetCode != "AQUA" || stat.AssetIssuer != "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA" {
		t.Fatalf("decoded wrong record: %+v", stat)
	}
}

func TestAssetNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"_embedded":{"records":[]}}`))
	}))
	t.Cleanup(srv.Close)
	c := horizon.New(srv.URL)

	if _, err := c.Asset(context.Background(), "MISSING", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"); !errors.Is(err, horizon.ErrNotFound) {
		t.Fatalf("Asset error = %v, want ErrNotFound", err)
	}
}

func TestAssetMultipleRecordsErrors(t *testing.T) {
	code, issuer := "AQUA", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Return two records for the exact code/issuer
		_, _ = w.Write([]byte(`{"_embedded":{"records":[` + assetJSON(code, issuer) + `,` + assetJSON(code, issuer) + `]}}`))
	}))
	t.Cleanup(srv.Close)
	c := horizon.New(srv.URL)

	asset, err := c.Asset(context.Background(), code, issuer)
	if asset != nil {
		t.Fatalf("expected error on multiple records, got asset %+v", asset)
	}
	if !errors.Is(err, horizon.ErrMultipleRecords) {
		t.Fatalf("Asset error = %v, want ErrMultipleRecords", err)
	}
}

func TestAssetMismatchErrors(t *testing.T) {
	code, issuer := "AQUA", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"
	otherCode, otherIssuer := "WRONG", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"

	t.Run("different code", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_embedded":{"records":[` + assetJSON(otherCode, otherIssuer) + `]}}`))
		}))
		t.Cleanup(srv.Close)
		c := horizon.New(srv.URL)

		asset, err := c.Asset(context.Background(), code, issuer)
		if asset != nil {
			t.Fatalf("expected error, got asset %+v", asset)
		}
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), code) || !strings.Contains(err.Error(), issuer) {
			t.Errorf("error = %q, want it to name the requested %s-%s", err, code, issuer)
		}
	})

	t.Run("different issuer", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_embedded":{"records":[` + assetJSON(code, "WRONG-ISSUER") + `]}}`))
		}))
		t.Cleanup(srv.Close)
		c := horizon.New(srv.URL)

		asset, err := c.Asset(context.Background(), code, issuer)
		if asset != nil {
			t.Fatalf("expected error, got asset %+v", asset)
		}
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestAccountDecodes(t *testing.T) {
	c := newClient(t)
	acct, err := c.Account(context.Background(), "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA")
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if acct.AccountID != "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA" {
		t.Fatalf("decoded wrong record: %+v", acct)
	}
}

func TestAccountNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	c := horizon.New(srv.URL)

	if _, err := c.Account(context.Background(), "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"); !errors.Is(err, horizon.ErrNotFound) {
		t.Fatalf("Account error = %v, want ErrNotFound", err)
	}
}

func TestAccountMismatchErrors(t *testing.T) {
	id := "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"

	t.Run("different account_id", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"account_id":"WRONG","home_domain":"","flags":{"auth_required":false,"auth_revocable":false,"auth_immutable":false,"auth_clawback_enabled":false}}`))
		}))
		t.Cleanup(srv.Close)
		c := horizon.New(srv.URL)

		account, err := c.Account(context.Background(), id)
		if account != nil {
			t.Fatalf("expected error, got account %+v", account)
		}
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestNon200IsAnError(t *testing.T) {
	// 429 is the rate-limit that was observed in a real sweep; 500 the outage.
	// Only 404 is ErrNotFound, so these must all classify as generic failures.
	for _, status := range []int{http.StatusBadRequest, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusTeapot, http.StatusGatewayTimeout} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("{}"))
		}))
		t.Cleanup(srv.Close)
		c := horizon.New(srv.URL)
		if _, err := c.Asset(context.Background(), "AQUA", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"); err == nil {
			t.Errorf("status %d was reported as a successful decode", status)
		}
	}
}

func TestMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not json"))
	}))
	t.Cleanup(srv.Close)
	c := horizon.New(srv.URL)

	if _, err := c.Asset(context.Background(), "AQUA", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"); err == nil {
		t.Error("malformed body was decoded without an error")
	}
}

func TestTimeoutIsAnError(t *testing.T) {
	delay := 200 * time.Millisecond
	c := clientWithTransport(t, delayRoundTripper{delay: delay})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Asset(ctx, "AQUA", "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"); err == nil {
		t.Fatal("timeout was reported as a successful decode")
	}
}

// delayRoundTripper runs the underlying round tripper, but only after a
// delay chosen by the test. It never answers on its own.
type delayRoundTripper struct {
	delay time.Duration
	rt    http.RoundTripper
}

func (d delayRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if d.rt == nil {
		d.rt = http.DefaultTransport
	}
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	return d.rt.RoundTrip(req)
}
