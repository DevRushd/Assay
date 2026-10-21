package sep1_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/use-assay/assay/internal/sep1"
)

// TestClassifyHost covers the host policy in isolation. It decides on the
// literal host only, which is what makes it testable without a network; the
// resolved-address half of the policy lives in CheckDialAddress.
func TestClassifyHost(t *testing.T) {
	cases := []struct {
		host   string
		public bool
		why    string
	}{
		// valid state: public hosts are allowed.
		{"circle.com", true, "ordinary public domain"},
		{"example.com", true, "ordinary public domain"},
		{"8.8.8.8", true, "public IPv4 literal"},
		{"1.1.1.1", true, "public IPv4 literal"},
		{"2606:4700:4700::1111", true, "public IPv6 literal"},
		{"EXAMPLE.COM", true, "case-insensitive"},

		// invalid state: non-public hosts are refused.
		{"127.0.0.1", false, "loopback IPv4"},
		{"127.0.0.1:8080", false, "loopback with port"},
		{"[::1]", false, "loopback IPv6"},
		{"::1", false, "loopback IPv6"},
		{"10.0.0.1", false, "private RFC1918 10/8"},
		{"172.16.0.1", false, "private RFC1918 172.16/12"},
		{"192.168.1.1", false, "private RFC1918 192.168/16"},
		{"fd00::1", false, "unique local IPv6 RFC4193"},
		{"169.254.169.254", false, "cloud metadata address"},
		{"fe80::1", false, "link-local IPv6"},
		{"0.0.0.0", false, "unspecified"},
		{"100.64.0.1", false, "shared address space RFC6598"},
		{"127.0.0.1:443", false, "loopback with port"},
		{"localhost", false, "loopback hostname"},
		{"foo.localhost", false, "loopback subdomain"},
		{"db.internal", false, "internal name suffix"},
		{"printer.local", false, "mDNS name suffix"},
		{"metadata.home.arpa", false, "home.arpa name suffix"},
		{"intranet", false, "single-label hostname"},
		{"", false, "empty host"},
	}

	for _, tc := range cases {
		public, reason := sep1.ClassifyHost(tc.host)
		if public != tc.public {
			t.Errorf("ClassifyHost(%q) public = %v, want %v (%s); reason=%q",
				tc.host, public, tc.public, tc.why, reason)
			continue
		}
		if !public && reason == "" {
			t.Errorf("ClassifyHost(%q) refused without a reason", tc.host)
		}
		if public && reason != "" {
			t.Errorf("ClassifyHost(%q) allowed but gave reason %q", tc.host, reason)
		}
	}
}

// TestCheckDialAddress is the resolved-address half of the policy, exercised
// with the address forms a dialer actually passes to net.Dialer.Control.
func TestCheckDialAddress(t *testing.T) {
	refused := []string{
		"127.0.0.1:443",
		"[::1]:443",
		"169.254.169.254:80",
		"10.1.2.3:443",
		"192.168.0.10:443",
		"172.20.0.5:443",
		"fd00::5:443",
	}
	for _, addr := range refused {
		err := sep1.CheckDialAddress(addr)
		if err == nil {
			t.Errorf("CheckDialAddress(%q) = nil, want refusal", addr)
			continue
		}
		if !errors.Is(err, sep1.ErrNonPublicHost) {
			t.Errorf("CheckDialAddress(%q) error = %v, want ErrNonPublicHost", addr, err)
		}
		var refusedErr *sep1.HostRefusedError
		if !errors.As(err, &refusedErr) {
			t.Errorf("CheckDialAddress(%q) error is not a *HostRefusedError: %v", addr, err)
		}
	}

	for _, addr := range []string{"1.1.1.1:443", "8.8.8.8:443", "[2606:4700:4700::1111]:443"} {
		if err := sep1.CheckDialAddress(addr); err != nil {
			t.Errorf("CheckDialAddress(%q) = %v, want nil", addr, err)
		}
	}
}

// TestFetchRefusesNonPublicHost is the acceptance test for #76 at the fetch
// layer: a non-public home_domain is refused before any request is made, and
// the refusal is programmatically distinguishable from an ordinary fetch
// failure.
func TestFetchRefusesNonPublicHost(t *testing.T) {
	for _, domain := range []string{
		"127.0.0.1",
		"localhost",
		"10.0.0.1",
		"169.254.169.254",
		"db.internal",
	} {
		t.Run(domain, func(t *testing.T) {
			var called atomic.Int32
			f := sep1.NewFetcher()
			f.HTTP = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				called.Add(1)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     http.Header{},
					Request:    req,
				}, nil
			})}

			_, err := f.Fetch(context.Background(), domain)
			if err == nil {
				t.Fatalf("Fetch(%q) succeeded, want a host-policy refusal", domain)
			}
			if !errors.Is(err, sep1.ErrNonPublicHost) {
				t.Fatalf("Fetch(%q) error = %v, want ErrNonPublicHost", domain, err)
			}
			var refusedErr *sep1.HostRefusedError
			if !errors.As(err, &refusedErr) {
				t.Fatalf("Fetch(%q) error is not a *HostRefusedError: %v", domain, err)
			}
			if got := called.Load(); got != 0 {
				t.Fatalf("Fetch(%q) made %d requests; a refused host must not be contacted", domain, got)
			}
		})
	}
}

// TestFetchRefusalDiffersFromTimeout pins the distinction the issue asks for:
// a refusal is not an ordinary fetch failure. A timeout is a *url.Error, not a
// *HostRefusedError, and errors.Is(err, ErrNonPublicHost) is false for it.
func TestFetchRefusalDiffersFromTimeout(t *testing.T) {
	f := sep1.NewFetcher()
	f.HTTP = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}

	_, timeoutErr := f.Fetch(context.Background(), "public-host.example")
	if timeoutErr == nil {
		t.Fatal("expected the stub transport to fail")
	}
	if errors.Is(timeoutErr, sep1.ErrNonPublicHost) {
		t.Fatalf("a timeout was classified as a host refusal: %v", timeoutErr)
	}
	var refusedErr *sep1.HostRefusedError
	if errors.As(timeoutErr, &refusedErr) {
		t.Fatalf("a timeout was typed as a host refusal: %v", timeoutErr)
	}

	_, err := f.Fetch(context.Background(), "10.0.0.1")
	if !errors.Is(err, sep1.ErrNonPublicHost) {
		t.Fatalf("a refused host was not classified as a refusal: %v", err)
	}
}

// TestFetchAllowsPublicHost proves the policy is not a blanket refusal: a
// public host still proceeds to the transport, and the document parses.
func TestFetchAllowsPublicHost(t *testing.T) {
	var called atomic.Int32
	f := sep1.NewFetcher()
	f.HTTP = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		called.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     http.Header{},
			Request:    req,
		}, nil
	})}

	doc, err := f.Fetch(context.Background(), "circle.com")
	if err != nil {
		t.Fatalf("Fetch(circle.com): %v", err)
	}
	if doc == nil {
		t.Fatal("Fetch(circle.com) returned a nil document")
	}
	if got := called.Load(); got != 1 {
		t.Fatalf("the transport was called %d times, want exactly 1", got)
	}
}
