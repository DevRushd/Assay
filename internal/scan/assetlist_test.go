package scan_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/scan"
)

// End-to-end coverage for consuming configured SEP-0042 lists: the fetch, the
// per-list attribution on the Subject, and what reaches the report. Everything
// is served by httptest, so the suite stays hermetic.

// serveList stands up a list server and counts the requests it received, so a
// test can assert one fetch per configured list.
func serveList(t *testing.T, body string, status int) (*httptest.Server, *int) {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

const (
	listCode   = "USDC"
	listIssuer = scanIssuer // the issuer newFakeSources serves
)

// listBody is a conforming SEP-0042 document; withEntry decides whether it
// contains the asset under scan.
func listBody(name string, withEntry bool) string {
	assets := `"assets":[{"code":"OTHER","issuer":"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF","name":"Other","org":"Elsewhere"}]`
	if withEntry {
		assets = `"assets":[{"code":"` + listCode + `","issuer":"` + listIssuer +
			`","name":"USD Coin","org":"Centre","domain":"centre.test","decimals":7}]`
	}
	return `{"name":"` + name + `","provider":"` + name + ` Collective","description":"d",` +
		`"version":"1.0","network":"public",` + assets + `}`
}

// The acceptance case: two lists with different answers plus one that is down,
// all three visible as three separate statements.
func TestAssetListsAreFetchedAndAttributedPerList(t *testing.T) {
	fs := newFakeSources(t)
	alpha, alphaHits := serveList(t, listBody("Alpha List", true), http.StatusOK)
	beta, betaHits := serveList(t, listBody("Beta List", false), http.StatusOK)
	dead, deadHits := serveList(t, "", http.StatusServiceUnavailable)

	sc := scan.New()
	sc.Horizon.BaseURL = fs.horizon.URL
	sc.Expert.BaseURL = fs.expert.URL
	sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(fs.toml.URL, "http://")}
	sc.AssetListURLs = []string{alpha.URL, beta.URL, dead.URL}

	start := time.Now().UTC()
	sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}

	if len(sub.AssetLists) != 3 {
		t.Fatalf("want one signal per configured list, got %d", len(sub.AssetLists))
	}
	// Configuration order is preserved, so a report reads in the order the
	// operator configured.
	wantURLs := []string{alpha.URL, beta.URL, dead.URL}
	for i, want := range wantURLs {
		if sub.AssetLists[i].URL != want {
			t.Fatalf("signal %d fetched %q, want the configured %q", i, sub.AssetLists[i].URL, want)
		}
	}

	a, b, c := sub.AssetLists[0], sub.AssetLists[1], sub.AssetLists[2]
	if a.Name != "Alpha List" || a.Provider != "Alpha List Collective" || a.Version != "1.0" {
		t.Errorf("list A self-description lost: %+v", a)
	}
	if !a.Listed || a.Entry == nil {
		t.Fatalf("list A contains the asset but was recorded as absent: %+v", a)
	}
	if a.Entry.Name != "USD Coin" || a.Entry.Domain != "centre.test" {
		t.Errorf("list A entry decoded wrongly: %+v", a.Entry)
	}
	if b.Listed || b.Entry != nil || b.Err != "" {
		t.Errorf("list B was read and lacks the asset, but was recorded as %+v", b)
	}
	if c.Err == "" || c.Listed {
		t.Errorf("list C is down but was recorded as a clean answer: %+v", c)
	}
	if c.Name != "" {
		t.Errorf("an unreadable list should not claim a name it never gave: %q", c.Name)
	}
	if a.FetchedAt.IsZero() || b.FetchedAt.IsZero() {
		t.Error("a list that was read records no fetch time, so its evidence could not be aged")
	}
	if a.FetchedAt.Before(start) {
		t.Errorf("list A fetch time %s predates the scan", a.FetchedAt)
	}
	if *alphaHits != 1 || *betaHits != 1 || *deadHits != 1 {
		t.Errorf("lists fetched %d, %d, %d times; want 1 each", *alphaHits, *betaHits, *deadHits)
	}

	rep, err := sc.Engine.Run(context.Background(), sub)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Escalated || rep.Severity != rep.Base {
		t.Errorf("lists moved severity: base=%v severity=%v escalated=%v",
			rep.Base, rep.Severity, rep.Escalated)
	}

	// Three claims, each attributed to its own list by name and URL.
	bySource := map[string]string{}
	for _, ev := range rep.Evidence {
		if strings.HasPrefix(ev.Source, "asset-list") {
			bySource[ev.Source] = ev.Claim
		}
	}
	if len(bySource) != 3 {
		t.Fatalf("want three separately attributed claims, got %v", bySource)
	}
	if claim := bySource["asset-list/Alpha List"]; !strings.Contains(claim, "listed as") {
		t.Errorf("Alpha's claim is %q", claim)
	}
	if claim := bySource["asset-list/Beta List"]; !strings.Contains(claim, "not present in list") {
		t.Errorf("Beta's claim is %q", claim)
	}
	if claim := bySource["asset-list"]; !strings.Contains(claim, "not retrievable") {
		t.Errorf("the down list's claim is %q (it has no name to attribute it by, only its URL)", claim)
	}

	reasoning := ""
	for _, f := range rep.Findings {
		if f.Check == "reputation" {
			reasoning = f.Reasoning
		}
	}
	if !strings.Contains(reasoning, "Sources disagree") {
		t.Errorf("the lists disagreeing was not reported: %q", reasoning)
	}
	if !strings.Contains(reasoning, "could not be read") {
		t.Errorf("the down list was not reported in the reasoning: %q", reasoning)
	}
	if rep.Undetermined {
		t.Error("an unreadable asset list marked the report undetermined; it cannot change severity")
	}
}

// The default: no list is configured, so the scanner consults none. This is
// what keeps a plain scan identical to the reports produced before lists
// existed — including every evidence_hash.
func TestNoAssetListsConfiguredByDefault(t *testing.T) {
	fs := newFakeSources(t)

	sc := scan.New()
	sc.Horizon.BaseURL = fs.horizon.URL
	sc.Expert.BaseURL = fs.expert.URL
	sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(fs.toml.URL, "http://")}

	if len(sc.AssetListURLs) != 0 {
		t.Fatalf("New() configured %v lists; none is the default", sc.AssetListURLs)
	}

	sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}
	if len(sub.AssetLists) != 0 {
		t.Fatalf("a scan consulted %d asset lists without any configured", len(sub.AssetLists))
	}
}
