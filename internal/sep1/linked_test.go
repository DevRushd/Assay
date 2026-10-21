package sep1_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/sep1"
)

const linkedIssuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

// routedTransport answers requests from a fixed map, so the linked-document
// tests never touch a network. An unmapped URL is an error, which doubles as
// the assertion that only the expected documents are fetched.
type routedTransport struct {
	routes map[string]routedResponse
}

type routedResponse struct {
	status int
	body   string
	err    error
}

func (t routedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r, ok := t.routes[req.URL.String()]
	if !ok {
		return nil, fmt.Errorf("routedTransport: unexpected request %s", req.URL)
	}
	if r.err != nil {
		return nil, r.err
	}
	status := r.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Header:     http.Header{},
		Request:    req,
	}, nil
}

func linkedFetcher(routes map[string]routedResponse) *sep1.Fetcher {
	f := sep1.NewFetcher()
	f.HTTP = &http.Client{Transport: routedTransport{routes: routes}}
	return f
}

func currencyDoc(t *testing.T, body string) *sep1.Doc {
	t.Helper()
	doc, err := sep1.Parse([]byte(body))
	if err != nil {
		t.Fatalf("parse toml: %v", err)
	}
	return doc
}

// TestResolveLinkedClaims is the primary acceptance case for #78: an issuer
// that delegates its currency entry to a per-currency TOML is verified when
// that document names this exact code and issuer.
func TestResolveLinkedClaims(t *testing.T) {
	doc := currencyDoc(t, `
[[CURRENCIES]]
toml = "https://links.example/USDC.toml"

[[CURRENCIES]]
toml = "https://links.example/EURC.toml"
`)
	f := linkedFetcher(map[string]routedResponse{
		"https://links.example/USDC.toml": {
			body: fmt.Sprintf("[[CURRENCIES]]\ncode=\"USDC\"\nissuer=\"%s\"\n", linkedIssuer),
		},
		"https://links.example/EURC.toml": {
			body: "[[CURRENCIES]]\ncode=\"EURC\"\nissuer=\"GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2\"\n",
		},
	})

	res := f.ResolveLinked(context.Background(), doc, "USDC", linkedIssuer)
	if !res.Claimed {
		t.Fatal("a linked document naming the asset was not treated as a claim")
	}
	if res.ClaimedURL != "https://links.example/USDC.toml" {
		t.Errorf("ClaimedURL = %q, want the USDC link", res.ClaimedURL)
	}
	if res.Deferred != 0 {
		t.Errorf("Deferred = %d, want 0", res.Deferred)
	}
}

// TestResolveLinkedNoneClaim covers the invalid state: every link was read and
// none names the asset, which is a genuine refusal rather than an unresolved
// hedge.
func TestResolveLinkedNoneClaim(t *testing.T) {
	doc := currencyDoc(t, `
[[CURRENCIES]]
toml = "https://links.example/USDC.toml"
`)
	f := linkedFetcher(map[string]routedResponse{
		"https://links.example/USDC.toml": {
			body: "[[CURRENCIES]]\ncode=\"XLM\"\nissuer=\"other\"\n",
		},
	})

	res := f.ResolveLinked(context.Background(), doc, "USDC", linkedIssuer)
	if res.Claimed {
		t.Fatal("a linked document that does not name the asset was treated as a claim")
	}
	if res.Attempted != 1 || res.Deferred != 0 {
		t.Fatalf("Attempted=%d Deferred=%d, want 1 and 0", res.Attempted, res.Deferred)
	}
	if len(res.Docs) != 1 || res.Docs[0].Err != "" {
		t.Fatalf("expected one successfully read document, got %+v", res.Docs)
	}
}

// TestResolveLinkedOneHopOnly pins the bound on recursion: a linked document's
// own links are not followed, so a cycle cannot make the scanner fetch forever.
func TestResolveLinkedOneHopOnly(t *testing.T) {
	doc := currencyDoc(t, `
[[CURRENCIES]]
toml = "https://links.example/USDC.toml"
`)
	f := linkedFetcher(map[string]routedResponse{
		"https://links.example/USDC.toml": {
			body: "[[CURRENCIES]]\ntoml = \"https://links.example/OTHER.toml\"\n",
		},
	})

	res := f.ResolveLinked(context.Background(), doc, "USDC", linkedIssuer)
	if res.Attempted != 1 {
		t.Fatalf("Attempted = %d, want 1 (one hop only)", res.Attempted)
	}
	if res.Claimed {
		t.Fatal("a nested link must not be treated as a claim")
	}
}

// TestResolveLinkedUnfetchable covers the unavailable state: a link that could
// not be read leaves the answer unresolved and is recorded verbatim.
func TestResolveLinkedUnfetchable(t *testing.T) {
	doc := currencyDoc(t, `
[[CURRENCIES]]
toml = "https://links.example/USDC.toml"
`)
	f := linkedFetcher(map[string]routedResponse{
		"https://links.example/USDC.toml": {err: fmt.Errorf("connection refused")},
	})

	res := f.ResolveLinked(context.Background(), doc, "USDC", linkedIssuer)
	if res.Claimed {
		t.Fatal("an unfetchable link must not produce a claim")
	}
	if len(res.Docs) != 1 || res.Docs[0].Err == "" {
		t.Fatalf("unfetchable link was not recorded: %+v", res.Docs)
	}
	if res.Docs[0].Refused {
		t.Error("an ordinary fetch failure must not be marked as a host-policy refusal")
	}
}

// TestResolveLinkedRefusesNonPublicHost shows the linked fetches obey the same
// host policy as the main document: a link to a private address is refused and
// recorded as a refusal, not an outage.
func TestResolveLinkedRefusesNonPublicHost(t *testing.T) {
	doc := currencyDoc(t, `
[[CURRENCIES]]
toml = "https://127.0.0.1/.well-known/USDC.toml"
`)
	f := linkedFetcher(nil)

	res := f.ResolveLinked(context.Background(), doc, "USDC", linkedIssuer)
	if res.Claimed {
		t.Fatal("a refused link must not produce a claim")
	}
	if len(res.Docs) != 1 || !res.Docs[0].Refused {
		t.Fatalf("non-public linked host was not recorded as a refusal: %+v", res.Docs)
	}
}

// TestResolveLinkedBound covers the unknown state: more links than the bound is
// not read, so the answer is unresolved and the number deferred is reported.
func TestResolveLinkedBound(t *testing.T) {
	var b strings.Builder
	routes := map[string]routedResponse{}
	total := sep1.MaxLinkedDocuments + 3
	for i := 0; i < total; i++ {
		url := fmt.Sprintf("https://links.example/C%d.toml", i)
		fmt.Fprintf(&b, "[[CURRENCIES]]\ntoml = %q\n\n", url)
		routes[url] = routedResponse{body: "[[CURRENCIES]]\ncode=\"OTHER\"\nissuer=\"other\"\n"}
	}
	doc := currencyDoc(t, b.String())

	res := linkedFetcher(routes).ResolveLinked(context.Background(), doc, "USDC", linkedIssuer)
	if res.Deferred != 3 {
		t.Errorf("Deferred = %d, want 3", res.Deferred)
	}
	if res.Attempted != sep1.MaxLinkedDocuments {
		t.Errorf("Attempted = %d, want the %d-document bound", res.Attempted, sep1.MaxLinkedDocuments)
	}
	if res.Claimed {
		t.Error("a bound-truncated scan must not report a claim")
	}
}

// TestResolveLinkedNilDoc is the empty case: no document means no links, and
// the result is an empty resolution rather than nil, so a caller cannot confuse
// "not followed" with "followed and found nothing".
func TestResolveLinkedNilDoc(t *testing.T) {
	res := linkedFetcher(nil).ResolveLinked(context.Background(), nil, "USDC", linkedIssuer)
	if res == nil {
		t.Fatal("ResolveLinked(nil) returned nil, want an empty resolution")
	}
	if res.Attempted != 0 || res.Claimed || len(res.Docs) != 0 {
		t.Fatalf("ResolveLinked(nil) = %+v, want empty", res)
	}
}
