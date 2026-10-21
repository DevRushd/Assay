package attest_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/sep1"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// The escaping unit test constructs the hostile claim directly
// (TestSeparatorsInClaimsCannotForgeALine). That proves the encoder escapes a
// string; it does not prove the string can arrive that way. The actual threat
// is third-party text arriving over HTTP, flowing through the check into an
// evidence claim, and then into the hashed preimage.
//
// This test carries a hostile directory entry through that full path — stubbed
// HTTP response -> stellarexpert decode -> reputation check -> evidence claim ->
// preimage — so the escape is exercised where the threat lives. The directory
// name is attacker-influenced: it is curated by StellarExpert, but the value
// originates from the entity being described.
func TestDirectoryNameInjectionCannotForgePreimage(t *testing.T) {
	const issuer = "GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P"

	// A name, domain and tag each carrying every escapable control character,
	// plus a literal backslash-t sequence that must not be double-decoded into
	// a tab. The JSON escapes are decoded by the client into real control
	// characters, so the check receives what a hostile source would send.
	hostile := `{"address":"` + issuer + `",` +
		`"name":"Evil\tName\nSecond\rLine\\Path\tand\\tseq",` +
		`"domain":"evil\t.example\n\r.com",` +
		`"tags":["issuer","a\tb\nc\rd\\e"]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(hostile))
	}))
	t.Cleanup(srv.Close)

	client := stellarexpert.New(srv.URL)
	entry, err := client.Directory(context.Background(), issuer)
	if err != nil {
		t.Fatalf("Directory: %v", err)
	}
	if entry.Value == nil {
		t.Fatal("the stubbed entry was dropped; the test would prove nothing")
	}
	// If the control characters did not survive decoding, the rest of the test
	// is vacuous rather than passing.
	if !strings.ContainsRune(entry.Value.Name, '\n') || !strings.ContainsRune(entry.Value.Name, '\t') || !strings.ContainsRune(entry.Value.Name, '\r') {
		t.Fatalf("hostile name did not survive decoding: %q", entry.Value.Name)
	}

	sub := &mechanics.Subject{
		Asset: mechanics.Asset{Code: "DOGE", Issuer: issuer},
		// A home_domain is advertised, so the reputation check does not treat
		// the blocklist as unaskable; this test is about the directory claim.
		Issuer:       &horizon.Account{AccountID: issuer, HomeDomain: "blocked.example"},
		Directory:    entry.Value,
		DirectoryURL: client.DirectoryURL(issuer),
	}
	// Only the reputation check: the claim under test is the one this check
	// builds from the hostile directory entry.
	engine := &mechanics.Engine{Checks: []mechanics.Check{mechanics.ReputationCheck{}}}
	rep, err := engine.Run(context.Background(), sub)
	if err != nil {
		t.Fatalf("run reputation check: %v", err)
	}

	params, err := attest.FromReport(rep)
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}

	// Expected shape: version + six header fields + the bound check set + two
	// evidence lines (the directory listing and the unrecognised hostile tag),
	// with the hostile text escaped inside its own field. A stray newline or an
	// injected record would move this count.
	const wantLines = 10
	if got := strings.Count(params.Preimage, "\n"); got != wantLines {
		t.Fatalf("hostile text changed the preimage line count: got %d, want %d\n%s", got, wantLines, params.Preimage)
	}

	evidence := evidenceLines(params.Preimage)
	if len(evidence) != 2 {
		t.Fatalf("expected the directory listing and the unrecognised tag as two evidence lines, got %d:\n%s", len(evidence), params.Preimage)
	}
	// A forged line would show up as an extra record attributed to a source the
	// hostile text named rather than the real one.
	if strings.Contains(params.Preimage, "\nevidence\thorizon\t") {
		t.Fatalf("a claim forged a horizon evidence line:\n%s", params.Preimage)
	}
	// Exactly four tab-separated fields: "evidence", source, URL, claim. A raw
	// tab in the claim — from a control character that escaped its field, or a
	// backslash-t that was decoded — would add a field. Checked for every
	// evidence line, since both carry hostile text.
	for _, line := range evidence {
		if fields := strings.Split(line, "\t"); len(fields) != 4 {
			t.Fatalf("evidence line has %d tab-separated fields, want 4 (a control character left its field):\n%q", len(fields), line)
		}
	}
	// The literal backslash-t in the name must be escaped to `\\t`, not decoded
	// into a real tab.
	if !strings.Contains(params.Preimage, `\\t`) {
		t.Fatalf("literal backslash-t was not preserved as an escape:\n%s", params.Preimage)
	}
}

// tomlRoundTripper adapts a function to http.RoundTripper for the fetch below.
type tomlRoundTripper func(*http.Request) (*http.Response, error)

func (f tomlRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// The organisation fields are the same threat from the other direction, aimed
// at the document instead of a curated entry: a hostile stellar.toml chooses
// ORG_NAME and ORG_URL, and both now flow into an evidence claim that is
// hashed into the attestation preimage. No unit test on either side — not the
// sep1 parse, not the domain check, not the encoder — proves the string can
// arrive that way and still stay inside its field.
//
// So this test carries a hostile document through the full path — stubbed HTTP
// response -> sep1 fetch and parse -> domain check -> evidence claim ->
// preimage — with every escapable control character in BOTH fields, a literal
// backslash-t that must not be decoded into a tab, and a complete forged
// evidence line that must not become one. The stub transport is the real fetch
// path minus the network: the URL scheme, host policy and parse error handling
// all run exactly as they do against a live domain.
func TestTomlOrganisationInjectionCannotForgePreimage(t *testing.T) {
	const issuer = "GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P"

	// Both organisation fields carrying real control characters (the TOML
	// escapes are decoded into them by the parser), the literal two-character
	// backslash-t sequence, and — inside ORG_NAME — a whole forged evidence
	// line starting at a raw newline. The document still claims the asset, so
	// the check runs its verified path and emits the attribution.
	hostile := `
[DOCUMENTATION]
ORG_NAME = "Evil\tCorp\nSecond\rLine\\Path\tand\\tseq\nevidence\thorizon\thttps://evil\tissuer flags: none"
ORG_URL = "https://evil\t.example\n\r.com"

[[CURRENCIES]]
code = "DOGE"
issuer = "` + issuer + `"
`

	f := sep1.NewFetcher()
	f.HTTP = &http.Client{Transport: tomlRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(hostile)),
			Header:     http.Header{},
			Request:    req,
		}, nil
	})}

	doc, err := f.Fetch(context.Background(), "evil.example")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// If the control characters did not survive parsing, the rest of the test
	// is vacuous rather than passing.
	if !strings.ContainsRune(doc.Documentation.OrgName, '\n') || !strings.ContainsRune(doc.Documentation.OrgName, '\t') || !strings.ContainsRune(doc.Documentation.OrgName, '\r') {
		t.Fatalf("hostile ORG_NAME did not survive parsing: %q", doc.Documentation.OrgName)
	}
	if !strings.ContainsRune(doc.Documentation.OrgURL, '\n') || !strings.ContainsRune(doc.Documentation.OrgURL, '\t') {
		t.Fatalf("hostile ORG_URL did not survive parsing: %q", doc.Documentation.OrgURL)
	}
	if !strings.Contains(doc.Documentation.OrgName, `and\tseq`) {
		t.Fatalf("literal backslash-t did not survive parsing: %q", doc.Documentation.OrgName)
	}

	sub := &mechanics.Subject{
		Asset:  mechanics.Asset{Code: "DOGE", Issuer: issuer},
		Issuer: &horizon.Account{AccountID: issuer, HomeDomain: "evil.example"},
		Toml:   doc,
		// The document URL both claims are attributed to.
		TomlURL: sep1.URLFor("evil.example"),
	}
	// Only the domain check: the claims under test are the two this check builds
	// from the hostile document — the reciprocity claim and the attribution.
	engine := &mechanics.Engine{Checks: []mechanics.Check{mechanics.DomainCheck{}}}
	rep, err := engine.Run(context.Background(), sub)
	if err != nil {
		t.Fatalf("run domain check: %v", err)
	}

	params, err := attest.FromReport(rep)
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}

	// Expected shape: version + six header fields + the bound check set + two
	// evidence lines (the CURRENCIES claim and the organisation attribution),
	// with the hostile text escaped inside its own field. A stray newline or an
	// injected record would move this count.
	const wantLines = 10
	if got := strings.Count(params.Preimage, "\n"); got != wantLines {
		t.Fatalf("hostile text changed the preimage line count: got %d, want %d\n%s", got, wantLines, params.Preimage)
	}

	evidence := evidenceLines(params.Preimage)
	if len(evidence) != 2 {
		t.Fatalf("expected the reciprocity claim and the organisation attribution as two evidence lines, got %d:\n%s", len(evidence), params.Preimage)
	}
	// A forged line would show up as an extra record attributed to a source the
	// hostile text named rather than the real one.
	if strings.Contains(params.Preimage, "\nevidence\thorizon\t") {
		t.Fatalf("a claim forged a horizon evidence line:\n%s", params.Preimage)
	}
	// Exactly four tab-separated fields: "evidence", source, URL, claim. A raw
	// tab in a claim — from a control character that escaped its field, or a
	// backslash-t that was decoded — would add a field.
	for _, line := range evidence {
		if fields := strings.Split(line, "\t"); len(fields) != 4 {
			t.Fatalf("evidence line has %d tab-separated fields, want 4 (a control character left its field):\n%q", len(fields), line)
		}
	}

	// Both fields reached one claim, attributed with source and URL, and both
	// are written in the escaped form: every real control character came out as
	// a backslash escape rather than as itself.
	var orgLine string
	for _, line := range evidence {
		if strings.Contains(line, "ORG_NAME") {
			orgLine = line
		}
	}
	if orgLine == "" {
		t.Fatalf("no organisation attribution in the preimage:\n%s", params.Preimage)
	}
	if !strings.HasPrefix(orgLine, "evidence\tstellar.toml\thttps://evil.example/.well-known/stellar.toml\tORG_NAME") {
		t.Fatalf("attribution is not attributed with source and URL:\n%q", orgLine)
	}
	if !strings.Contains(orgLine, "ORG_URL") {
		t.Fatalf("the same evidence line must carry both fields:\n%q", orgLine)
	}
	// ORG_NAME: real tab, newline and CR escaped by the quoting, and the
	// single backslash of `\\Path` doubled — first by the quoting, then by the
	// encoder, the same two-step every other issuer-controlled string gets.
	if !strings.Contains(params.Preimage, `ORG_NAME "Evil\\tCorp\\nSecond\\rLine\\\\Path\\tand\\\\tseq`) {
		t.Fatalf("ORG_NAME was not escaped into its own field:\n%s", params.Preimage)
	}
	// ORG_URL: the same treatment for the second field this test covers.
	if !strings.Contains(params.Preimage, `ORG_URL "https://evil\\t.example\\n\\r.com"`) {
		t.Fatalf("ORG_URL was not escaped into its own field:\n%s", params.Preimage)
	}
}

// evidenceLines returns the preimage's evidence records, which are the only
// lines whose contents are influenced by third-party text.
func evidenceLines(preimage string) []string {
	var out []string
	for _, line := range strings.Split(preimage, "\n") {
		if strings.HasPrefix(line, "evidence\t") {
			out = append(out, line)
		}
	}
	return out
}
