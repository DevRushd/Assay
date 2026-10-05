package attest_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
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
