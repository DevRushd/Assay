package mechanics_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/sep1"
)

const (
	domainIssuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
	otherIssuer  = "GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2"
)

// domainSubject builds the subject DomainCheck reasons over: a USDC issuer with
// a resolvable home_domain and a stellar.toml whose body the caller supplies.
// The document is parsed from TOML bytes rather than constructed, so the test
// exercises the same decoder the fetcher uses.
func domainSubject(t *testing.T, tomlBody string) *mechanics.Subject {
	t.Helper()
	doc, err := sep1.Parse([]byte(tomlBody))
	if err != nil {
		t.Fatalf("parse stellar.toml: %v", err)
	}
	doc.URL = "https://circle.com/.well-known/stellar.toml"
	doc.FetchedAt = time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)

	return &mechanics.Subject{
		Asset:     mechanics.Asset{Code: "USDC", Issuer: domainIssuer},
		Issuer:    &horizon.Account{AccountID: domainIssuer, HomeDomain: "circle.com"},
		Toml:      doc,
		TomlURL:   sep1.URLFor("circle.com"),
		ScannedAt: time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
	}
}

func runDomain(t *testing.T, s *mechanics.Subject) mechanics.Finding {
	t.Helper()
	f, err := mechanics.DomainCheck{}.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("DomainCheck.Run: %v", err)
	}
	return f
}

// TestDomainCheckHedgesOnLinkedEntryWithACode is the bug this fixes. A
// stellar.toml may carry an entry with both a toml link and a code that is not
// this asset. That entry points at a per-currency document Assay never read, so
// the domain may have claimed the asset there; the check must say "unconfirmed"
// rather than the flat "has not claimed this asset". Before the fix the entry
// was skipped by the count, and the unearned negative was emitted.
func TestDomainCheckHedgesOnLinkedEntryWithACode(t *testing.T) {
	f := runDomain(t, domainSubject(t, `
[[CURRENCIES]]
toml = "https://circle.com/.well-known/EURC.toml"
code = "EURC"
issuer = "`+otherIssuer+`"
`))

	if f.Accountability == nil {
		t.Fatal("domain check must always set accountability")
	}
	if *f.Accountability != mechanics.AccountabilityUnverified {
		t.Errorf("accountability = %q, want %q", *f.Accountability, mechanics.AccountabilityUnverified)
	}
	if f.Mechanics&mechanics.MechDomainUnverified == 0 {
		t.Error("the unverified bit must be set")
	}

	// The hedge wording must be present...
	for _, want := range []string{
		"is not declared inline",
		"may be claimed in one of them",
		"because it is unconfirmed, not because it was refuted",
	} {
		if !strings.Contains(f.Reasoning, want) {
			t.Errorf("hedged reasoning is missing %q:\n%s", want, f.Reasoning)
		}
	}
	// ...and the flat negative it replaces must not be, since the whole point
	// is that the domain may yet have claimed the asset.
	if strings.Contains(f.Reasoning, "has not claimed this asset") {
		t.Errorf("linked entry produced the unearned negative:\n%s", f.Reasoning)
	}

	if len(f.Evidence) != 1 {
		t.Fatalf("want exactly one evidence entry, got %d", len(f.Evidence))
	}
	if !strings.Contains(f.Evidence[0].Claim, "1 are links not followed") {
		t.Errorf("evidence claim must state the unfollowed link count: %q", f.Evidence[0].Claim)
	}
}

// TestDomainCheckLinkedEntryMatchingInlineIsVerified is the other half of the
// semantics: an entry that already matches inline IS the claim, so its link is
// irrelevant. It must be counted as unresolved neither for the asset it
// declares nor produce the hedge wording for that asset.
func TestDomainCheckLinkedEntryMatchingInlineIsVerified(t *testing.T) {
	s := domainSubject(t, `
[[CURRENCIES]]
toml = "https://circle.com/.well-known/USDC.toml"
code = "USDC"
issuer = "`+domainIssuer+`"
`)

	if got := s.Toml.LinkedCurrencies(s.Asset.Code, s.Asset.Issuer); got != 0 {
		t.Errorf("a matching inline entry must not count as unresolved: got %d", got)
	}

	f := runDomain(t, s)
	if f.Accountability == nil {
		t.Fatal("domain check must always set accountability")
	}
	if *f.Accountability != mechanics.AccountabilityVerified {
		t.Errorf("accountability = %q, want %q", *f.Accountability, mechanics.AccountabilityVerified)
	}
	if f.Mechanics&mechanics.MechDomainUnverified != 0 {
		t.Error("a verified reciprocal claim must not set the unverified bit")
	}
	if strings.Contains(f.Reasoning, "may be claimed in one of them") {
		t.Errorf("verified entry still hedged:\n%s", f.Reasoning)
	}
	if !strings.Contains(f.Reasoning, "reciprocal") {
		t.Errorf("verified reasoning must state the round trip:\n%s", f.Reasoning)
	}
}
