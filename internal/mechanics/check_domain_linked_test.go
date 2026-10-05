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
	linkedDomain = "centre.example"
	assetCode    = "USDC"
	linkedURL    = "https://centre.example/.well-known/USDC.toml"
)

func linkedDomainSubject(t *testing.T, toml string) *mechanics.Subject {
	t.Helper()
	fetched := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	s := &mechanics.Subject{
		Asset:           mechanics.Asset{Code: assetCode, Issuer: testIssuer},
		Issuer:          &horizon.Account{AccountID: testIssuer, HomeDomain: linkedDomain},
		TomlURL:         sep1.URLFor(linkedDomain),
		TomlAttemptedAt: fetched,
		ScannedAt:       fetched,
	}
	if toml != "" {
		doc, err := sep1.Parse([]byte(toml))
		if err != nil {
			t.Fatalf("parse toml: %v", err)
		}
		doc.URL = s.TomlURL
		doc.FetchedAt = fetched
		s.Toml = doc
	}
	return s
}

func runLinkedDomain(t *testing.T, s *mechanics.Subject) mechanics.Finding {
	t.Helper()
	f, err := mechanics.DomainCheck{}.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("DomainCheck.Run: %v", err)
	}
	return f
}

const linkedToml = `
[[CURRENCIES]]
toml = "https://centre.example/.well-known/USDC.toml"
`

// TestDomainLinkedClaimVerified: a match in a followed linked document is a
// claim, and produces verified accountability.
func TestDomainLinkedClaimVerified(t *testing.T) {
	s := linkedDomainSubject(t, linkedToml)
	fetched := time.Date(2026, 9, 27, 0, 0, 5, 0, time.UTC)
	s.TomlLinked = &sep1.LinkedResolution{
		Attempted:  1,
		Claimed:    true,
		ClaimedURL: linkedURL,
		Docs: []sep1.LinkedDoc{{
			URL: linkedURL,
			Doc: &sep1.Doc{
				Currencies: []sep1.Currency{{Code: assetCode, Issuer: testIssuer}},
				FetchedAt:  fetched,
			},
		}},
	}

	f := runLinkedDomain(t, s)
	if f.Accountability == nil || *f.Accountability != mechanics.AccountabilityVerified {
		t.Fatalf("accountability = %v, want verified", f.Accountability)
	}
	var found bool
	for _, e := range f.Evidence {
		if e.Source == "stellar.toml" && e.URL == linkedURL && strings.Contains(e.Claim, "linked document claims") {
			found = true
			if !e.RetrievedAt.Time().Equal(fetched) {
				t.Errorf("linked claim evidence carries %s, want the linked document's fetch time %s", e.RetrievedAt, fetched)
			}
		}
	}
	if !found {
		t.Fatalf("no evidence pointing at the claiming linked document: %+v", f.Evidence)
	}
}

// TestDomainLinkedNoneClaimRefused: every link was read and none names the
// asset, which is a genuine refusal, not an unresolved hedge.
func TestDomainLinkedNoneClaimRefused(t *testing.T) {
	s := linkedDomainSubject(t, linkedToml)
	s.TomlLinked = &sep1.LinkedResolution{
		Attempted: 1,
		Docs:      []sep1.LinkedDoc{{URL: linkedURL, Doc: &sep1.Doc{}}},
	}

	f := runLinkedDomain(t, s)
	if f.Accountability == nil || *f.Accountability != mechanics.AccountabilityUnverified {
		t.Fatalf("accountability = %v, want unverified", f.Accountability)
	}
	if f.Mechanics&mechanics.MechDomainUnverified == 0 {
		t.Error("domain_unverified bit not set on a genuine refusal")
	}
	if strings.Contains(f.Reasoning, "could not be read") || strings.Contains(f.Reasoning, "bound") {
		t.Errorf("a fully-read refusal must not hedge: %q", f.Reasoning)
	}
	if !strings.Contains(f.Reasoning, "has not claimed this asset") {
		t.Errorf("refusal reasoning does not state the refusal: %q", f.Reasoning)
	}
}

// TestDomainLinkedUnfetchableUnresolved: a link that could not be read leaves
// the answer unresolved. The evidence is marked Attempted, never Refused.
func TestDomainLinkedUnfetchableUnresolved(t *testing.T) {
	s := linkedDomainSubject(t, linkedToml)
	s.TomlLinked = &sep1.LinkedResolution{
		Attempted: 1,
		Docs:      []sep1.LinkedDoc{{URL: linkedURL, Err: "connection refused"}},
	}

	f := runLinkedDomain(t, s)
	if f.Accountability == nil || *f.Accountability != mechanics.AccountabilityUnverified {
		t.Fatalf("accountability = %v, want unverified", f.Accountability)
	}
	if !strings.Contains(f.Reasoning, "could not be read") {
		t.Errorf("unfetchable link reasoning kept no hedge: %q", f.Reasoning)
	}
	var found bool
	for _, e := range f.Evidence {
		if strings.Contains(e.Claim, "could not be read") {
			found = true
			if e.Refused {
				t.Error("an ordinary fetch failure was marked as a host-policy refusal")
			}
		}
	}
	if !found {
		t.Fatalf("no evidence for the unfetchable link: %+v", f.Evidence)
	}
}

// TestDomainLinkedBoundUnresolved: reaching the follow bound leaves the answer
// unresolved and says the bound was hit.
func TestDomainLinkedBoundUnresolved(t *testing.T) {
	s := linkedDomainSubject(t, linkedToml)
	docs := make([]sep1.LinkedDoc, 0, sep1.MaxLinkedDocuments)
	for i := 0; i < sep1.MaxLinkedDocuments; i++ {
		docs = append(docs, sep1.LinkedDoc{URL: linkedURL, Doc: &sep1.Doc{}})
	}
	s.TomlLinked = &sep1.LinkedResolution{Attempted: sep1.MaxLinkedDocuments, Deferred: 3, Docs: docs}

	f := runLinkedDomain(t, s)
	if f.Accountability == nil || *f.Accountability != mechanics.AccountabilityUnverified {
		t.Fatalf("accountability = %v, want unverified", f.Accountability)
	}
	if !strings.Contains(f.Reasoning, "bound") {
		t.Errorf("bound-hit reasoning does not mention the bound: %q", f.Reasoning)
	}
	found := false
	for _, e := range f.Evidence {
		if strings.Contains(e.Claim, "left unread") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no evidence stating the bound was hit: %+v", f.Evidence)
	}
}

// TestDomainRefusedHostRecorded: a non-public home_domain is a refusal, not an
// outage. It is reported as attributed evidence marked Refused.
func TestDomainRefusedHostRecorded(t *testing.T) {
	s := linkedDomainSubject(t, "")
	s.TomlRefused = true
	s.TomlErr = "sep1: refusing non-public host \"10.0.0.1\": private address (RFC 1918 / RFC 4193)"

	f := runLinkedDomain(t, s)
	if f.Accountability == nil || *f.Accountability != mechanics.AccountabilityUnverified {
		t.Fatalf("accountability = %v, want unverified", f.Accountability)
	}
	var found bool
	for _, e := range f.Evidence {
		if e.Source != "stellar.toml" {
			continue
		}
		found = true
		if !e.Refused {
			t.Error("host-policy refusal evidence is not marked Refused")
		}
		if !e.Attempted {
			t.Error("host-policy refusal evidence is not marked Attempted")
		}
		if !strings.HasPrefix(e.Claim, "refused: ") {
			t.Errorf("refusal evidence claim = %q, want a refusal prefix", e.Claim)
		}
	}
	if !found {
		t.Fatalf("no evidence recorded for the refused host: %+v", f.Evidence)
	}
}

// TestDomainInlineClaimStillVerified is the regression guard: resolving links
// must not disturb the round-trip check for an inline claim.
func TestDomainInlineClaimStillVerified(t *testing.T) {
	s := linkedDomainSubject(t, "[[CURRENCIES]]\ncode=\"USDC\"\nissuer=\""+testIssuer+"\"\n")
	f := runLinkedDomain(t, s)
	if f.Accountability == nil || *f.Accountability != mechanics.AccountabilityVerified {
		t.Fatalf("inline claim accountability = %v, want verified", f.Accountability)
	}
}
