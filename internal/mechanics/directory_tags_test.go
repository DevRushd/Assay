package mechanics_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// These tests pin the directory tag rule stated in docs/checks.md: escalation
// changes on an explicit, documented adverse set, a descriptive tag never
// escalates, and a tag outside the vocabulary is recorded as evidence rather
// than silently dropped. The vocabulary itself, with its source and capture
// date, lives in mechanics.AdverseDirectoryTags / descriptiveDirectoryTags.

// tagSubject builds a subject whose only reputation input is the directory,
// carrying exactly the given tags. The blocklist answers "not blocked" so a
// tag is the only thing that could escalate.
func tagSubject(tags ...string) *mechanics.Subject {
	fetched := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	const (
		code   = "TAGTEST"
		issuer = "GBXRPL45NPHCVMFFAYZVUVFFVKSIZ362ZXFP7I2ETNQ3QKZMFLPRDTD5"
		domain = "tag-issuer.test"
	)
	return &mechanics.Subject{
		Asset:                mechanics.Asset{Code: code, Issuer: issuer},
		Stat:                 &horizon.AssetStat{AssetCode: code, AssetIssuer: issuer},
		StatFetchedAt:        fetched,
		Issuer:               &horizon.Account{AccountID: issuer, HomeDomain: domain},
		IssuerFetchedAt:      fetched,
		TomlURL:              "https://" + domain + "/.well-known/stellar.toml",
		TomlAttemptedAt:      fetched,
		DirectoryURL:         "https://api.stellar.expert/explorer/directory/" + issuer,
		Directory:            &stellarexpert.DirectoryEntry{Address: issuer, Name: "Tag test", Domain: domain, Tags: tags},
		DirectoryFetchedAt:   fetched,
		DirectoryAttemptedAt: fetched,
		BlockedURL:           "https://api.stellar.expert/explorer/directory/blocked-domains/" + domain,
		Blocked:              &stellarexpert.BlockedDomain{Domain: domain, Blocked: false},
		BlockedFetchedAt:     fetched,
		BlockedAttemptedAt:   fetched,
		ScannedAt:            fetched,
	}
}

// TestAdverseDirectoryTagSetIsPinned makes the adverse set itself a reviewed
// decision: adding or removing a tag must be a deliberate edit here as well,
// with a source and date recorded alongside it.
func TestAdverseDirectoryTagSetIsPinned(t *testing.T) {
	want := []string{"malicious", "unsafe"}
	if !slices.Equal(mechanics.AdverseDirectoryTags, want) {
		t.Fatalf("AdverseDirectoryTags = %v, want %v; a change here moves what escalates "+
			"and must be deliberate (see docs/checks.md)", mechanics.AdverseDirectoryTags, want)
	}
}

// TestEachAdverseDirectoryTagEscalates is the valid state: every tag in the
// documented adverse set, on its own, escalates to critical.
func TestEachAdverseDirectoryTagEscalates(t *testing.T) {
	if len(mechanics.AdverseDirectoryTags) == 0 {
		t.Fatal("the adverse tag set is empty; nothing can escalate on a directory listing")
	}
	for _, tag := range mechanics.AdverseDirectoryTags {
		t.Run(tag, func(t *testing.T) {
			rep := run(t, tagSubject(tag))
			if rep.Severity != mechanics.Critical || !rep.Escalated {
				t.Fatalf("adverse tag %q: severity=%v escalated=%v, want critical/escalated",
					tag, rep.Severity, rep.Escalated)
			}
			if rep.Mechanics&mechanics.MechBlocklisted == 0 {
				t.Errorf("adverse tag %q did not set the blocklisted mechanic", tag)
			}
			if rep.Undetermined {
				t.Error("a positive listing decides the question; the report must not be undetermined")
			}
		})
	}
}

// TestDescriptiveDirectoryTagDoesNotEscalate is the invalid state: tags that
// describe what an account is rather than asserting abuse must stay
// non-escalating and must not be reported as unrecognised.
func TestDescriptiveDirectoryTagDoesNotEscalate(t *testing.T) {
	for _, tag := range []string{
		"issuer", "anchor", "exchange", "wallet", "custodian",
		"personal", "sdf", "memo-required", "airdrop", "obsolete-inflation-pool",
	} {
		t.Run(tag, func(t *testing.T) {
			rep := run(t, tagSubject(tag))
			if rep.Severity == mechanics.Critical || rep.Escalated {
				t.Fatalf("descriptive tag %q escalated: severity=%v escalated=%v",
					tag, rep.Severity, rep.Escalated)
			}
			for _, e := range rep.Evidence {
				if strings.Contains(strings.ToLower(e.Claim), "unrecognised") {
					t.Errorf("known-descriptive tag %q was reported as unrecognised: %q", tag, e.Claim)
				}
			}
		})
	}
}

// TestUnknownDirectoryTagIsRecordedAndDoesNotEscalate is the unknown state: a
// tag outside the documented vocabulary is surfaced as attributed evidence and
// does not escalate, so a newly introduced adverse tag is visible rather than
// silently dropped.
func TestUnknownDirectoryTagIsRecordedAndDoesNotEscalate(t *testing.T) {
	const tag = "some-tag-not-in-the-vocabulary"

	rep := run(t, tagSubject(tag))

	if rep.Severity == mechanics.Critical || rep.Escalated {
		t.Fatalf("unrecognised tag %q escalated: severity=%v escalated=%v",
			tag, rep.Severity, rep.Escalated)
	}
	if rep.Undetermined {
		t.Fatal("an unrecognised tag is not an outage and must not mark the report undetermined")
	}

	var recorded bool
	for _, e := range rep.Evidence {
		if e.Source != "stellar.expert/directory" || !strings.Contains(e.Claim, tag) {
			continue
		}
		if !strings.Contains(strings.ToLower(e.Claim), "unrecognised") {
			continue
		}
		recorded = true
		if e.URL == "" {
			t.Error("unrecognised-tag evidence carries no URL, so it cannot be re-checked")
		}
	}
	if !recorded {
		t.Fatalf("unrecognised tag %q was not recorded as evidence: %+v", tag, rep.Evidence)
	}
}
