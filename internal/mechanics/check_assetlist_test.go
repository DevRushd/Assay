package mechanics_test

import (
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/assetlist"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// These are the acceptance tests for consuming SEP-0042 asset lists: that they
// are attributed one at a time, that presence on one is never a safety signal,
// that absence from one is never an observation, that disagreement is reported
// rather than resolved, and that a list which could not be read is a failure
// and not silence.

var salTime = time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)

// horizonFlagsClawback is a revocable-plus-clawback issuer: capability High.
func horizonFlagsClawback() horizon.Flags {
	return horizon.Flags{AuthRevocable: true, AuthClawbackEnabled: true}
}

// reputationFinding returns the reputation finding, so a test never asserts
// against whichever finding happens to sort first by severity.
func reputationFinding(t *testing.T, rep *mechanics.Report) mechanics.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Check == "reputation" {
			return f
		}
	}
	t.Fatal("the report has no reputation finding")
	return mechanics.Finding{}
}

// salListed is a signal for a list that contains the asset under scan.
func salListed(name, url string) mechanics.AssetListSignal {
	return mechanics.AssetListSignal{
		Name:        name,
		Provider:    name + " Collective",
		URL:         url,
		Version:     "1.0",
		Network:     "public",
		Listed:      true,
		FetchedAt:   salTime,
		AttemptedAt: salTime,
		Entry: &assetlist.Asset{
			Code:   "DOGE",
			Issuer: testIssuer,
			Name:   "Dogecoin (scam copy)",
			Org:    "Nobody",
			Domain: "darkpool.digital",
		},
	}
}

// salAbsent is a signal for a list that was read and does not contain the asset.
func salAbsent(name, url string) mechanics.AssetListSignal {
	return mechanics.AssetListSignal{
		Name:        name,
		Provider:    name + " Collective",
		URL:         url,
		Version:     "2.0",
		Network:     "public",
		FetchedAt:   salTime,
		AttemptedAt: salTime,
	}
}

// salBroken is a signal for a list that could not be read at all.
func salBroken(name, url string) mechanics.AssetListSignal {
	return mechanics.AssetListSignal{
		URL:         url,
		AttemptedAt: salTime,
		Err:         "assetlist: get " + url + ": status 503",
	}
}

func listEvidence(rep *mechanics.Report) []mechanics.Evidence {
	var out []mechanics.Evidence
	for _, e := range rep.Evidence {
		if strings.HasPrefix(e.Source, "asset-list") {
			out = append(out, e)
		}
	}
	return out
}

// The acceptance criterion stated directly: inclusion in a curated list must
// not lower severity. This subject is a clawback-capable issuer, so its
// capability base is High; being listed by a provider cannot turn that into
// something safer, and presence alone must not escalate either — escalating on
// an inclusion would invert the severity model, where only a *malicious*
// listing is decisive.
func TestAssetListPresenceDoesNotChangeSeverity(t *testing.T) {
	base := run(t, subject(func(s *mechanics.Subject) {
		s.Stat.Flags = horizonFlagsClawback()
		s.Issuer.Flags = horizonFlagsClawback()
	}))
	listed := run(t, subject(func(s *mechanics.Subject) {
		s.Stat.Flags = horizonFlagsClawback()
		s.Issuer.Flags = horizonFlagsClawback()
		s.AssetLists = []mechanics.AssetListSignal{salListed("Alpha", "https://alpha.test/list.json")}
	}))

	if base.Base != mechanics.High || base.Severity != mechanics.High {
		t.Fatalf("precondition: clawback subject should be high, got base=%v severity=%v", base.Base, base.Severity)
	}
	if listed.Base != base.Base {
		t.Errorf("presence on a list moved the capability base from %v to %v", base.Base, listed.Base)
	}
	if listed.Severity != base.Severity {
		t.Errorf("presence on a list changed severity from %v to %v", base.Severity, listed.Severity)
	}
	if listed.Escalated {
		t.Error("presence on a curated list escalated the report; only a confirmed malicious listing may")
	}
	// The whole mechanic bitset must be what the checks observed with no list
	// involved: an inclusion adds no bit and, crucially, takes none away.
	if listed.Mechanics != base.Mechanics {
		t.Errorf("presence on a list changed the mechanics from %v to %v",
			base.Mechanics.Names(), listed.Mechanics.Names())
	}

	// The reputation finding is always marked Escalation — that flag says the
	// check is permitted to escalate, not that it did. What must not happen is
	// it claiming a level from an inclusion.
	for _, f := range listed.Findings {
		if f.Check != "reputation" {
			continue
		}
		if f.Severity != mechanics.Clear {
			t.Errorf("an inclusion produced severity %v in the reputation finding", f.Severity)
		}
		if f.Mechanics != 0 {
			t.Errorf("the reputation finding set mechanics %v from an inclusion", f.Mechanics.Names())
		}
		if f.Undetermined {
			t.Error("an inclusion marked the reputation finding undetermined")
		}
	}
}

// The mirror image: absence from a list is not an observation, so it cannot
// reassure either. Same severity, and the reasoning says so rather than staying
// silent and letting absence read as approval.
func TestAssetListAbsenceIsNotASafetySignal(t *testing.T) {
	bare := run(t, subject(func(s *mechanics.Subject) {
		s.Stat.Flags = horizonFlagsClawback()
		s.Issuer.Flags = horizonFlagsClawback()
	}))
	absent := run(t, subject(func(s *mechanics.Subject) {
		s.Stat.Flags = horizonFlagsClawback()
		s.Issuer.Flags = horizonFlagsClawback()
		s.AssetLists = []mechanics.AssetListSignal{salAbsent("Alpha", "https://alpha.test/list.json")}
	}))

	if absent.Base != bare.Base || absent.Severity != bare.Severity {
		t.Errorf("absence from a list moved severity: base %v->%v, severity %v->%v",
			bare.Base, absent.Base, bare.Severity, absent.Severity)
	}
	if absent.Escalated {
		t.Error("absence from a list escalated the report")
	}

	// The absence must be visible as an absence, and the reasoning must
	// disclaim it.
	ev := listEvidence(absent)
	if len(ev) != 1 {
		t.Fatalf("want one asset-list evidence entry, got %d", len(ev))
	}
	if !strings.Contains(ev[0].Claim, "not present in list") {
		t.Errorf("absence claim reads %q, which does not state the absence", ev[0].Claim)
	}
	if !strings.Contains(reputationFinding(t, absent).Reasoning, "absence is not an observation") {
		t.Errorf("reasoning does not disclaim absence: %q", reputationFinding(t, absent).Reasoning)
	}
}

// Two providers, two answers. Presence on A and absence from B are two
// statements by two sources, so they must appear as two attributed claims with
// their own names and URLs — never merged into one verdict, and never
// collapsed into "the curated sources say nothing".
func TestAssetListsAreAttributedSeparately(t *testing.T) {
	rep := run(t, subject(func(s *mechanics.Subject) {
		s.AssetLists = []mechanics.AssetListSignal{
			salListed("Alpha", "https://alpha.test/list.json"),
			salAbsent("Beta", "https://beta.test/list.json"),
		}
	}))

	ev := listEvidence(rep)
	if len(ev) != 2 {
		t.Fatalf("want one evidence entry per list, got %d: %+v", len(ev), ev)
	}

	bySource := map[string]mechanics.Evidence{}
	for _, e := range ev {
		bySource[e.Source] = e
	}
	alpha, ok := bySource["asset-list/Alpha"]
	if !ok {
		t.Fatalf("no evidence attributed to Alpha; sources were %v", listSources(ev))
	}
	beta, ok := bySource["asset-list/Beta"]
	if !ok {
		t.Fatalf("no evidence attributed to Beta; sources were %v", listSources(ev))
	}

	if alpha.URL != "https://alpha.test/list.json" || beta.URL != "https://beta.test/list.json" {
		t.Errorf("evidence URLs lost their per-list attribution: %q, %q", alpha.URL, beta.URL)
	}
	if !strings.Contains(alpha.Claim, "listed as") || !strings.Contains(alpha.Claim, "in list \"Alpha\"") {
		t.Errorf("the listing claim does not state what Alpha said: %q", alpha.Claim)
	}
	if !strings.Contains(beta.Claim, "not present in list") || !strings.Contains(beta.Claim, "in list \"Beta\"") {
		t.Errorf("the absence claim does not state what Beta said: %q", beta.Claim)
	}
	// Each claim carries its own source's fetch time, never a scan-wide one.
	if !alpha.RetrievedAt.Equal(salTime) || !beta.RetrievedAt.Equal(salTime) {
		t.Errorf("claims carry %s and %s, want the list fetch time %s",
			alpha.RetrievedAt, beta.RetrievedAt, salTime)
	}
}

// Published lists are imperfect: LOBSTR's real curated list contains entries
// with no `name`, and the format leaves `org` and `domain` optional. A claim
// must state what the list published without rendering a gap as a value — an
// empty quoted name reads like a name that was published as empty — while still
// using the wording the history view recognises as an inclusion.
func TestAssetListClaimsStateOnlyWhatWasPublished(t *testing.T) {
	unnamed := func(entry *assetlist.Asset) mechanics.AssetListSignal {
		return mechanics.AssetListSignal{
			Name: "Sparse", URL: "https://sparse.test/list.json", Listed: true,
			FetchedAt: salTime, AttemptedAt: salTime, Entry: entry,
		}
	}

	cases := []struct {
		name  string
		entry *assetlist.Asset
		claim string
	}{
		{
			name:  "no name published",
			entry: &assetlist.Asset{Code: "DOGE", Domain: "fchain.io"},
			claim: `listed as an entry the list leaves unnamed (domain "fchain.io") in list "Sparse"`,
		},
		{
			name:  "name only",
			entry: &assetlist.Asset{Code: "DOGE", Name: "XRP"},
			claim: `listed as "XRP" in list "Sparse"`,
		},
		{
			name:  "entry with no metadata at all",
			entry: &assetlist.Asset{Code: "DOGE"},
			claim: `listed as an entry the list leaves unnamed in list "Sparse"`,
		},
		{
			name:  "everything published",
			entry: &assetlist.Asset{Code: "DOGE", Name: "XRP", Org: "Ripple", Domain: "ripple.com"},
			claim: `listed as "XRP" (org "Ripple", domain "ripple.com") in list "Sparse"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, subject(func(s *mechanics.Subject) {
				s.AssetLists = []mechanics.AssetListSignal{unnamed(tc.entry)}
			}))
			ev := listEvidence(rep)
			if len(ev) != 1 {
				t.Fatalf("want one claim, got %+v", ev)
			}
			if ev[0].Claim != tc.claim {
				t.Errorf("claim =\n%q\nwant\n%q", ev[0].Claim, tc.claim)
			}
			// The inclusion wording survives every shape of entry, because the
			// history view maps claims to terms by this wording and must not
			// read a list that answered as one that did not.
			if !strings.HasPrefix(ev[0].Claim, "listed as") {
				t.Errorf("claim %q is not worded as an inclusion", ev[0].Claim)
			}
			// And no optional field is ever rendered as an empty quote, which is
			// the one way this claim could be misread as a statement.
			if strings.Contains(ev[0].Claim, `""`) {
				t.Errorf("claim %q renders an unpublished field as an empty value", ev[0].Claim)
			}
		})
	}
}

// Sources disagreeing is reported, not silently resolved. Two lists that
// disagree about the asset must both keep their claims and the reasoning must
// say so out loud — resolving it by picking a winner would require Assay to
// weigh two providers it does not judge.
func TestAssetListDisagreementIsReported(t *testing.T) {
	rep := run(t, subject(func(s *mechanics.Subject) {
		s.AssetLists = []mechanics.AssetListSignal{
			salListed("Alpha", "https://alpha.test/list.json"),
			salAbsent("Beta", "https://beta.test/list.json"),
		}
	}))

	f := reputationFinding(t, rep)
	if !strings.Contains(f.Reasoning, "Sources disagree") {
		t.Errorf("disagreement between lists was not reported: %q", f.Reasoning)
	}
	if !strings.Contains(f.Reasoning, "reported, not resolved") {
		t.Errorf("the reasoning does not state it was left unresolved: %q", f.Reasoning)
	}
	if f.Undetermined {
		t.Error("two lists disagreeing is an observation, not a missing source")
	}
	if rep.Escalated || rep.Severity != rep.Base {
		t.Errorf("disagreement moved severity: base=%v severity=%v escalated=%v",
			rep.Base, rep.Severity, rep.Escalated)
	}
	if ev := listEvidence(rep); len(ev) != 2 {
		t.Errorf("both claims must survive the disagreement, got %d", len(ev))
	}
}

// A list that could not be read is a failure, not an absence, and it does not
// make the report undetermined: an asset list can neither escalate nor lower
// severity, so it cannot be a source the verdict depends on. The failure is
// recorded anyway, as Attempted evidence carrying the attempt time.
func TestUnreadableAssetListIsFailureNotAbsence(t *testing.T) {
	rep := run(t, subject(func(s *mechanics.Subject) {
		s.AssetLists = []mechanics.AssetListSignal{salBroken("Alpha", "https://alpha.test/list.json")}
	}))

	ev := listEvidence(rep)
	if len(ev) != 1 {
		t.Fatalf("want exactly one evidence entry, got %d", len(ev))
	}
	if !strings.Contains(ev[0].Claim, "not retrievable") {
		t.Errorf("claim reads %q, which does not read as a failure", ev[0].Claim)
	}
	if strings.Contains(ev[0].Claim, "not present") {
		t.Errorf("an unreadable list was rendered as an absence: %q", ev[0].Claim)
	}
	if !ev[0].Attempted {
		t.Error("failure evidence is not marked Attempted: an attempt is not an answer")
	}
	if !ev[0].RetrievedAt.Equal(salTime) {
		t.Errorf("failure evidence carries %s, want the attempt time %s", ev[0].RetrievedAt, salTime)
	}

	if rep.Undetermined {
		t.Error("an unreadable asset list marked the whole report undetermined; it can " +
			"neither escalate nor lower the severity, so it is not a source the verdict depends on")
	}
	if rep.Severity != rep.Base {
		t.Errorf("an unreadable list moved severity: base=%v severity=%v", rep.Base, rep.Severity)
	}
	reasoning := reputationFinding(t, rep).Reasoning
	if !strings.Contains(reasoning, "could not be read") {
		t.Errorf("the reasoning does not surface the unreadable list: %q", reasoning)
	}
	if !strings.Contains(reasoning, "does not mark this report undetermined") {
		t.Errorf("the reasoning does not explain the non-degradation: %q", reasoning)
	}
}

// The most safety-relevant disagreement: a provider's curated list contains an
// asset whose issuer StellarExpert flags as malicious. Both facts are reported.
// The escalation stands — evidence of abuse does not become less true because
// another provider's list disagrees — and the inclusion changes nothing.
func TestAssetListDisagreeingWithAnEscalationIsReported(t *testing.T) {
	rep := run(t, subject(func(s *mechanics.Subject) {
		s.Issuer.HomeDomain = "example.test"
		s.DirectoryURL = "https://api.stellar.expert/explorer/directory/" + testIssuer
		s.Directory = &stellarexpert.DirectoryEntry{
			Address: testIssuer,
			Name:    "Scam Asset",
			Domain:  "example.test",
			Tags:    []string{"malicious"},
		}
		s.BlockedURL = "https://api.stellar.expert/explorer/directory/blocked-domains/example.test"
		s.AssetLists = []mechanics.AssetListSignal{salListed("Alpha", "https://alpha.test/list.json")}
	}))

	if !rep.Escalated || rep.Severity != mechanics.Critical {
		t.Fatalf("the escalation must stand: escalated=%v severity=%v", rep.Escalated, rep.Severity)
	}
	f := reputationFinding(t, rep)
	if !strings.Contains(f.Reasoning, "Sources disagree") {
		t.Errorf("the conflict was not reported: %q", f.Reasoning)
	}
	if !strings.Contains(f.Reasoning, "while another source flags it") {
		t.Errorf("the reasoning does not name the conflict: %q", f.Reasoning)
	}
	if f.Mechanics&mechanics.CapabilityMask != 0 {
		t.Errorf("asset lists set capability bits %v", (f.Mechanics & mechanics.CapabilityMask).Names())
	}
}

// Regression guard for reports produced without any list configured: nothing
// about them may change. Adding evidence to every report would silently change
// every evidence_hash, including for assets already attested on chain.
func TestNoAssetListsConfiguredChangesNothing(t *testing.T) {
	rep := run(t, subject(nil))

	if ev := listEvidence(rep); len(ev) != 0 {
		t.Errorf("asset-list evidence appeared with no list configured: %+v", ev)
	}
	if strings.Contains(reputationFinding(t, rep).Reasoning, "SEP-0042") {
		t.Errorf("the asset-list note leaked into a report with no lists: %q",
			reputationFinding(t, rep).Reasoning)
	}
}

func listSources(ev []mechanics.Evidence) []string {
	out := make([]string, 0, len(ev))
	for _, e := range ev {
		out = append(out, e.Source)
	}
	return out
}
