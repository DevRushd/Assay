package mechanics

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// ReputationCheck folds in StellarExpert's curated reputation data and any
// configured SEP-0042 asset list.
//
// Assay does not maintain a scam list, a rating, or a domain blocklist. Those
// exist, they are actively curated, and this check consumes them. Everything it
// produces is attributed Evidence naming the source and the URL the claim came
// from — one entry per source, so two sources saying different things stays two
// statements rather than one verdict.
//
// It is the only check permitted to escalate, and it can only ever raise the
// level. A confirmed malicious listing is decisive evidence of abuse. Absence
// from the list is not evidence of anything: most legitimate assets are absent,
// and so is every scam that has not been reported yet. The same applies to an
// asset list — presence on one is not endorsement, which SEP-0042 states
// outright, so it neither escalates nor reassures.
type ReputationCheck struct{}

// ID implements Check.
func (ReputationCheck) ID() string { return "reputation" }

// Describe implements Check.
func (ReputationCheck) Describe() string {
	return "Consumes StellarExpert's curated address directory and " +
		"malicious-domain blocklist, plus any configured SEP-0042 asset list, " +
		"as attributed evidence. Escalates to critical on a confirmed listing; " +
		"never lowers severity, and says nothing about an asset that a curated " +
		"list does not contain."
}

// Run implements Check.
func (c ReputationCheck) Run(_ context.Context, s *Subject) (Finding, error) {
	f := Finding{
		Check:      c.ID(),
		Title:      "Curated reputation signals",
		Severity:   Clear,
		Escalation: true,
		Evidence:   []Evidence{},
	}

	var flagged []string
	// unreachable names sources that were asked and did not answer. It is kept
	// separate from "answered, not listed" because collapsing the two is
	// exactly how a scanner reports an outage as a clean bill of health.
	var unreachable []string
	// unrecognised names directory tags outside Assay's documented vocabulary.
	// They never escalate, but they are recorded so the vocabulary can be
	// extended deliberately rather than an adverse tag being silently missed.
	var unrecognised []string

	if s.DirectoryErr != "" {
		unreachable = append(unreachable, "the curated directory")
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.expert/directory",
			URL:    s.DirectoryURL,
			Claim:  "not retrievable: " + s.DirectoryErr,
			// The source never answered, so this is the attempt time — marked
			// as such, because an attempt is not an answer.
			RetrievedAt: NewCanonicalTime(s.DirectoryAttemptedAt),
			Attempted:   true,
		})
	}

	// The blocklist is keyed on a domain. scan.Scanner records the skip in
	// BlockedSkipped; the HomeDomain check is a fallback so a hand-built
	// subject that omits the field cannot silently reintroduce the gap.
	blockedSkipped := s.BlockedSkipped
	if blockedSkipped == "" && s.HomeDomain() == "" {
		blockedSkipped = "the issuer advertises no home_domain to key the lookup on"
	}
	if blockedSkipped != "" {
		unasked = append(unasked, "the malicious-domain blocklist ("+blockedSkipped+")")
	} else if s.BlockedErr != "" {
		unreachable = append(unreachable, "the malicious-domain blocklist")
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "stellar.expert/blocked-domains",
			URL:         s.BlockedURL,
			Claim:       "not retrievable: " + s.BlockedErr,
			RetrievedAt: NewCanonicalTime(s.BlockedAttemptedAt),
			Attempted:   true,
		})
	}

	if s.Directory != nil {
		tags := strings.Join(s.Directory.Tags, ", ")
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.expert/directory",
			URL:    s.DirectoryURL,
			Claim: fmt.Sprintf("listed as %q (domain %q, tags: %s)",
				s.Directory.Name, s.Directory.Domain, tags),
			RetrievedAt: NewCanonicalTime(s.DirectoryFetchedAt),
		})
		// Escalation is driven by the named, documented adverse set rather than
		// an inline literal, so the vocabulary is a reviewed artifact.
		for _, tag := range AdverseDirectoryTags {
			if s.Directory.HasTag(tag) {
				flagged = append(flagged, fmt.Sprintf("the curated directory tags the issuer %q", tag))
				break
			}
		}
		// A tag outside the documented vocabulary is not silently dropped. An
		// unrecognised tag could be adverse, and ignoring it would be a false
		// negative that never announces itself, on the only axis that can raise
		// a severity. It is recorded as attributed evidence and left
		// non-escalating, so the vocabulary is extended deliberately rather
		// than guessed at scan time.
		for _, tag := range s.Directory.Tags {
			if classifyDirectoryTag(tag) != directoryTagUnknown {
				continue
			}
			unrecognised = append(unrecognised, tag)
			f.Evidence = append(f.Evidence, Evidence{
				Source: "stellar.expert/directory",
				URL:    s.DirectoryURL,
				Claim: fmt.Sprintf(
					"unrecognised directory tag %q: not in Assay's documented vocabulary, "+
						"so it did not affect severity; review it so the vocabulary can be updated deliberately",
					tag),
				RetrievedAt: s.DirectoryFetchedAt,
			})
		}
	}

	blocklistHit := s.Blocked != nil && s.Blocked.Blocked
	if s.Blocked != nil {
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "stellar.expert/blocked-domains",
			URL:         s.BlockedURL,
			Claim:       fmt.Sprintf("domain %q blocked=%t", s.Blocked.Domain, s.Blocked.Blocked),
			RetrievedAt: NewCanonicalTime(s.BlockedFetchedAt),
		})
		if blocklistHit {
			flagged = append(flagged, fmt.Sprintf(
				"the malicious-domain blocklist contains %q", s.Blocked.Domain))
		}
	}

	// SEP-0042 asset lists, each attributed separately by its own name and URL.
	// They never touch `flagged` or severity: inclusion is not endorsement —
	// the spec says so itself — and absence is not an observation, so a list
	// can neither escalate nor reassure. What they add is another provider's
	// view, with disagreement visible rather than averaged away.
	var listedIn, absentFrom, unreadable []string
	for _, l := range s.AssetLists {
		switch {
		case l.Err != "":
			// The list could not be read: a failure, not an absence. Recorded
			// as Attempted evidence so a consumer can tell "we could not check
			// this list" from "this list does not list it" without parsing
			// English.
			unreadable = append(unreadable, assetListLabel(l))
			f.Evidence = append(f.Evidence, Evidence{
				Source:      assetListSource(l),
				URL:         l.URL,
				Claim:       "not retrievable: " + l.Err,
				RetrievedAt: l.AttemptedAt,
				Attempted:   true,
			})
		case l.Listed:
			listedIn = append(listedIn, assetListLabel(l))
			f.Evidence = append(f.Evidence, Evidence{
				Source:      assetListSource(l),
				URL:         l.URL,
				Claim:       assetListClaim(l),
				RetrievedAt: l.FetchedAt,
			})
		default:
			// The list was read and does not contain the asset. Stated as its
			// own claim so "absent from B" stays visible next to "present in
			// A" instead of both sources collapsing into one silence.
			absentFrom = append(absentFrom, assetListLabel(l))
			f.Evidence = append(f.Evidence, Evidence{
				Source:      assetListSource(l),
				URL:         l.URL,
				Claim:       fmt.Sprintf("not present in list %q", assetListName(l)),
				RetrievedAt: l.FetchedAt,
			})
		}
	}

	// Sources disagreeing is reported, never resolved. Two disagreements can
	// occur and neither is ours to settle: the asset lists can disagree with
	// each other, and a list can contain an asset the StellarExpert sources
	// flag. Both are facts about what different providers said, so both are
	// stated. Neither moves severity — an escalation already stands on its own
	// evidence, and an inclusion was never a credential.
	var disagreements []string
	if len(listedIn) > 0 && len(absentFrom) > 0 {
		disagreements = append(disagreements, fmt.Sprintf(
			"the asset lists disagree with each other: present in %s, absent from %s",
			joinPowers(listedIn), joinPowers(absentFrom)))
	}
	if len(listedIn) > 0 && len(flagged) > 0 {
		disagreements = append(disagreements, fmt.Sprintf(
			"a curated list contains this asset while another source flags it: present in %s, and %s",
			joinPowers(listedIn), joinPowers(flagged)))
	}
	listNote := assetListsNote(s.AssetLists, listedIn, absentFrom, unreadable, disagreements)

	// A positive listing decides the question even if the other source is down.
	// Evidence of abuse does not become less true because a second endpoint
	// timed out, and Critical is the ceiling, so nothing that is still missing
	// could raise the level further.
	if len(flagged) > 0 {
		f.Severity = Critical
		f.Mechanics = MechBlocklisted
		f.Reasoning = "Escalated to critical because " + joinPowers(flagged) +
			". This is StellarExpert's determination, reported here as their claim " +
			"and not re-derived by Assay. It raises the level regardless of what the " +
			"issuer's flags allow." + listNote
		return f, nil
	}

	// Nothing was flagged — but that only means something if every source was
	// actually read. Reporting a missing source as a clean result is the one
	// failure this check must never have, because reputation is the only axis
	// that can escalate: an asset that is critical solely by escalation reads
	// as its bare capability severity when a source is unavailable.
	//
	// A source that was never asked leaves the same gap as one that failed to
	// answer, so both mark the finding undetermined; the wording distinguishes
	// a missing answer from a missing question.
	if len(unreachable) > 0 || len(unasked) > 0 {
		f.Undetermined = true
		f.Reasoning = "Reputation could not be determined: " + joinPowers(unreachable) +
			" did not answer, and the failure is recorded above verbatim. This is " +
			"not a clean result. Absence of a malicious listing is only meaningful " +
			"when the list was actually read, and an asset whose only adverse signal " +
			"is a curated listing would look clear here. Treat the severity below as " +
			"a floor rather than an answer." + listNote
		return f, nil
	}

	if len(f.Evidence) == 0 {
		f.Reasoning = "Curated sources were reachable and returned nothing for this " +
			"issuer. That is the normal case and is not a positive signal: absence " +
			"from a scam list is not evidence of safety." + listNote
		return f, nil
	}

	f.Reasoning = "Curated sources returned data for this issuer and none of it " +
		"flags the issuer as malicious. Recorded as attributed evidence only: it " +
		"does not lower the capability severity, because a named issuer holds the " +
		"same power over your balance as an anonymous one." + listNote
	return f, nil
}

// assetListName is the identity of a list in a claim: the name it published,
// falling back to its URL, because a list that could never be read never
// described itself.
func assetListName(l AssetListSignal) string {
	if l.Name != "" {
		return l.Name
	}
	return l.URL
}

// assetListSource names a list as an evidence source. Evidence.Source is the
// structural hook attribution hangs off, so each list gets its own and two
// lists never share one.
func assetListSource(l AssetListSignal) string {
	if l.Name == "" {
		return "asset-list"
	}
	return "asset-list/" + l.Name
}

// assetListLabel names a list in prose, with its publisher when it gave one.
func assetListLabel(l AssetListSignal) string {
	if l.Name != "" && l.Provider != "" {
		return fmt.Sprintf("%s (%s)", l.Name, l.Provider)
	}
	return assetListName(l)
}

// assetListClaim renders what one list said about the asset, in the same shape
// the directory entry's claim uses so a reader meets one convention.
func assetListClaim(l AssetListSignal) string {
	if l.Entry == nil {
		return fmt.Sprintf("present in list %q", assetListName(l))
	}
	// "listed as" is kept as the prefix even when the entry carries nothing:
	// it is the term the history view recognises as an inclusion, and dropping
	// it would render a source that answered as one that did not.
	described := fmt.Sprintf("as %q", l.Entry.Name)
	if l.Entry.Name == "" {
		// Published lists really do contain unnamed entries. Quoting the empty
		// string would read like a name published as empty, so the gap is
		// stated instead of looking like a value.
		described = "as an entry the list leaves unnamed"
	}
	// Only the fields this list actually published are named. The format makes
	// them optional and real lists omit them, so a claim that always printed
	// org and domain would print empty quotes for information that was never
	// stated — which a reader could only misread as a statement of emptiness.
	var published []string
	if l.Entry.Org != "" {
		published = append(published, fmt.Sprintf("org %q", l.Entry.Org))
	}
	if l.Entry.Domain != "" {
		published = append(published, fmt.Sprintf("domain %q", l.Entry.Domain))
	}
	if len(published) == 0 {
		return fmt.Sprintf("listed %s in list %q", described, assetListName(l))
	}
	return fmt.Sprintf("listed %s (%s) in list %q",
		described, strings.Join(published, ", "), assetListName(l))
}

// assetListsNote renders what the configured SEP-0042 lists said, and any
// disagreement between sources, as a suffix to the finding's reasoning.
//
// It is appended to whichever reasoning is chosen so a reader of any one of
// them still learns what the lists did and did not say — including that
// silence from them carries no weight in either direction, and that a list
// which could not be read is not a list that found nothing.
func assetListsNote(signals []AssetListSignal, listedIn, absentFrom, unreadable, disagreements []string) string {
	if len(signals) == 0 {
		return ""
	}
	var parts []string
	if len(listedIn) > 0 {
		parts = append(parts, "present in "+joinPowers(listedIn))
	}
	if len(absentFrom) > 0 {
		parts = append(parts, "absent from "+joinPowers(absentFrom))
	}
	if len(unreadable) > 0 {
		parts = append(parts, "could not be read: "+joinPowers(unreadable))
	}
	if len(parts) == 0 {
		parts = append(parts, "consulted with no recorded answer")
	}

	var b strings.Builder
	b.WriteString(" SEP-0042 asset lists: ")
	b.WriteString(strings.Join(parts, "; "))
	b.WriteString(".")
	for _, d := range disagreements {
		b.WriteString(" Sources disagree — reported, not resolved: ")
		b.WriteString(d)
		b.WriteString(".")
	}
	b.WriteString(" No list is authoritative: inclusion is not a safety signal and " +
		"absence is not an observation, so neither moves the severity.")
	if len(unreadable) > 0 {
		b.WriteString(" An unreadable list is recorded as failure evidence rather than " +
			"as an absence, and does not mark this report undetermined — it can " +
			"neither escalate nor lower the level.")
	}
	return b.String()
}
