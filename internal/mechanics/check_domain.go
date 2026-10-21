package mechanics

import (
	"context"
	"fmt"
	"strings"

	"github.com/use-assay/assay/internal/sep1"
)

// DomainCheck performs reciprocal SEP-1 domain verification.
//
// It never contributes to severity. Its output is the Accountability field:
// whether an identifiable party has publicly claimed this asset. A verified
// domain does not make an issuer's confiscation power any weaker; it only
// means there is someone to name.
type DomainCheck struct{}

// ID implements Check.
func (DomainCheck) ID() string { return "sep1-domain" }

// Describe implements Check.
func (DomainCheck) Describe() string {
	return "Checks whether the issuer's advertised home_domain publishes a " +
		"stellar.toml that claims this exact asset. Establishes accountability, " +
		"not safety: it never raises or lowers severity."
}

// Run implements Check.
//
// Verification requires both directions to agree. The account advertises a
// home_domain, and that domain's stellar.toml must list this code AND this
// issuer. Either half alone is worthless: home_domain is a free-text field any
// account can set to any string, and a stellar.toml can list any asset code it
// likes. Only the round trip is evidence.
func (c DomainCheck) Run(_ context.Context, s *Subject) (Finding, error) {
	f := Finding{
		Check:    c.ID(),
		Title:    "Issuer domain verification",
		Severity: Clear, // accountability is never severity
		Evidence: []Evidence{},
	}
	acc := AccountabilityUnknown
	f.Accountability = &acc

	domain := s.HomeDomain()
	if domain == "" {
		f.Mechanics = MechDomainUnverified
		f.Reasoning = "The issuer account advertises no home_domain, so there is no " +
			"published identity to verify against. Nobody has publicly claimed this " +
			"asset. That is not a failed verification — there was no claim to test — " +
			"which is why accountability is unknown rather than unverified."
		return f, nil
	}

	// The advertised domain and the curated directory disagree about who
	// claims this asset. Reported before toml reciprocity: whichever way the
	// toml answers, the two sources cannot both be right, and a holder needs
	// both claims attributed to their source rather than one silently winning.
	if s.Directory != nil && s.Directory.Domain != "" && s.Directory.Domain != domain {
		f.Mechanics = MechDomainUnverified
		acc = AccountabilityUnverified
		f.Accountability = &acc
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q, but the curated directory lists the "+
				"same issuer under %q. The two sources disagree about who claims this "+
				"asset, so accountability is unverified: it cannot be determined which "+
				"domain, if either, published a reciprocal claim.",
			domain, s.Directory.Domain)
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "horizon",
			URL:         horizonAccountURL(s.Asset.Issuer),
			Claim:       fmt.Sprintf("home_domain %q", domain),
			RetrievedAt: NewCanonicalTime(s.IssuerFetchedAt),
		})
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "stellar.expert/directory",
			URL:         s.DirectoryURL,
			Claim:       fmt.Sprintf("listed under domain %q", s.Directory.Domain),
			RetrievedAt: NewCanonicalTime(s.DirectoryFetchedAt),
		})
		return f, nil
	}

	if s.Toml == nil {
		acc = AccountabilityUnverified
		f.Mechanics = MechDomainUnverified
		if s.TomlRefused {
			// A host-policy refusal is a decision Assay made, not a source that
			// failed. It is reported as attributed evidence, the same way a
			// fetch failure is, but labelled Refused so a consumer can tell
			// "Assay declined to fetch this host" from "the host did not
			// answer" without reading the claim text.
			f.Reasoning = fmt.Sprintf(
				"The issuer advertises home_domain %q, which names a host Assay "+
					"refuses to fetch from (%s). Non-public hosts — loopback, private "+
					"and link-local addresses, and the cloud metadata address — are "+
					"refused so an issuer cannot point the scanner at the network the "+
					"scanner runs on. The domain claim is therefore unverified: the "+
					"host was never read.",
				domain, s.TomlErr)
			f.Evidence = append(f.Evidence, Evidence{
				Source:      "stellar.toml",
				URL:         s.TomlURL,
				Claim:       "refused: " + s.TomlErr,
				RetrievedAt: NewCanonicalTime(s.TomlAttemptedAt),
				Attempted:   true,
				Refused:     true,
			})
			return f, nil
		}
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q, but its stellar.toml could not be "+
				"read (%s). The domain claim is unverified: anyone can set home_domain "+
				"to any value, so an unreachable toml proves nothing about who issued this.",
			domain, s.TomlErr)
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.toml",
			// The fetch never produced a document, so there is no final
			// location: URL and RequestedURL are the same here.
			URL:          s.TomlURL,
			RequestedURL: s.TomlURL,
			Claim:        "not retrievable: " + s.TomlErr,
			// The toml never answered, so this carries the attempt time, not a
			// retrieval time — and says so programmatically.
			RetrievedAt: NewCanonicalTime(s.TomlAttemptedAt),
			Attempted:   true,
		})
		return f, nil
	}

	if !s.Toml.Claims(s.Asset.Code, s.Asset.Issuer) {
		acc = AccountabilityUnverified
		f.Mechanics = MechDomainUnverified
		if s.TomlLinked != nil {
			return c.resolveLinked(f, s, domain, s.TomlLinked), nil
		}

		// SEP-0001 lets a currency entry delegate to its own TOML file. When
		// those links were followed, a match there is a claim like any other;
		// when they could not all be read, the answer stays unresolved and must
		// not be reported as a refusal. Overstating a negative is the same
		// class of error as overstating a positive.
		if res := s.TomlLinked; res != nil {
			return c.resolveLinked(f, s, domain, res), nil
		}

		// SEP-0001 lets a currency entry delegate to its own TOML file, and
		// does not require the link to be the entry's only field: an entry may
		// carry a code and issuer next to the link. Assay does not follow those
		// links yet, so it must not claim the domain failed to name this asset
		// when it may have done so in a document Assay never read. An entry
		// that already matches inline is not an unresolved link — it is the
		// claim itself — so only the entries that do not match are counted.
		// Overstating a negative is the same class of error as overstating a
		// positive.
		if linked := s.Toml.LinkedCurrencies(s.Asset.Code, s.Asset.Issuer); linked > 0 {
			f.Reasoning = fmt.Sprintf(
				"The issuer advertises home_domain %q and that domain publishes a "+
					"stellar.toml, but this asset (%s) is not declared inline in its "+
					"CURRENCIES. The toml delegates %d currency entries to separate "+
					"per-currency TOML files, by a toml link, whether or not the entry "+
					"also carries a code. Assay does not follow those links yet, so this "+
					"asset may be claimed in one of them. Treated as unverified "+
					"because it is unconfirmed, not because it was refuted.",
				domain, s.Asset, linked)
			f.Evidence = append(f.Evidence, Evidence{
				Source: "stellar.toml",
				// URL is the post-redirect location the document was read from;
				// RequestedURL is what home_domain pointed at. Recording both is
				// what lets an auditor tell a claim made by the requested host
				// from one served by a host a redirect moved the fetch to.
				URL:          s.Toml.URL,
				RequestedURL: s.TomlURL,
				Claim: fmt.Sprintf(
					"CURRENCIES lists %d entries, none matching %s inline; %d are links not followed",
					len(s.Toml.Currencies), s.Asset, linked),
				RetrievedAt: NewCanonicalTime(s.Toml.FetchedAt),
			})
			return f, nil
		}

		acc = AccountabilityUnverified
		f.Mechanics = MechDomainUnverified
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q and that domain publishes a "+
				"stellar.toml, but the toml does not list this asset (%s) in its "+
				"CURRENCIES. The domain has not claimed this asset, so the association "+
				"is asserted by the issuer only and is not reciprocated.",
			domain, s.Asset)
		f.Evidence = append(f.Evidence, Evidence{
			Source:       "stellar.toml",
			URL:          s.Toml.URL,
			RequestedURL: s.TomlURL,
			Claim: fmt.Sprintf("CURRENCIES lists %d entries, none matching %s",
				len(s.Toml.Currencies), s.Asset),
			RetrievedAt: NewCanonicalTime(s.Toml.FetchedAt),
		})
		return f, nil
	}

	acc = AccountabilityVerified
	f.Reasoning = fmt.Sprintf(
		"The issuer advertises home_domain %q, and that domain's stellar.toml lists "+
			"this exact code and issuer. The association is reciprocal, so a named "+
			"party has publicly claimed this asset. This says nothing about what the "+
			"issuer can do to your balance — see the capability finding for that.",
		domain)
	f.Evidence = append(f.Evidence, Evidence{
		Source:      "stellar.toml",
		URL:         s.Toml.URL,
		Claim:       "CURRENCIES claims " + s.Asset.String(),
		RetrievedAt: NewCanonicalTime(s.Toml.FetchedAt),
	})
	// SEP-0001 lets a CURRENCIES entry carry a status — "live", "dead",
	// "test". An issuer declaring its own asset dead or test is a fact a
	// prospective holder wants, the document is already fetched, and
	// surfacing it costs nothing. It is relayed as attributed evidence and
	// moves nothing else: it is the issuer's own claim about its own asset,
	// not a ledger fact, so severity stays capability-only — and an issuer
	// can write any string here, so Assay never treats it as a determination
	// of its own. Accountability was already settled by the reciprocity test
	// above and is unchanged by what the claim says.
	if status := s.Toml.Status(s.Asset.Code, s.Asset.Issuer); status != "" {
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "stellar.toml",
			URL:         s.Toml.URL,
			Claim:       "CURRENCIES entry status: " + status,
			RetrievedAt: NewCanonicalTime(s.Toml.FetchedAt),
		})
	}
	// The document also declares who publishes it (ORG_NAME / ORG_URL), which
	// is what a human reading the report wants first: who claims to be behind
	// this asset. Relayed as attributed evidence and nothing else — see
	// appendOrganisationEvidence for why it moves no other field.
	appendOrganisationEvidence(&f, s.Toml)
	return f, nil
}

// appendOrganisationEvidence adds the toml's own publisher fields — ORG_NAME
// and ORG_URL — to the finding as one attributed evidence claim, when the
// document publishes at least one of them.
//
// A reader of a report wants to know who claims to be behind an asset, and the
// claim is the toml's, not Assay's: the fields are relayed with the source and
// the URL they were read from, quoted with %q exactly like every other
// issuer-controlled string in this report (home_domain, a directory name), so
// the encoder escapes them into their own field like every other claim before
// they reach the hashed preimage.
//
// It moves nothing else. Severity stays capability-only — an issuer buying
// attribution gains nothing there — and accountability was already settled by
// the reciprocity test, not by who the document says it is: a toml may name
// anyone it likes, so this is never a verification of identity, only a relay
// of the claim. A document that declares neither field contributes no evidence
// at all, so the evidence bytes — and therefore evidence_hash — are unchanged
// for every asset attested without one.
//
// doc is the document the fields were read from, and its URL is what the claim
// is attributed to: for a linked claim that is still the document home_domain
// itself, not the per-currency file the asset claim came from.
func appendOrganisationEvidence(f *Finding, doc *sep1.Doc) {
	if doc == nil {
		return
	}
	claims := make([]string, 0, 2)
	if doc.Documentation.OrgName != "" {
		claims = append(claims, fmt.Sprintf("ORG_NAME %q", doc.Documentation.OrgName))
	}
	if doc.Documentation.OrgURL != "" {
		claims = append(claims, fmt.Sprintf("ORG_URL %q", doc.Documentation.OrgURL))
	}
	if len(claims) == 0 {
		return
	}
	f.Evidence = append(f.Evidence, Evidence{
		Source:      "stellar.toml",
		URL:         doc.URL,
		Claim:       strings.Join(claims, " "),
		RetrievedAt: NewCanonicalTime(doc.FetchedAt),
	})
}

// resolveLinked renders the domain finding for an issuer whose asset was not
// declared inline but whose per-currency links were followed.
//
// A match in a linked document is a claim exactly like an inline one, so it
// sets verified accountability. Everything else stays unverified, matching the
// rule this check has always followed — a domain that advertised an asset it
// did not confirm is unverified — but the reasoning distinguishes a genuine
// refusal (every link was read and none named the asset) from an unresolved
// answer (a link could not be read, or the follow bound was reached). Those
// must never render the same: overstating a negative is the same class of
// error as overstating a positive.
func (DomainCheck) resolveLinked(f Finding, s *Subject, domain string, res *sep1.LinkedResolution) Finding {
	if res.Claimed {
		acc := AccountabilityVerified
		f.Accountability = &acc

		retrieved := s.Toml.FetchedAt
		for _, ld := range res.Docs {
			if ld.URL == res.ClaimedURL && ld.Doc != nil {
				retrieved = ld.Doc.FetchedAt
			}
		}
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q, and this asset (%s) is not declared "+
				"inline in that domain's stellar.toml, but a per-currency TOML it links to "+
				"(%s) names this exact code and issuer. The association is reciprocal, so a "+
				"named party has publicly claimed this asset. This says nothing about what "+
				"the issuer can do to your balance — see the capability finding for that.",
			domain, s.Asset, res.ClaimedURL)
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "stellar.toml",
			URL:         res.ClaimedURL,
			Claim:       "linked document claims " + s.Asset.String(),
			RetrievedAt: NewCanonicalTime(retrieved),
		})
		// A verified claim is a verified claim however it arrived, so the
		// publisher declared by the document home_domain points at is surfaced
		// here exactly as it is for an inline claim — attributed to the document
		// that declared it, not to the linked file the claim came from.
		appendOrganisationEvidence(&f, s.Toml)
		return f
	}

	acc := AccountabilityUnverified
	f.Accountability = &acc
	f.Mechanics = MechDomainUnverified

	// The bound was reached before every link could be read. The documents
	// past the bound may have claimed the asset, so this is unresolved, not a
	// refusal, and the report says the bound was hit.
	if res.Deferred > 0 {
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q and that domain publishes a "+
				"stellar.toml, but this asset (%s) is not declared inline in its "+
				"CURRENCIES. The toml delegates %d currency entries to separate "+
				"per-currency TOML files; Assay followed the first %d and left %d "+
				"unfollowed because its bound of %d documents was reached, so this "+
				"asset may be claimed in one of the unread documents. Treated as "+
				"unverified because it is unconfirmed, not because it was refuted.",
			domain, s.Asset, res.Attempted+res.Deferred, res.Attempted, res.Deferred,
			sep1.MaxLinkedDocuments)
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.toml",
			URL:    s.Toml.URL,
			Claim: fmt.Sprintf(
				"CURRENCIES lists %d entries, none matching %s inline; %d linked documents left unread (bound: %d)",
				len(s.Toml.Currencies), s.Asset, res.Deferred, sep1.MaxLinkedDocuments),
			RetrievedAt: NewCanonicalTime(s.Toml.FetchedAt),
		})
		return f
	}

	// At least one link could not be read. Whether it claimed the asset is
	// simply unknown, so the answer stays unresolved and the reasoning keeps
	// the hedge — it never claims the domain failed to name this asset.
	unread := 0
	for _, ld := range res.Docs {
		if ld.Err != "" {
			unread++
		}
	}
	if unread > 0 {
		f.Reasoning = fmt.Sprintf(
			"The issuer advertises home_domain %q and that domain publishes a "+
				"stellar.toml, but this asset (%s) is not declared inline in its "+
				"CURRENCIES. The toml delegates %d currency entries to separate "+
				"per-currency TOML files; %d of them could not be read, so this "+
				"asset may be claimed in one of them. Treated as unverified because "+
				"it is unconfirmed, not because it was refuted.",
			domain, s.Asset, res.Attempted, unread)
		// The main toml did resolve; it is some of its links that did not. The
		// claim is about the document Assay did read, so it carries that
		// document's retrieval time and is not marked Attempted.
		f.Evidence = append(f.Evidence, Evidence{
			Source: "stellar.toml",
			URL:    s.Toml.URL,
			Claim: fmt.Sprintf(
				"CURRENCIES lists %d entries, none matching %s inline; %d of %d linked documents could not be read",
				len(s.Toml.Currencies), s.Asset, unread, res.Attempted),
			RetrievedAt: NewCanonicalTime(s.Toml.FetchedAt),
		})
		return f
	}

	// Every link was read and none names the asset. This is a genuine
	// refusal: the domain published a stellar.toml and its linked documents,
	// and none of them claims this code and issuer.
	f.Reasoning = fmt.Sprintf(
		"The issuer advertises home_domain %q and that domain publishes a "+
			"stellar.toml, but neither the toml's CURRENCIES nor the %d per-currency "+
			"documents it links to list this asset (%s). The domain has not claimed "+
			"this asset, so the association is asserted by the issuer only and is not "+
			"reciprocated.",
		domain, res.Attempted, s.Asset)
	f.Evidence = append(f.Evidence, Evidence{
		Source: "stellar.toml",
		URL:    s.Toml.URL,
		Claim: fmt.Sprintf(
			"CURRENCIES lists %d entries and %d linked documents, none matching %s",
			len(s.Toml.Currencies), res.Attempted, s.Asset),
		RetrievedAt: NewCanonicalTime(s.Toml.FetchedAt),
	})
	return f
}
