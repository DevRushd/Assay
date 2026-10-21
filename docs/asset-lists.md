# SEP-0042 asset lists

Assay's consumed signals all used to come from one provider. That is a single
point of failure twice over: if StellarExpert is unavailable, every reputation
signal disappears at once — and if StellarExpert's directory simply does not
carry an asset, Assay cannot tell a genuinely unlisted asset from one provider's
blind spot.

A [SEP-0042](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0042.md)
Stellar Asset List (SAL) is a standardised, publisher-agnostic format for
curated asset metadata, so support here is per-format rather than per-vendor:
any list publishing it can be consumed, and none of them is built into Assay.

## What a list is, and what it is not

The spec is explicit about both halves:

> Inclusion of any particular asset in a list should not be considered as
> endorsement or recommendation of any kind. — SEP-0042, §Specification

and, in its security considerations:

> application developer should either depend only on several trustworthy
> providers or utilize the community-maintained repository of curated asset
> lists.

So a list is **one provider's opinion of what assets exist**, with metadata
attached. It is not a safety rating, a certification, or an adversarial
judgment. Assay treats it exactly that way:

| Situation | What Assay reports | What it does **not** do |
| --- | --- | --- |
| The asset is in list A | Evidence: `listed as "…" (org "…", domain "…") in list "A"` | Does not lower severity, does not set a mechanic, does not escalate |
| The asset is not in list B | Evidence: `not present in list "B"` | Does not treat it as an observation of anything |
| List A has it, list B does not | Both claims, plus `Sources disagree — reported, not resolved:` in the reasoning | Does not pick a winner or average them |
| List C could not be read | Evidence: `not retrievable: …`, marked `attempted` | Does not render as an absence, does not mark the report undetermined |

The severity model's first rule — severity is capability-only — is why none of
this can move the level. A contract gating on `severity <= MEDIUM` is relying on
a statement about ledger mechanics; the moment a curated list could influence
that number, it would be relying on a third party's opinion with no way to tell
the two kinds of claim apart. See [severity-model.md](severity-model.md).

## Configuring it

**No list is configured by default**, and that is deliberate:

- Shipping a default would hard-code one provider's curation as authoritative
  for every scan, which is the opposite of what the format is for.
- It would also add evidence to every report, which changes every
  `evidence_hash` — including for assets already attested on chain. Reproducible
  attestation is a property this project does not trade away for a feature.

Instead a deployment opts in:

```sh
assay scan -asset-lists https://api.stellar.expert/explorer/public/asset-list/top50 \
           -asset-lists https://lobstr.co/api/v1/sep/assets/curated.json \
           CODE-ISSUER

assay serve -asset-lists https://example.org/my-list.json   # comma-separated works too
```

Both `-asset-lists=a,b` and `-asset-lists=a -asset-lists=b` are accepted. The
same configuration lives on `scan.Scanner.AssetListURLs` for programmatic use.

Lists are fetched in the order configured, one per scan, best-effort — a list
that is down must not turn a dangerous asset into an error page — and each one's
failure is recorded against that list alone.

### Finding lists to configure

- SEP-1 publishers advertise theirs from `stellar.toml` as `ASSET_LISTS = [...]`.
- The community [Asset Lists Catalog](https://github.com/stellar-asset-lists/index)
  collects them; its web UI is at https://stellar.expert/asset-lists.
- SEP-0042 names reference implementations: LOBSTR's curated list, Soroswap's
  token list, and StellarExpert's Top 50 for pubnet and testnet.

## How a list appears in a report

Each configured list becomes its own `Evidence` entry, attributed by the name
the list published and the URL it was read from, and carrying the time the
*list* was fetched rather than the time of the scan:

```json
{
  "source": "asset-list/StellarExpert Top 50",
  "url": "https://api.stellar.expert/explorer/public/asset-list/top50",
  "claim": "listed as \"USD Coin\" (org \"Centre Consortium LLC dba Centre Consortium\", domain \"centre.io\") in list \"StellarExpert Top 50\"",
  "retrieved_at": "2026-09-27T17:34:00Z",
  "attempted": false
}
```

A list that could not be read has published no name, so it is attributed as
`asset-list` with its URL, and its claim reads `not retrievable: …` with
`attempted: true` — the same attempt-versus-answer distinction every other
consumed signal uses.

The reasoning states the whole picture in one place, including disagreement:

> SEP-0042 asset lists: present in Alpha List (Alpha Collective); absent from
> Beta List (Beta Collective). Sources disagree — reported, not resolved: the
> asset lists disagree with each other: present in Alpha List (Alpha Collective),
> absent from Beta List (Beta Collective). No list is authoritative: inclusion is
> not a safety signal and absence is not an observation, so neither moves the
> severity.

### Why an unreadable list is not `undetermined`

`undetermined` marks a report whose *verdict* is incomplete: it blocks
attestation, because an escalation source that did not answer could have
escalated, and a partial scan must not become an on-chain claim.

An asset list can neither escalate nor lower severity by construction. So a list
that fails to load cannot leave a verdict unknown — marking the report
undetermined would refuse attestations for an informational source that was
never in a position to change the answer. The failure is therefore recorded as
attributed evidence (visible, timestamped, `attempted`), and the reasoning says
explicitly that it did not degrade the report.

StellarExpert's directory and blocklist, which *can* escalate, keep the existing
behaviour: an outage there marks the check undetermined.

## Format notes verified against real lists

Field names were checked against a real published list before being encoded, and
the captured list is committed as a fixture with its provenance in
[`internal/assetlist/testdata/PROVENANCE.md`](../internal/assetlist/testdata/PROVENANCE.md).
The short version:

- Document level: `name`, `provider`, `description`, `version`, `network`,
  `feedback`, `assets`. Only `name`, `provider`, `version` and `assets` are
  required by the schema; the decoder is strict only about `name`, because a
  document with no name cannot be attributed to anyone.
- Entry level: `code`, `issuer`, `contract`, `name`, `org`, `domain`, `icon`,
  `decimals`, `comment`. A list publishes either the classic `code`+`issuer`
  pair or a Soroban `contract` (or both), so Assay matches on both — a classic
  asset's contract address is derived from its code and issuer, and Horizon
  reports it on the asset record already fetched.
- Codes are compared case-sensitively: Stellar asset codes are case-sensitive,
  and folding case could match a lookalike.
- Real lists are imperfect: LOBSTR's published list omits `org` on some entries
  and encodes `contract` as raw hex rather than a StrKey. The decoder does not
  reject a list for that; it reports what was published.

### `comment` is never parsed

The format allows a free-text `comment` per entry ("Alerts, messages, or other
additional information specified by the provider"). It is carried through as
published and never interpreted. Searching prose for scam keywords would be
writing a scam heuristic over someone else's curation — which
[CONTRIBUTING.md](../CONTRIBUTING.md) forbids outright, and which would make
Assay assert a conclusion no provider actually made.

## Licence and terms

- **The format**: SEP-0042, Status Draft, Version 0.2.1, in the
  [stellar-protocol repository](https://github.com/stellar/stellar-protocol)
  (Apache-2.0). Draft status is why this is consumed defensively: the schema is
  a complete list of permitted fields (`additionalProperties: false` at both
  levels), so an unknown field is a decoding surprise rather than data.
- **Each list carries its own terms.** They are not all the same, and Assay does
  not assume they are. The one list used as a fixture — StellarExpert's Top 50 —
  comes from an API documented as MIT-licensed; its own description states that
  the assets "were not verified by StellarExpert team" and that StellarExpert
  "does not endorse or advertise assets in the list". Both are recorded in
  PROVENANCE.md alongside the capture date.
- No list's licence is inferred from another's, and no list is fetched by
  default — so nothing is consumed that someone did not ask for.
