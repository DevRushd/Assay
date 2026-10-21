# Fixture provenance

## `stellar-expert-top50.json`

| | |
| --- | --- |
| Source URL | https://api.stellar.expert/explorer/public/asset-list/top50 |
| Captured | 2026-09-27 |
| Format | SEP-0042 Stellar Asset List (SAL), `version: "1.0"`, `network: "public"` |
| Publisher | StellarExpert (self-declared in the document's `provider` field) |
| Size | 50 asset entries, captured verbatim, unedited |

This list is named in [SEP-0042](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0042.md)
("StellarExpert Top50 asset list for Stellar Pubnet") as a reference
implementation of the format, which is why it was chosen as the real published
list the decoder is verified against.

### Licence and terms

- **The API and its responses**: StellarExpert's OpenAPI document (retrieved
  2026-09-27) states `License: MIT` for the API and links a Terms of Service.
  It also states that the API "features Cross-Origin Resource Sharing (CORS)
  implemented in compliance with W3C spec" and requires no authentication.
  The document's own rate-limit/caching guidance is quoted in
  [docs/caching.md](../../../docs/caching.md).
- **The list's own disclaimer**, carried in the document because it is part of
  what consuming the list means: *"Assets included in this list were not
  verified by StellarExpert team. StellarExpert is not affiliated with issuers,
  and does not endorse or advertise assets in the list. Assets reported for
  fraudulent activity removed from the list automatically."*
- This mirrors the SEP-0042 rule the rest of the code relies on: inclusion is
  not endorsement, so it is never allowed to lower a severity.

### Field names verified against it

Checked 2026-09-27 against the captured document and the
[SEP-0042 JSON schema](https://github.com/stellar/stellar-protocol/blob/master/contents/sep-0042/assetlist.schema.json)
(schema `additionalProperties: false` on both levels, so the schema is a
complete list of what may appear):

| Level | Fields present in this list | Fields the schema also allows |
| --- | --- | --- |
| document | `name`, `provider`, `description`, `version`, `network`, `feedback`, `assets` | `name`, `network`, `provider`, `description`, `version`, `feedback`, `assets` |
| asset entry | `code`, `issuer`, `contract`, `name`, `org`, `domain`, `icon`, `decimals` | `name`, `contract`, `code`, `issuer`, `org`, `domain`, `icon`, `decimals`, `comment` |

`comment` is decoded by `internal/assetlist` but does not appear in this
document; the schema permits it and other lists publish it.
`TestFixtureCarriesTheFormatFieldNames` fails if the list ever starts using a
field this package does not decode.

The schema requires `name`, `provider`, `version` and `assets` at document
level, and `name` and `org` on each entry. This list satisfies all of them — all
50 entries carry `org`. Other published lists do not (see the LOBSTR row below),
which is why the decoder is strict about the document's `name` and permissive
about everything else.

### Other lists inspected, not committed

| List | What was checked | Why it is not a fixture |
| --- | --- | --- |
| LOBSTR curated list (`https://lobstr.co/api/v1/sep/assets/curated.json`) | Live 2026-09-27: top-level `name`, `provider`, `description`, `version`, `network`; entries carrying `contract`, `code`, `issuer`, `name`, `domain`, `icon`, `decimals`. Entries omit `org` on some assets, and `contract` is published as a 64-character hex string rather than a StrKey. | Its licence and terms were not determined, so it was verified for field names and not stored. Note the hex `contract`: `Lookup` therefore never relies on the contract field alone, and the fixture above pins the StrKey assumption to a list that uses it. |
| Soroswap token list (`https://raw.githubusercontent.com/soroswap/token-list/main/tokenList.json`) | Named in SEP-0042 as a reference implementation. | Not fetched: no licence identified for it either. |

Neither is referenced by any test, so nothing outside the committed fixture is
required to make the suite green.
