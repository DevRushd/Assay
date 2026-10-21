# Differential derivation

An independent re-derivation of ledger facts, compared against what the scanner
produced. Implemented in [`internal/differential`](../internal/differential) —
issue [#48](https://github.com/use-assay/Assay/issues/48).

## Why this exists

Every other test in this repository compares Assay against itself: fixtures go
through the same parser the scan went through, hash tests call the same encoder
the attestation used, eval compares the engine against labels the engine's own
runs produced. A bug in the fetch-and-parse path — taking the wrong record,
misreading a flag — produces a consistent, self-agreeing, wrong answer that no
self-comparison can catch. Independent derivation is the only structural
defence: a second reading of the same fact through a route that shares nothing
with the first.

## Scope

Deliberately narrow. This is not a second scanner. It re-derives the one fact
every severity rests on — **the issuer's authorization flags** — and nothing
else:

- Not reputation. Assay relays curated reputation by design
  ([docs/severity-model.md](severity-model.md)); re-deriving it would be
  building a second reputation layer, which the project exists to avoid.
- Not the judgment layer. The engine's severity rules are tested against the
  labelled corpus; a second copy of the rules would only agree or disagree
  with itself.
- Not the other consumed signals (stellar.toml, directory, blocklist). Those
  are third-party claims that Assay attributes rather than owns; there is no
  ledger route to re-derive them.

## Candidate independent sources, and what each actually proves

The issue asked for this evaluation first. Three candidates were considered;
each is independent along different axes, and "independent" only counts where
it shares nothing with the primary path — protocol, server, and encoding.

| Candidate | Shares with primary | Independence | Verdict |
| --- | --- | --- | --- |
| Horizon `/accounts/{id}` flags | Same REST server, same JSON codec, same client package | Weak | **Rejected as the check.** The flags appear twice in Horizon (asset record and issuer account), but both copies are produced by the same service from the same ledger state. The reconciliation the capability check already performs catches disagreement *within* Horizon; a second Horizon route cannot catch a fault in Horizon's answer itself. Already fetched and used — see below. |
| Soroban RPC `getLedgerEntries` with an account ledger key | Nothing: different protocol (JSON-RPC POST vs REST GET), different SDF service (RPC vs Horizon), different encoding (raw XDR vs Horizon JSON) | Strong | **Implemented.** Reads the same consensus state, so it verifies *facts*, but every layer of the transport and decode is different. |
| Full-history archive (e.g. stellarch) | Different server; but serves *history*, not current state | Wrong axis | **Not implemented.** An archive answers "what was true at ledger N", which is a freshness question, not a correctness check; comparing a live scan against a history archive mostly measures how long ago the ledger changed. Requires trusting an archive operator's completeness, which is exactly the kind of unverified input Assay avoids. |

A fourth route — running a full validator node and reading state directly —
would be stronger still, but it is an operations decision (a node to run and
trust) rather than a package, and the RPC route gets most of the independence
without it.

### The subtle limit of any differential check

Every route reads the same consensus state. A differential check therefore
catches faults in **Assay's fetch and parse path** — the wrong record, the
misread flag, a parsing regression — but not a fault in the ledger state
itself. If the ledger's consensus is wrong, both derivations agree on the
wrong thing. That limit is inherent and is stated here rather than left
implicit: this control is for self-inflicted errors, not for consensus
failures.

## What was implemented

- `internal/differential.Client.AccountFlags` — derives the issuer's flags via
  `getLedgerEntries` on Soroban RPC, using a hand-built account ledger key and
  a hand-decoded `AccountEntry`. The strkey decode (base32 + CRC-16 checksum
  verification) and the XDR offsets are implemented in-package rather than
  imported, so the derivation shares no parsing code with the primary path and
  adds no third-party dependency.
- The XDR layout through the flags field was verified live before
  implementation (2026-09-27, pubnet): the AQUA issuer (no `inflationDest`,
  flags 0) and a revocable ARST issuer (`inflationDest` present, flags 2) both
  decoded to the same flags Horizon reports for the same accounts. The
  `PublicKey` union framing (4-byte tag + 32 bytes) is pinned by fixtures,
  because that offset is exactly the kind of thing a hand parser gets wrong
  once and never notices.
- `Compare` — takes the scanner's reconciled reading (via
  `SubjectProvider`, the same reconciliation rule the capability check uses)
  and the independent reading, and returns one of four states:
  `agreement`, `disagreement`, `inconclusive_one_side`,
  `inconclusive_both_sides`.

## The four states, and why inconclusive is not agreement

- **Agreement** — both derivations answered identically. The only state that
  verifies anything.
- **Disagreement** — both answered, differently. Both values are carried on
  the result and **nothing in this package picks a winner**. Auto-resolving in
  favour of either side (e.g. "trust the ledger, ignore the scanner") would
  convert a detected fault into an undetectable one; the correct response to
  disagreement is human investigation, so the result stops there.
- **Inconclusive (one side)** — exactly one derivation produced no answer. One
  honest reading plus one absence is not agreement: the absent side could have
  found exactly the fault this package exists to catch. Errors are carried
  verbatim on the result.
- **Inconclusive (both)** — neither answered. Nothing was verified.

This is the same rule the rest of the repo states for checks — "'we could not
check' and 'this is fine' must never render the same" — applied to a
comparison instead of a finding.

## Wiring

`differential.Compare` is exported for callers (the future `assay verify`
command of #39 is the natural consumer) rather than invoked automatically:
running a second network round-trip on every scan is an operator's choice, and
a differential disagreement needs somewhere to be *reported*, which is a CLI
and API decision. Nothing in the scan path changed; the scanner's own reading
is exposed through `differential.SubjectProvider` over the same two flag
copies the engine already fetches.

## Tests

All in-package, no network:

- Parser fixtures pin both inflationDest branches, all four flag bits,
  non-account discriminants, and truncation at every boundary before flags.
- The strkey decoder is pinned against live-derived keys (the exact base64
  ledger key the SDF RPC answered for these accounts) and refuses wrong
  version bytes, non-alphabet characters, and checksum corruption.
- Client tests cover an echoing server, a missing entry, a JSON-RPC error
  body, and an HTTP error status, and refuse a response that does not echo
  the requested key.
- Comparison tests cover agreement, disagreement, both-unavailable,
  either-side-unavailable, absent-entry-as-inconclusive, and the acceptance
  test: a **deliberately wrong primary value is caught** and both values are
  preserved on the result.
