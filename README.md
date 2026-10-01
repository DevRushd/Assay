# Assay

Mechanical trap-scanner and on-chain safety gate for Stellar assets.

Assay answers one question: **can the issuer of this asset take or freeze my
tokens after I hold them?** It answers it from the ledger's own rules — the
issuer's authorization flags — not from reputation, community reports, or a
domain blocklist.

## Live on testnet

```
Safety registry   CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73
Network           Testnet (Test SDF Network ; September 2015)
```

`get_safety(asset)` is callable now, by any Soroban contract, atomically.
[docs/integrating.md](docs/integrating.md) has a copy-pasteable gate and a
worked example contract that is also deployed on testnet
(`CAL5VYSWLKG367D5IYGI57XH7EMN5PLJ4CD6K3MO2HJBYYKEKPG3NKRX`);
[docs/deployment.md](docs/deployment.md) has the transaction hashes, the
attested assets, and the live fail-closed checks.

## Why this exists

Stellar already has a reputation layer, and Assay does not rebuild it.
StellarExpert publishes asset ratings, a curated address directory, and a
malicious-domain blocklist; SEP-0037 defines the directory format; the SCF
runs a scam-flagging process. Assay **consumes** those as attributed input
signals and never re-derives them.

What no tool in the ecosystem does is the other half:

1. **Trap mechanics from the ledger itself.** Authorization flags are
   consensus-enforced facts about what the issuer is *able* to do. They are
   true whether or not anyone has reported the asset yet, which means a
   brand-new asset with no reputation at all is still fully classifiable.
2. **An on-chain gate.** `get_safety(asset)` is designed to be callable by
   another Soroban contract, atomically, in the same transaction as the
   action it protects.

## The hard part

Detecting a flag is trivial. Judging it is not.

`auth_clawback_enabled` is not inherently malicious — it is the mechanism
regulated issuers use to meet legal obligations like sanctions enforcement
and court-ordered reversal. A scanner that paints every clawback-capable
asset red is wrong about every well-run regulated stablecoin, and a scanner
that is wrong about the biggest assets on the network gets ignored.

So Assay's engine reports **severity plus reasoning**, never a boolean, and
carries an explicit, evaluated position on legitimate clawback use. See
[docs/severity-model.md](docs/severity-model.md) for the model and
[docs/eval.md](docs/eval.md) for the labelled set it is measured against.

## Docs

| Document | What's in it |
| --- | --- |
| [docs/glossary.md](docs/glossary.md) | Every state Assay reports — severity, accountability, verdict state, `undetermined` — and the state each is most often confused with |
| [docs/cli.md](docs/cli.md) | The `assay` binary: scan, attestation, history, serve |
| [docs/severity-model.md](docs/severity-model.md) | The judgment layer: severity levels, the legitimate-use carve-out, and why |
| [docs/checks.md](docs/checks.md) | Each mechanic Assay checks, and what it can and cannot conclude |
| [docs/contract-interface.md](docs/contract-interface.md) | `get_safety(asset)` design and the `evidence_hash` encoding |
| [docs/api-versioning.md](docs/api-versioning.md) | What `/api/v1` guarantees: additive vs breaking changes and the deprecation process |
| [docs/integrating.md](docs/integrating.md) | How your contract calls `get_safety` and gates on both severity and the bitset |
| [docs/trust.md](docs/trust.md) | What you are trusting: verifiable facts vs. relayed claims, and consequence matrix |
| [docs/deployment.md](docs/deployment.md) | Deployed addresses, attested assets, transaction hashes |
| [docs/attester-key.md](docs/attester-key.md) | Attester key custody, loss/compromise response, rotation limits |
| [docs/verifying.md](docs/verifying.md) | How a third party verifies an attestation end to end, without reading the source |
| [docs/attestation-run.md](docs/attestation-run.md) | Every asset scanned, what each check returned, and what the run exposed about the scanner |
| [docs/history.md](docs/history.md) | The observation history API: what is retained, for how long, and what an empty history means |
| [docs/eval.md](docs/eval.md) | Labelled trap/legitimate set and current results |
| [docs/threat-model.md](docs/threat-model.md) | The actors, what each can do, and which attacks Assay defends against, accepts, or scopes out |
| [docs/freshness.md](docs/freshness.md) | How old an attestation may be: measured flag-change rates and window guidance per use class |
| [docs/asset-lists.md](docs/asset-lists.md) | Consuming SEP-0042 Stellar Asset Lists as a second curation source, and why listing is never a safety signal |
| [docs/adding-a-check.md](docs/adding-a-check.md) | How to write a new mechanic check |
| [docs/pipeline.md](docs/pipeline.md) | The full ledger-fact to on-chain-verdict path for a single asset |

## Status

The mechanics engine, the HTTP API, and the on-chain gate all work. The gate is
deployed to testnet, 18 real assets have been scanned and 10 attested from live
scans, and the round trip — scan, attest, `get_safety` — is reproducible end to
end: re-checked on 2026-09-17, a fresh scan reproduced the stored `evidence_hash`
for every attested asset, with the limits recorded in
[#24](https://github.com/use-assay/Assay/issues/24).
[docs/verifying.md](docs/verifying.md) is the procedure a third party follows to
check one of those attestations from scratch, including what a mismatch does and
does not prove.

Four things are worth knowing before you rely on any of it:

- **Coverage is 10 attested assets.** Everything else on the network returns `None`.
  That is the correct answer — an asset nobody has scanned is unknown, not safe
  — but it means the registry is not yet useful as a general lookup, and a
  correctly written gate will refuse nearly everything.
- **An attestation is only as fresh as its `attested_at`.** Nothing is
  refreshing them on a schedule. Issuer flags can change after an attestation is
  written, so pass a `max_age_secs` you would actually accept rather than
  assuming someone is keeping the registry current.
  [docs/freshness.md](docs/freshness.md) measures how often flags actually
  change and recommends windows per use class.
- **This is testnet, not mainnet.** One key can write any attestation, and
  testnet is periodically reset. The live registry's entries are archived: they
  are restored on read with their original `attested_at`, and they do not read
  as missing ([docs/deployment.md](docs/deployment.md#entry-lifetime)). Nothing
  here is ready for money.
- **Severity is capability, not prediction.** It says what an issuer *can* do,
  never what they are likely to do. A regulated stablecoin with clawback and a
  scam with clawback score the same, on purpose — see
  [the severity model](docs/severity-model.md).

The gaps are not left implicit. [docs/threat-model.md](docs/threat-model.md)
names the actors, states which attacks are defended (with the test that holds
them), which are accepted risks, and which are out of scope — including the one
that matters most, that a single compromised attester key can currently cause an
admission.

## License

Apache-2.0. See [LICENSE](LICENSE).
- [Temporal Trust Model](docs/temporal.md)
