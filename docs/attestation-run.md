# Attestation run

Every asset Assay has attested on-chain, what each check returned, and what the
run exposed about the scanner itself.

This document exists to be checked rather than believed. Every figure below came
from a live command or an on-chain record, and each section says which command
produces it. Nothing here is reconstructed from an earlier write-up.

- **Registry** `CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73` (testnet)
- **Example gate** `CAL5VYSWLKG367D5IYGI57XH7EMN5PLJ4CD6K3MO2HJBYYKEKPG3NKRX` (testnet, redeployed 2026-09-16 with the [#26](https://github.com/use-assay/Assay/issues/26) ceiling)
- **First tranche attested** 2026-08-15 · **re-verified** 2026-09-05
- **Second tranche** 2026-09-05
- **Third tranche** 2026-09-16

To reproduce any row:

```sh
./assay scan CODE-ISSUER              # the findings and reasoning
./assay attestation -raw CODE-ISSUER  # severity, flags, evidence_hash
./assay attestation -preimage CODE-ISSUER   # the exact bytes hashed
make read ASSET=CODE-ISSUER           # what the contract actually stores
```

## Sample so far

**18 assets scanned, 10 attested on-chain.** The target is 20–25, reached across
several sittings rather than in one sweep; this document grows as each tranche
completes.

The first four were attested 2026-08-15. Nine more were added 2026-09-05, chosen
deliberately to include assets expected to come back **clean** — a scanner
measured only on assets with problems is uncalibrated, and the original four
were three-quarters bad news. Five more were scanned 2026-09-16; that tranche
went looking for clean assets and found counterfeiters instead, which turned
out to be the more honest calibration. See
[the third tranche](#third-tranche-2026-09-16).

| Asset | Severity | Base | Escalated | Accountability | Flags | On-chain |
| --- | --- | --- | --- | --- | --- | --- |
| `AQUA` | 0 clear | 0 | no | verified | `0` | yes |
| `ARST` | 0 clear | 0 | no | verified | `0` | yes |
| `yXLM` | 0 clear | 0 | no | verified | `0` | no |
| `XRP` | 0 clear | 0 | no | verified | `0` | no |
| `SSLX` | 0 clear | 0 | no | verified | `0` | no |
| `SHX` | 0 clear | 0 | no | verified | `8` | no |
| `USDC` | 2 medium | 2 | no | unverified | `18` | yes |
| `EURC` | 2 medium | 2 | no | unverified | `18` | no |
| `USDZ` | 3 high | 3 | no | verified | `6` | yes |
| `ZARZ` | 3 high | 3 | no | verified | `6` | no |
| `USDGLO` | 3 high | 3 | no | verified | `6` | yes |
| `BERKSHIRE` | 4 critical | 3 | **yes** | unverified | `54` | yes |
| `DOGE` | 4 critical | **0** | **yes** | unverified | `48` | yes |
| `VELO` | 0 clear | 0 | no | unknown | `16` | yes |
| `KALE` — kalepail.com issuer | 0 clear | 0 | no | unverified | `16` | yes |
| `KALE` — xlmcash.tech issuer | 4 critical | 0 | **yes** | unverified | `48` | no |
| `REPO` | 4 critical | 0 | **yes** | unverified | `48` | yes |
| `yFLR` — flare.claims issuer | *refused* | — | — | — | — | no |

Not every scan is attested. Each attestation is a real transaction, and the
value of this document is the scan record; the on-chain subset is chosen to
cover the range rather than to inflate a count.

**Calibration.** Of the 49 issued assets in StellarExpert's top 50 by rating,
**39 carry no authorization flags at all**, three carry only `auth_immutable`,
and seven carry some power. So `clear` is the overwhelmingly common answer on
the network, and a sample that did not reflect that would be measuring the
wrong thing.

`DOGE` is the most informative row in the table: base severity `0`, final
severity `4`. Capability analysis honestly returns `clear` for a known scam,
because its issuer genuinely holds no power over a holder's balance. It is
critical solely because a curated source says so. That asset is why reputation
exists as a separate upward-only axis — and it is also what broke two things
this run found.

---

## AQUA — clear

`AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA`
Scanned 2026-09-05T06:55:53Z · attested 2026-08-15T05:26:51Z

**`capability` → clear, mechanics none.** Horizon reports
`auth_required=false auth_revocable=false auth_immutable=false auth_clawback_enabled=false`.
The issuer holds no authorization flags: it cannot freeze, confiscate, or gate
this asset. The reasoning also states the converse, which matters — the flags
are *not* locked (`auth_immutable` unset), so the issuer may add freeze or
confiscation powers later. Under CAP-0035 that would not reach existing
trustlines but would apply to any opened after the change.

**`sep1-domain` → accountability verified.** `home_domain` is `aqua.network`,
and that domain's `stellar.toml` `CURRENCIES` lists this exact code and issuer.
Reciprocal, so a named party has publicly claimed the asset. It contributes
nothing to severity.

**`reputation` → no escalation.** The directory lists the issuer as
`"AQUA Issuer"` (domain `aqua.network`, tags `anchor, issuer`); blocked-domains
returns `blocked=false`. Neither lowers the capability severity.

| | |
| --- | --- |
| On-chain | `severity 0`, `flags 0`, `attested_at 1786771611` (first write) |
| `evidence_hash` | `688453bd22e9b694b9c70659d37526bdae18944645542642008e9d961461a4a9` |
| Attest tx | `1b6bafc1226570b2415299f5531256716f4d8dc489a9784fcd6ea347d0f63f5f` |
| Re-attested | 2026-09-16, tx `595f89b53c897f583132e302ea6f78f1c334ce819423a27c5dd7981174fe39e7`, `attested_at 1789546357` — same `evidence_hash`, so only the timestamp moved |

---

## USDC — medium

`USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`
Scanned 2026-09-05T06:55:58Z · attested 2026-08-15T05:27:11Z

**`capability` → medium, mechanics `auth_revocable`.** The issuer can freeze a
holder's balance so it cannot be moved. It **cannot** claw back —
`auth_clawback_enabled=false`, verified live. Worth stating plainly because the
widespread assumption that regulated stablecoins carry clawback is false for the
largest asset on the network.

**`sep1-domain` → accountability unverified, mechanic `domain_unverified`.**
`home_domain` is `circle.com`, and `https://circle.com/.well-known/stellar.toml`
returns **404**. So the most reputable regulated stablecoin on Stellar fails
reciprocal SEP-1 verification by the letter of the spec.

This is the case that justifies keeping accountability out of severity. Had
attribution been a discount, USDC would score worse than a scam asset with a
working `stellar.toml`. It is reported as it is, not special-cased.

Note also that the directory names the issuer `"Centre"` on domain `centre.io`,
which does not match the advertised `circle.com`. Assay does not currently
compare those two — see [tracked as #4](https://github.com/use-assay/Assay/issues/4).

**`reputation` → no escalation.** Directory: `"Centre"` (tags `anchor, issuer`).
Blocked-domains: `circle.com` `blocked=false`.

| | |
| --- | --- |
| On-chain | `severity 2`, `flags 18` (`auth_revocable`\|`domain_unverified`), `attested_at 1786771631` |
| `evidence_hash` | `e7fc765d396de672a85c1b7fe76f67b05a17ad0798167748b285df020ed790bd` |
| Attest tx | `9869957e510ac6cb9ba4e5ffaff66ad0286e420e824efc0095d9e578be37564e` |

---

## USDZ — high, and the reason severity is capability-only

`USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR`
Scanned 2026-09-05T06:56:02Z · attested 2026-08-15T05:27:31Z

**`capability` → high, mechanics `auth_revocable | auth_clawback_enabled`.** The
issuer can freeze a balance and can confiscate it outright and burn it, without
the holder's signature. Clawback already applies to trustlines opened now.

**`sep1-domain` → accountability verified.** `home_domain` is `zeam.money` and
that domain's `stellar.toml` claims this exact code and issuer.

**This is the case the severity model exists for.** USDZ is domain-verified,
unblocklisted, and scores `high` anyway — because a verified domain does not
weaken clawback. It only names who holds it. Accountability is reported beside
severity and never folded into it.

**`reputation` → no escalation.** Directory: `"Zeam.Money"` (domain
`zeam.money`, tags `issuer`). Blocked-domains: `blocked=false`.

A caution, because it would be easy to over-read this asset: a directory tag of
`issuer` and a working `stellar.toml` establish that *someone published a claim*,
not that the entity behind it is what it appears to be. Assay has not
independently verified who operates `zeam.money`, and nothing in this document
should be read as saying it has.

| | |
| --- | --- |
| On-chain | `severity 3`, `flags 6`, `attested_at 1786771651` |
| `evidence_hash` | `ca9b13a66f3a0a4b43d66dea29a505658447e08eee200d2bdb5e66aa1065fb4d` |
| Attest tx | `069d519fa20c472bbc3756291307fb30719219903c1e62a27b4967c0b07ecfd6` |

---

## BERKSHIRE — critical by escalation

`BERKSHIRE-GA22QHSHQEHDJS2ZOINSC77XPPQ24G5EFRJGVEIZLKC5FAW3PQ5XNSDQ`
Scanned 2026-09-05T06:56:07Z · attested 2026-08-15T05:27:46Z

**`capability` → high, mechanics `auth_revocable | auth_clawback_enabled`.**
Identical capability to USDZ. On flags alone these two assets are the same
asset, which is the intended behaviour: capability is capability.

**`sep1-domain` → accountability unverified, mechanic `domain_unverified`.**
`home_domain` is `nasdaq.finance`; DNS does not resolve it.

**`reputation` → escalates to critical, mechanic `blocklisted`.** The curated
directory lists the issuer as `"Scam Asset"` with tags `malicious, unsafe`.
Reported as StellarExpert's determination, not re-derived by Assay, and it
raises the level regardless of the flags.

Base stays `3`; final severity is `4`; `escalated: true`. The two numbers are
stored separately precisely so this is auditable.

**A caveat this asset exposed.** `blocked-domains` returns
`"nasdaq.finance" blocked=false` — the malicious-domain blocklist does **not**
contain a domain whose issuer the directory tags `malicious`. The escalation
came entirely from the directory. Had Assay consulted only the blocklist,
a confirmed scam would not have escalated. Consumed sources are not
interchangeable and are not individually complete.

| | |
| --- | --- |
| On-chain | `severity 4`, `flags 54`, `attested_at 1786771666` |
| `evidence_hash` | `dc2bbf0849dfc001c44be9a5de4fe19c39300e5c4735c9ed3311b3d214171a0d` |
| Attest tx | `322f4bb5fcc84cea9231b7d12e0a964a304a7bd4ea78f97991ca335426e5e2ff` |

---

## The round trip still reproduces, three weeks on

Re-scanned 2026-09-05 against attestations written 2026-08-15. All four
severities, bitsets, and evidence hashes match what the contract stores:

| Asset | Re-scan `severity flags evidence_hash` | On-chain | Match |
| --- | --- | --- | --- |
| `AQUA` | `0 0 688453bd…61a4a9` | `0 0 688453bd…61a4a9` | yes |
| `USDC` | `2 18 e7fc765d…d790bd` | `2 18 e7fc765d…d790bd` | yes |
| `USDZ` | `3 6 ca9b13a6…65fb4d` | `3 6 ca9b13a6…65fb4d` | yes |
| `BERKSHIRE` | `4 54 dc2bbf08…171a0d` | `4 54 dc2bbf08…171a0d` | yes |

That is the property the encoding was designed for: retrieval timestamps are
outside the preimage, so unchanged evidence reproduces the same hash and a
verifier can re-scan rather than trust. One of the four reproduces for a
weaker reason than it appears — see [Finding 2](#finding-2), and the
[2026-09-17 reproducibility audit](#reproducibility-audit-2026-09-17), which found
three of the ten on-chain hashes exposed the same way.

## Fail-closed, demonstrated

Verified live on testnet on 2026-09-05 using `native` XLM as a control that is
deliberately never attested (testnet SAC
`CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC`).

| Attempted | Result | Why that is correct |
| --- | --- | --- |
| `get_safety(unattested)` | `null` | Never-attested stays distinguishable from an attestation of `clear`. Collapsing them would make every unscanned asset read as safe. |
| `is_safe(unattested, max_severity=4, max_age_secs=0)` | `false` | These are the **most permissive arguments the gate accepts** — the maximum severity, freshness check disabled. It still refuses, because there is nothing to admit. |
| gate `would_admit(unattested)` | `false` | Same answer through a real cross-contract call rather than a direct read. |
| gate `deposit(unattested)` **submitted** | reverts `Error(Contract, #1)` `NotAttested` | The refusal is a real transaction revert, not an advisory return value. |

The second row is the one that matters. An unknown asset is unknown, not safe,
and no argument the caller supplies converts one into the other.

---

## What the checks can get wrong

Stated per check, because a scanner that publishes only its successes is not
measurable.

### `capability`

- **Reads two copies of the flags and used not to corroborate them.** Severity
  comes from the `flags` object on Horizon's `/assets` record. The scan also
  fetches the issuer *account*, which carries its own copy of the same flags.
  The first run compared neither and silently used one. This is now fixed:
  `check_capability.go` reconciles both ingestion paths and, on disagreement,
  takes the more dangerous reading and cites both URLs
  ([checks.md](checks.md#the-two-copies-of-the-flags)).
- **Prospective only.** Clawback is inherited at trustline creation (CAP-0035),
  so a `high` verdict describes what happens to a trustline you open *now*, not
  a balance you already hold.
- **`clear` used to double as "not evaluated".** There was no severity value
  meaning unknown, so a report built from an empty subject read `clear` — the
  safest value in the ABI. This is now fixed by the `unevaluated` sentinel (5)
  and `ErrUnevaluated`, which keep an unread flag out of the preimage and
  off-chain ([#32](https://github.com/use-assay/Assay/issues/32),
  [glossary](glossary.md#not-evaluated)).
- **No false positives observed in this run.** Flags are consensus-enforced
  booleans; the check reports them without interpretation. Its risk is
  under-reporting, not over-reporting.

### `sep1-domain`

- **`unverified` conflates two different facts.** "The `stellar.toml` could not
  be fetched" and "it was fetched and does not claim this asset" both produce
  `unverified`. The distinction survives only in the prose reasoning and the
  evidence claim — a consumer switching on the JSON `accountability` field
  cannot tell a broken web server from a refused claim. Both appear in this run:
  USDC is a 404, BERKSHIRE is a DNS failure.
- **Linked currency files are not followed.** A `stellar.toml` may point to a
  per-currency file rather than inline the entry. Assay reports that as
  unconfirmed rather than refuted, counting every entry that carries a `toml`
  link whether or not it also carries a code, and excluding only entries that
  already declare the asset inline — a claim Assay did read needs no hedge.
- **A verified domain is weak evidence.** It proves someone published a matching
  claim. Publishing a `stellar.toml` takes ten minutes.

### `reputation`

- **This check's failure mode is the subject of [Finding 1](#finding-1) below,
  and it is the most serious thing in this document.**
- **Escalation rests on a self-asserted string.** The blocklist is queried using
  the issuer's `home_domain` — the same free-text field this project elsewhere
  says proves nothing. An issuer that clears `home_domain` is never checked
  against the blocklist at all.
- **Only two directory tags are recognised** (`malicious`, `unsafe`). Any other
  adverse tag is silently ignored — a false negative that will never announce
  itself.
- **Consumed sources are not individually complete**, as BERKSHIRE showed:
  directory `malicious`, blocklist `blocked=false`.

---

## The second tranche, 2026-09-05

Nine assets added. All nine scans completed with every source answering — which
is now something the output states rather than something to be assumed.

| Asset | Issuer | Result |
| --- | --- | --- |
| `yXLM` | `GARDNV3Q…TEDL5T55` | clear, verified (`ultracapital.xyz`) |
| `XRP` | `GBXRPL45…PRDTD5` | clear, verified |
| `ARST` | `GCSAZVWX…DRGCI3DG` | clear, verified |
| `SSLX` | `GBHFGY3Z…REH37UR` | clear, verified |
| `SHX` | `GDSTRSHX…7I7KJ6JH` | clear + `auth_immutable`, verified (`stronghold.co`) |
| `EURC` | `GDHU6WRG…Y4ITNPP2` | medium, `circle.com` toml 404 |
| `ZARZ` | `GAROH4EV…MCTJBB3U` | high, clawback, verified (`zeam.money`) |
| `USDGLO` | `GBBS25EG…J34HWS6XV` | high, clawback, verified; issuer not in directory |
| `DOGE` | `GA22IDJN…AXCULNQ7P` | **critical by escalation, base clear** |

Three were attested on-chain:

| Asset | On-chain | `evidence_hash` | Attest tx |
| --- | --- | --- | --- |
| `DOGE` | `severity 4`, `flags 48`, `attested_at 1788592982` (2026-09-05T07:23:02Z) | `396c9f7c…91647e` | `ac1a89a64159e6ac2e9ed61bd67a79cd1584287cf57d19f9dc188d80e81298a6` |
| `ARST` | `severity 0`, `flags 0`, `attested_at 1788593012` (2026-09-05T07:23:32Z) | `82a6103f…fccacb` | `f497b91ab84340bcb7418940e620d080c8566e0cdf27346c8d74e165b5d66506` |
| `USDGLO` | `severity 3`, `flags 6`, `attested_at 1788593047` (2026-09-05T07:24:07Z) | `69b8c4f8…7c27a5` | `6016ed7d908cd20237f114b0cb6778886027ddc8336952acb77ddbeff16caf42` |

`DOGE` was re-attested from a live scan on 2026-09-16 (tx
`5012431be06a49f0bdc9b77e274aafaafabc6b30f6a5de535616050617ccd64c`,
`attested_at 1789546342`) so the fixed example gate could be observed refusing it
through the severity ceiling rather than as stale. The re-scan reproduced
`396c9f7c…91647e` exactly; the contract now stores the later timestamp. See
[deployment.md](deployment.md#the-26-fix-before-and-after).

`SHX` is worth a note: `auth_immutable` is set, so it carries mechanic bit
`1 << 3` while staying severity `0`. That is deliberate — locking the flag set
is not a power over holders, and here it is protective, because the issuer can
now never add freeze or clawback. Bits in the report are not all bad news, and
a gate refusing on any non-zero bitset would refuse this asset for being
permanently safe.

`EURC` repeats the `USDC` result exactly: Circle's euro stablecoin also fails
reciprocal SEP-1 verification, because `circle.com/.well-known/stellar.toml`
returns 404 for both. Two independent assets, same issuer domain, same honest
`unverified`.

### The blocklist did not flag either confirmed scam

Both `BERKSHIRE` and `DOGE` are tagged `malicious, unsafe` in the curated
directory. Both had their `home_domain` checked against the malicious-domain
blocklist, and both came back `blocked=false`:

```
$ curl -s https://api.stellar.expert/explorer/directory/blocked-domains/darkpool.digital
{"domain":"darkpool.digital","blocked":false}
```

So the escalation came entirely from the directory, in both cases. Consulting
only the blocklist would have missed two out of two known scams in this sample.
That is not a criticism of StellarExpert — the two data sets answer different
questions — but it is a concrete reason Assay consumes both, and a caution
against treating any single curated source as complete.

---

## Findings from this run

### Finding 1 — a source outage is reported as a clean result {#finding-1}

`internal/stellarexpert/client.go` correctly separates outcomes: HTTP 404 means
genuinely not listed and returns no error; 429, 5xx, and timeouts return an
error. `internal/scan/scan.go` then discards that error:

```go
if blocked, err := s.Expert.BlockedDomain(ctx, domain); err == nil { sub.Blocked = blocked }
if entry, err := s.Expert.Directory(ctx, a.Issuer); err == nil { sub.Directory = entry }
```

Both outcomes leave the field `nil`, and `check_reputation.go` then reports:

> "No curated reputation data was available for this issuer. **That is the
> normal case** and is not a positive signal."

That sentence is true on a 404 and false on a rate-limit. The report cannot tell
them apart, and neither can anything downstream — no field on the report records
that a source was unreachable.

**Why it matters.** `BERKSHIRE` above reaches `critical` *only* through
reputation; its capability severity is `high`, and `DOGE-GA22IDJN…` — a known
scam in the eval set — is `clear` on capability and `critical` only by
escalation. During a StellarExpert outage that asset scans `clear`, and the
resulting report passes the attestation invariant and is writable on-chain as
clear.

It contradicts this project's own published rule in
[docs/checks.md](checks.md): *"'We could not check' and 'this is fine' are
different answers and must never render the same."* Ledger data fails closed —
Horizon errors abort the scan — while reputation fails open and silent. That
asymmetry was not documented anywhere.

Per [CONTRIBUTING.md](../CONTRIBUTING.md), a way to make Assay under-report risk
is a security issue rather than a bug.

**Status: fixed.** Tracked as
[#23](https://github.com/use-assay/Assay/issues/23).

An unreachable source is now recorded as attributed evidence carrying the
failure verbatim, the finding is marked `undetermined`, the report names the
check on `undetermined_checks`, and `attest.FromReport` refuses to write a
partial scan on-chain.

Demonstrated rather than asserted — the scanner pointed at a dead StellarExpert
endpoint, everything else live:

```
$ # DOGE-GA22IDJN…, StellarExpert pointed at 127.0.0.1:1
severity      clear
undetermined  true [reputation]
attestable?   attest: scan is undetermined, so there is nothing to attest: reputation could not complete
```

Before the fix, that same scan produced `severity: clear` with "that is the
normal case" and was writable on-chain. Severity is deliberately still `clear`:
capability was fully readable and is reported as measured. What changed is that
the report says so and the attestation is refused.

This run's four assets are unaffected — all three sources answered for all four,
evidenced by the four evidence entries each report carries, and all four
on-chain hashes still reproduce after the change. But that was luck rather than
design: nothing in the output would have told us otherwise, which is the
finding.

### Finding 2 — the evidence hash is not reproducible across machines {#finding-2}

`evidence_hash` is documented as verifiable by re-scanning and recomputing. That
holds only when the evidence text is machine-independent, and it is not.

When a `stellar.toml` fetch fails, the raw Go transport error is recorded
verbatim and hashed. BERKSHIRE's preimage — one of the four already on-chain —
contains:

```
evidence	stellar.toml	https://nasdaq.finance/.well-known/stellar.toml	not retrievable: sep1: fetch https://nasdaq.finance/.well-known/stellar.toml: Get "https://nasdaq.finance/.well-known/stellar.toml": dial tcp: lookup nasdaq.finance on 10.255.255.254:53: no such host
```

`10.255.255.254` is **this machine's DNS resolver**. The on-chain hash
`dc2bbf08…171a0d` therefore commits to a local network detail. It reproduces
above only because the re-scan ran on the same host; a verifier anywhere else
gets different bytes, a different hash, and would reasonably conclude the
attestation does not match its evidence when nothing is wrong.

The same class of text — timeouts carrying resolved IPs, `context deadline
exceeded` versus a connection reset — makes any asset with an unreachable domain
non-reproducible. USDC is unaffected: a clean `status 404` is stable.

When this was written only BERKSHIRE was known to be affected. The 2026-09-17
audit below found **three of the ten** on-chain hashes commit to raw transport
text: BERKSHIRE, DOGE and KALE. A fourth, REPO, commits to a TOML parser error
about the remote file, which is stable only for as long as that file is
unchanged.

**Migration.** `assay-evidence-v1` attestations preserve the historical raw
transport text and are verifiable only with v1 rules. In particular, the
historical BERKSHIRE hash remains
`dc2bbf0849dfc001c44be9a5de4fe19c39300e5c4735c9ed3311b3d214171a0d`.
Operators must either retain the v1 preimage and verifier for that attestation,
or re-attest BERKSHIRE under v2 and record both hashes side by side. New v2
preimages use only closed canonical failure categories such as `dns-failure`,
`connection-refused`, `tls-failure`, `timeout`, and `status N`; raw transport
errors remain diagnostics and are excluded from the hash.

The committed vectors under `internal/attest/testdata/vectors/` include a v1
legacy profile and v2 profile bytes plus their SHA-256 digests. The version line
is part of each preimage, so a verifier must select the matching ruleset.

---

## Reproducibility audit, 2026-09-17

Every one of the ten on-chain attestations was checked three ways, from a
single machine, on 2026-09-17:

1. **An independent re-implementation of the documented encoding.** A short
   Python script built from `docs/contract-interface.md` alone, never reading
   the Go code, computed `evidence_hash` from each live scan's JSON report.
2. **The scanner's own output**, `assay attestation -raw`.
3. **What the registry stores**, read with `get_safety`.

For all ten, all three agreed on severity, flags and `evidence_hash`, and each
SAC address in [deployment.md](deployment.md) was re-derived and matched. So the
code, the documentation and the chain agree byte for byte, and the documented
encoding is complete enough to reimplement.

One gap in the documentation surfaced along the way. The JSON report gives
severity as a name and mechanics as a list of names, while the preimage wants
integers; a verifier has to join the encoding section to the ABI table to
convert them. Both are in the same document, but nothing says the join is
needed.

What did **not** go cleanly is worth more than the agreement:

| Asset | Hashed `stellar.toml` evidence | Exposure |
| --- | --- | --- |
| `BERKSHIRE` | DNS failure text naming this host's resolver | machine-dependent (#24) |
| `DOGE` | transport failure text | machine- and timing-dependent (#24) |
| `KALE` | transport failure text from `chainx.site` | machine- and timing-dependent (#24) |
| `REPO` | TOML parser error about the remote file | stable only while the site is unchanged |
| the other six | a claim, a stable HTTP status, or no toml line | reproducible |

- **Rapid scans fail transiently.** In one quick pass over all ten, three scans
  failed outright on Horizon or DNS errors, and one KALE scan came back
  `undetermined` because every reputation source timed out. All four
  reproduced on a slower retry. The undetermined KALE report would have hashed
  differently (`9595cc7d…`) — and `assay attestation` correctly refused to
  attest it. An independent verifier must do the same: never compare the hash of
  a report that has `undetermined: true`.
- **`circle.com` now redirects.** On 2026-09-17,
  `circle.com/.well-known/stellar.toml` answers 301 to `www.circle.com`, which
  returns 404. The scanner reports the 404 against the original URL, which is
  slightly misleading, but the recorded claim and USDC's hash are unchanged.

---

---

### Finding 3 — an unlisted address was reported as `listed as ""`

Surfaced by `USDGLO-GBBS25EG…`. StellarExpert's directory does not return 404
for an address it holds no entry for; it returns `200` with an empty object:

```
$ curl -s -w " [HTTP %{http_code}]" https://api.stellar.expert/explorer/directory/GBBS25EGYQPGEZCGCFBKG4OAGFXU6DSOQBGTHELLJT3HZXZJ34HWS6XV
{} [HTTP 200]
```

The client treated any `200` as a hit, so the reputation check published:

```
stellar.expert/directory: listed as "" (domain "", tags: )
```

A claim the directory never made, attributed to it by name and URL, and it
would have entered the `evidence_hash` preimage of any attestation built from
that scan.

Not a severity bug — an empty entry has no tags, so nothing escalated and no
risk was under-reported. The damage is to the evidence, which is the part a
reader is supposed to be able to check independently, and
[CONTRIBUTING.md](../CONTRIBUTING.md)'s first rule is never to display a value
that was not fetched.

**Status: fixed.** Tracked as
[#25](https://github.com/use-assay/Assay/issues/25). Confirmed against three
unlisted addresses before encoding the behaviour. The four earlier attestations
still reproduce their hashes; none had an empty entry.

### Finding 4 — the example gate admits a critical asset

This is the one the widened sample was for, and it is on a deployed contract.

`DOGE` is attested `severity 4`, `flags 48`. The registry answers correctly:

```
registry is_safe(DOGE, max_severity=2, max_age_secs=0)  ->  false
gate     would_admit(DOGE)                              ->  true
```

The example gate masks capability bits only —
`REFUSED_MECHANICS = auth_revocable | auth_clawback_enabled = 6` — and `48 & 6`
is `0`. It never reads `severity` at all, so it admits an asset a curated source
calls malicious.

The cause is structural rather than a slip. Reputation escalation raises
`severity` and sets `blocklisted`; it does not set a capability bit, and it must
not, because capability bits describe what an issuer *can do* and a scam listing
is not a capability. A mask over capability bits therefore cannot see escalation
by construction — which makes "gate on the bitset", the advice
[integrating.md](integrating.md) previously led with, actively unsafe as a
general rule. The correct rule is **bitset _and_ severity**.

`DOGE` also shows why this went unnoticed: it is the only asset in the sample
whose base severity and final severity differ by the whole scale, `0` to `4`.
Every other asset here has capability bits that a mask would catch anyway, so
the mask looked sufficient right up until an asset arrived whose severity came
from somewhere the mask cannot see.

**Status: fixed in source, redeploy pending.** Tracked as
[#26](https://github.com/use-assay/Assay/issues/26). The example gate's source
now carries a severity ceiling alongside the bitset mask, with two regression
tests (`critical_by_reputation_without_capability_bits_is_refused`,
`severity_above_ceiling_is_refused`) that would fail if the ceiling were
dropped. The guidance in [integrating.md](integrating.md) gates on both axes.
The **deployed instance still runs the pre-fix wasm** — a rebuild and redeploy
is its own change, and the doc states the live block shows the old behaviour
rather than quietly claiming the bug is gone.

### The fix from Finding 1 caught a real outage during this run

Not a finding, but the reason to record it: while re-verifying hashes mid-sweep,
one `BERKSHIRE` scan came back

```
attest: scan is undetermined, so there is nothing to attest: reputation could not complete
```

A genuine transient StellarExpert failure, caught and refused, during exactly
the kind of rapid multi-asset sweep [#23](https://github.com/use-assay/Assay/issues/23)
predicted would trigger it. The next attempt succeeded and reproduced the
on-chain hash. Before the fix, that scan would have returned `severity 3`
instead of `4` — silently dropping the escalation — and been attestable.

---

## Third tranche, 2026-09-16

The plan for this tranche (five assets, chosen for calibration) survives in the
notes below rather than being silently rewritten — several of its expectations
did not survive contact with the live network, and the reasons are the most
instructive material this run has produced.

| Asset | Issuer | Result | On-chain |
| --- | --- | --- | --- |
| `VELO` | `GDM4RQUQ…ARM2M5M` (`velo.org` per directory) | clear, accountability `unknown` — the first asset in the run with **no `home_domain` at all** | yes |
| `KALE` — kalepail.com issuer | `GAKJM27Q…VEWUNSYCEF` | clear, verified directory entry (`kalepail.com`), but the account advertises `chainx.site` — see below | yes |
| `KALE` — xlmcash.tech issuer | `GBEQXW5HH…2QYUXRP` | **critical by escalation, base clear** — directory tags it `malicious`, domain `xlmcash.tech` on the malicious-domain blocklist | no |
| `REPO` | `GA2BVQLG…O36EAZR` | **critical by escalation, base clear** — the *blocklist* contains `hiddenstellar.com`; the directory 404s for the issuer | yes |
| `yFLR` | `GAIUD5NP…ENQJYFLR` | **the scanner refused to produce a verdict** — see below | refused |

On-chain records (all three written 2026-09-16, spaced minutes apart):

| Asset | On-chain | `evidence_hash` | Attest tx |
| --- | --- | --- | --- |
| `VELO` | `severity 0`, `flags 16`, `attested_at 1789521172` (2026-09-16T01:12:52Z) | `3ed390fe…f49e02a` | `dcae1dd810f3e310e71e006f175857b12a8925e173e6d62d9f023ee91582e85b` |
| `REPO` | `severity 4`, `flags 48`, `attested_at 1789521267` (2026-09-16T01:14:27Z) | `4dacaa0f…69943cede` | `a6b5fa3058c3f7f25cbf45b22603f721de7767e4b853e644932e72215eb940e0` |
| `KALE` | `severity 0`, `flags 16`, `attested_at 1789521352` (2026-09-16T01:15:52Z) | `874087f2…220fdc6112` | `db36e5ece6c52d01287da2bdb9722affab84047d58ec21a332edd9d1e7392c90` |

### Where the tranche plan was wrong, and what that exposed

**The plan expected `yFLR` and `BRAID` to be clean assets. `BRAID` does not
exist on mainnet at all** — Horizon returns no records for the code. The plan
was written from a name list, not from the ledger, and one of its five rows
pointed at nothing. Recorded here rather than quietly dropped.

**`USDT` was dropped after discovery, and the discovery itself is the finding.**
There are **351 assets coded `USDT` on mainnet and not one of them is Tether**.
Tether is not in the curated directory under any tether-related name. The top
issuers by adoption carry no authorization flags and home domains like
`dead.apay.io`, `stellarstable.co`, `tether-stellar.com` — code-squatters, all
capability-`clear` by the letter of the model. The plan also carried an issuer
string for Tether (`GCZMWSOII4NBQCFQKEICHL5U6NI4MI4OGBQ7GID7EFN64GW5VYJBLBSP`)
that is **not a valid Stellar address at 55 characters** — the directory API
rejects it with 400. A wrong fact in a plan is exactly the kind of thing this
document exists to catch; this one was caught before it could become an
attestation, but only because the plan was re-derived from live sources first.

### The two-scam-codes tranche: reputation sources disagreeing about *which* source

The second tranche ended with "the blocklist did not flag either confirmed
scam — escalation came entirely from the directory." This tranche produced the
exact inverse, twice:

- **`REPO`**: the directory **404s** for `GA2BVQLG…` — no entry at all — but
  the malicious-domain **blocklist contains `hiddenstellar.com`**, the issuer's
  `home_domain`. Escalation came entirely from the blocklist.
- **`KALE` (xlmcash.tech issuer)**: the directory **does** tag it `malicious`
  (name "Scam"), and the blocklist independently contains `xlmcash.tech`. Both
  sources caught this one — the only asset in the run where the two agree.

So across the run: BERKSHIRE and DOGE were directory-only, REPO was
blocklist-only, this KALE was both. Neither source is individually complete in
*either direction*, and which one carries the signal is not predictable in
advance. That is now demonstrated on four assets rather than argued.

**`KALE` also exposed a two-domain issuer.** The clean kalepail.com issuer
(`GAKJM27Q…`) is listed in the directory under `kalepail.com` — but its
account's `home_domain` is `chainx.site`, a domain serving no readable toml.
The same entity is presenting different domains to different sources. This is
precisely the mismatch class [#4](https://github.com/use-assay/Assay/issues/4)
tracks (directory domain vs advertised domain) — this asset is its first live
specimen in the run. The scan still reports `clear`: capability is genuinely
empty, and the directory's claim is recorded as attributed evidence. Nothing
was bent to make the result cleaner than the evidence.

### A verdict Assay refused to produce

`yFLR`'s most-adopted issuer (`GAIUD5NP…`, 260 authorized accounts, directory
entry "SCAM-Counterfeiter") **has no issuer account on Horizon** — `/accounts/`
returns 404 while `/assets` still reports the supply. Horizon is telling two
stories about the same asset. The scanner **hard-refused**:

```
assay: horizon: not found: /accounts/GAIUD5NPLO2L6WWA7KLH4LIF54BBX24ELW3JSEINPVDRXZRIENQJYFLR
```

No severity, no report, nothing attestable. That is the invariant holding on a
case the run had never hit: a vanished issuer is not a `clear` verdict, and
nothing in the report path will invent one. It is also, unlike Finding 1, a
case where the refusal is the *entire* correct output — there is no partial
answer to salvage. Left unattested by construction.

### The `unknown` accountability branch finally exercised

`VELO`'s issuer advertises **no `home_domain` at all** — distinct from
`unverified` (a domain exists, reciprocal verification failed), and it had
never appeared in this run despite being a defined branch of the model. The
sample now covers all three accountability values end to end.

**Where a result felt borderline:** `KALE`'s two-domain issuer is the case this
tranche felt least comfortable publishing as `clear`. The two-domain mismatch
is not scored by any check — it lives only in the prose reasoning — and a
consumer reading only severity and flags would never see it. Publishing it as
`clear` with the mismatch documented is honest to the evidence; *not*
documenting it would not have been. That gap — structural signals visible to a
human reader but not to the severity number — is exactly what
[#4](https://github.com/use-assay/Assay/issues/4) is for, and this asset is now
its concrete motivating case.

---

## What this run does not establish

- **18 assets is not a measurement.** No precision or recall number is quoted,
  because 18 subjects cannot support one. For scale: even if every one of the 18
  were independently confirmed correctly classified, the rule of three would
  put the 95% upper bound on the error rate near 3/18, about 17% — and that bound
  would apply only to highly-rated assets like these, not to the network. The target is 20–25 and this document
  is not finished. This tranche also showed *how* the sample grows wrong: two of
  the planned subjects (BRAID, USDT) did not survive contact with the ledger —
  see [the third tranche](#third-tranche-2026-09-16). The next tranche verifies
  each subject against live sources before the plan is written, not after.
- **The sample is not random.** It was drawn from StellarExpert's top 50 by
  rating, plus two known scams carried over from the eval set. Highly-rated
  assets are not representative of the network: a random sample would be
  dominated by tiny, unlisted, recently-created assets, which is where a
  scanner's judgment is hardest and where this sample says nothing.
- **Nothing here measures false negatives.** Every asset in the table was
  classified from flags that are consensus-enforced facts, so the capability
  half is hard to get wrong. What is not measured is what Assay *fails to
  notice* — an abusive issuer with no flags and no curated listing is `clear`
  here and would be, correctly and uselessly, until someone reports it.
- **No independent verification of any issuer's identity.** A verified
  `stellar.toml` and a directory listing are claims by others, recorded as
  attributed evidence. Assay has not confirmed that any issuer here is the
  entity it appears to be. This matters most for the clawback-capable assets,
  where "legitimate regulated issuer" is the reading a reader will reach for and
  is precisely what has not been established — see
  [#16](https://github.com/use-assay/Assay/issues/16).
- **The eval set is unchanged at five subjects.** These scans are live and
  drift with the ledger; a fixture pins judgment. Attesting an asset is not
  labelling it.
- **Testnet.** One key can write any attestation; testnet resets and Soroban TTL
  expiry will remove these entries.
- **Attested 2026-08-15, 2026-09-05 and 2026-09-16** (AQUA and DOGE re-attested
  on 2026-09-16). Issuers can change flags at any time.
  These attestations are exactly as fresh as their `attested_at`, and nothing
  refreshes them on a schedule.
- **Four findings in the first 13 assets.** Two are fixed, one is fixed in
  source, redeployed on 2026-09-16, and merged in
  [PR #27](https://github.com/use-assay/Assay/pull/27) on 2026-09-17; one is
  deferred with a version bump behind it. The next five subjects produced no new findings in the scanner itself —
  but three failures of the *plan*, one refused verdict, and the first live
  specimen of a known gap (#4). A quiet tranche is not automatically a
  reassuring one.
- **Why the sample stopped at 18, not 20–25.** The 2026-09-17 session was an
  audit, and it decided not to add assets. Two to seven more assets from the
  same top-50 population would move the count without improving what the
  sample can support, and that day's network was producing transient and
  undetermined scans. The more useful next evidence is a differently drawn
  sample — recently created, unlisted assets, where judgment is hardest — not a
  bigger version of this one. Until then, 18 is the sample, and the statements
  above are what it supports.
