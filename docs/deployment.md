# Deployment

The Assay safety registry is deployed on **Stellar testnet**. It is not on
pubnet, and nothing here should be read as a claim that it is ready to be.

## Live addresses

| | |
| --- | --- |
| **Registry contract** | `CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73` |
| Network | Testnet (`Test SDF Network ; September 2015`) |
| Deployed | 2026-08-15 |
| Wasm hash | `c4105b91b3ceae95b5a225c55bc6981b3dcf71d07fdd0ee5c79a21d25edd301b` |
| Source | [`contracts/safety-registry`](../assay-contracts/contracts/safety-registry) |
| Admin / attester | `GALIEUOBDLTFJHTVH5E3MT2BMDTQ3PKMX2U6BRXVKLEB7ARFORFNNMVY` |
| Built with | `stellar` CLI 27.1.0, `soroban-sdk` 27.0.5, `rustc` 1.98.1 (pinned) |

The contracts' Rust toolchain is pinned to `rustc` 1.98.1 in
[`assay-contracts/rust-toolchain.toml`](../assay-contracts/rust-toolchain.toml),
so CI and local builds agree on the compiler and a toolchain upgrade is a
deliberate commit rather than whatever `stable` happens to be. Rebuilds should
be produced with it.

The worked integration example from [integrating.md](integrating.md) is
deployed alongside it, wired to the registry above:

| | |
| --- | --- |
| **Example gate contract** | `CAL5VYSWLKG367D5IYGI57XH7EMN5PLJ4CD6K3MO2HJBYYKEKPG3NKRX` |
| Wasm hash | `ca40172ec8ebc259e7e21429748b2bd7cafe467fa3005d849d81d16938e8987c` |
| Redeployed | 2026-09-16 — severity ceiling, [#26](https://github.com/use-assay/Assay/issues/26) |
| Source | [`contracts/example-gate`](../assay-contracts/contracts/example-gate) |

### Deployment transactions

| Step | Transaction |
| --- | --- |
| Upload registry wasm | `2c6b1e695fbaafa2c5134c6b57a0654371a8d9d7e90d70f3f85404a7709d53f1` |
| Deploy registry | `ff11e24ff1d9ccd4aeea4dc258ce17d49a7b0d0c529a326f7eda9d6eff2f1c9c` |
| `init(admin)` | `14082d78211ad494406c14d6f0bd2993a88008cb4091457a7685b3794d20ee09` |
| Upload gate wasm (original) | `2dc8387ff2a4ef2a24f788de627f566dfc6d60d96806f7ebffb529324056233e` |
| Deploy gate (original, **superseded** — admits DOGE) | `a6c4f642af24f32ec116a8a8918153cacafb86f9ac33c73dfb942dce73d5897f` |
| Upload gate wasm (redeploy) | `943c90b5d710499aa489b4ccb0c257447efb049859ef4401e10dc4e316e6d832` |
| Deploy gate (redeploy, #26 fix) | `2137605713924608aa801c560a9121534efd330201e6e174a33da51190e7bfa4` |
| Deploy gate (duplicate, unused) | `5fde49952a83f1acbe5b04a302302e0449f3348a49105d67babb8d1a5418b6c6` |

The last row is a mistake, recorded rather than hidden. Two working sessions
redeployed the same fixed wasm six minutes apart, so a second instance exists at
`CCMA2SW23WUWTJGSC2MTUZVYWROMVTT42NLPTBCOAHGM632KEMNL5N3G`, bound to the same
registry and running the same wasm (`ca40172e…`; it reused the upload above).
Soroban contracts cannot be deleted. It behaves identically and nothing refers
to it; `CAL5VYSW…` is the canonical instance.

Any of these can be read at
`https://stellar.expert/explorer/testnet/tx/<hash>`.

### Example gate instances

Three instances exist on testnet and none can be removed. Only one should be
used. Checked on 2026-09-17 by fetching each contract's wasm and hashing it, and
by reading the constructor argument from each deploy transaction:

| Instance | Status | Wasm | Registry at construction |
| --- | --- | --- | --- |
| `CAL5VYSWLKG367D5IYGI57XH7EMN5PLJ4CD6K3MO2HJBYYKEKPG3NKRX` | **canonical** — use this | `ca40172e…` (severity ceiling) | `CBK4FBIH…` |
| `CCMA2SW23WUWTJGSC2MTUZVYWROMVTT42NLPTBCOAHGM632KEMNL5N3G` | duplicate, **unused** — nothing in the repo refers to it | `ca40172e…` (identical) | `CBK4FBIH…` |
| `CANO57JRGTATHGLM26TWYPIXERSPVI5R52H33K7ZUJGGOEOVVZA44W3U` | **superseded, do not use** — admits critical-by-reputation assets ([#26](https://github.com/use-assay/Assay/issues/26)) | `d1683a1e…` (capability mask only) | `CBK4FBIH…` |

## Does the source still build what is deployed?

**Short answer: it cannot be verified today, and the reason is
[#127](https://github.com/use-assay/Assay/issues/127), not the source.** The
build is deterministic; the compiler is not pinned, so "the committed source"
does not determine the bytes. What follows is the measurement rather than a
conclusion drawn from one.

The `Wasm hash` rows above are a record of what was deployed. Whether the
source in this repository still produces them is a separate claim, and until
it is checked they are an unverified record.

### What was measured

Three builds of `assay-safety-registry` from the same commit, each after
`cargo clean`, the third from a different checkout path with a cold cargo
cache:

| Build | Toolchain | `sha256sum` of the built wasm |
| --- | --- | --- |
| recorded 2026-08-15 | stellar 27.1.0, rustc unknown (never recorded) | `c4105b91b3ceae95b5a225c55bc6981b3dcf71d07fdd0ee5c79a21d25edd301b` |
| measured, same checkout | stellar 27.1.0, rustc 1.98.1 | `60d482546df4d1973f7d4b5d9ff5b413a974ba16afea1cf4851fe32fe0d6e745` |
| measured, other checkout path | stellar 27.1.0, rustc 1.98.1 | `60d482546df4d1973f7d4b5d9ff5b413a974ba16afea1cf4851fe32fe0d6e745` |
| measured, different compiler | stellar 27.1.0, **rustc 1.95.0** | `12dbf6b9d29c2d1109523007b82392b91f232ca16cd1a2a8394b90d6c54425f6` |

Two things follow, and they are separate findings.

**The build is deterministic.** The same source under the same toolchain
produces byte-identical wasm every time, including from a different checkout
path with no build cache. Whatever the CLI and the compiler embed in the
output, it is not a timestamp, a path, or anything else that varies between
runs.

**The compiler version alone changes the bytes.** Identical source, identical
`Cargo.lock`, identical `stellar` CLI 27.1.0, identical target — rustc 1.98.1
and rustc 1.95.0 produce two different hashes. So byte-reproducibility across
machines is not a property this repository currently has, and cannot have
until the channel is fixed. `assay-contracts/rust-toolchain.toml` does not
exist; `rustup` selects whatever channel is installed, so two people running
`make build-contract` are running two different builds.

Neither measured hash equals the recorded one. **That is not evidence that the
source has drifted.** It is the expected consequence of an unpinned toolchain,
and it cuts both ways: today nobody can produce the recorded hash, and equally
nobody can rule out that they would. Until #127 lands, the recorded hashes
cannot be confirmed or refuted by anyone, and a matching hash found by
accident would be luck rather than verification.

For the gate the same holds: recorded `ca40172ec8ebc259e7e21429748b2bd7cafe467fa3005d849d81d16938e8987c`,
built here `9bd4a4b6a5e71e6c201eb633218c65dfb5dc0209dac6a0d5471b0228a4200a00`.

### Checking it

```sh
make verify-wasm          # or: scripts/verify-wasm-source.sh
```

The script builds each contract from the committed source and compares the
result to the hashes in this file. It builds into a temporary directory, so it
never disturbs `assay-contracts/out/` or the artifact a deploy would upload,
and it never edits this document, changes a recorded hash, or submits a
transaction. It reports one of four outcomes per contract and exits 0 only
when every recorded hash is reproduced:

| Outcome | Meaning | Exit |
| --- | --- | --- |
| `verified` | The fresh build hashes to the recorded value. | 0 |
| `mismatch` | It does not. Both values are printed, and it is never tolerated. | 1 |
| `unpinned` | `rust-toolchain.toml` is missing, so the build cannot be compared. | 2 |
| `unverifiable` | The `stellar` CLI is missing or is not the recorded 27.1.0, or the build failed. | 2 |

Exit 2 never means "verified" and never means "safe" — it means the run could
not answer the question, so a run with any `unpinned` or `unverifiable`
contract never exits 0. **Today it exits 2, and that is the correct answer.**
The moment #127 adds the pin this becomes the check it was written to be; the
`unpinned` branch is not a workaround, it is the absence of a verdict.

### What the recorded hashes are valid against

| Component | Recorded | Confidence |
| --- | --- | --- |
| `stellar` CLI | 27.1.0 | Recorded and reproducible |
| Rust target | `wasm32v1-none` | Recorded and reproducible |
| `soroban-sdk` | 27.0.5 | Recorded; pinned by `Cargo.lock` |
| Rust compiler | **not recorded** | **Unpinned — see #127** |

The compiler row is the gap. One constraint worth recording for whoever
closes #127: `soroban-sdk` 27.0.5 requires rustc 1.91.0 or newer, while
`stellar` CLI 27.1.0 rejects anything outside 1.81, 1.82, 1.83 and 1.91.0 — and
rejects 1.91.0 itself, so 1.90.0 and 1.91.0 both fail, one for being too old
and one for the CLI's version check. A pin has to be a channel the CLI
accepts, not merely one the SDK allows.

### What this does not check

The deployed bytes and this repository's source being *correct* is a
different question, and is not answered here. Nor does it check that the
registry still holds the attestations this document records — that is
`scripts/check-deployment.sh`, which compares the document against the chain
rather than against this repository.

## Attested assets

Ten mainnet assets, spanning the severity range. Every number below was
produced by `assay attestation` from a live scan and submitted unmodified by
`make attest`; none was typed by hand. The full scan record, including the
eight further assets scanned but not attested, is in
[attestation-run.md](attestation-run.md).

| Asset | Severity | Flags | Mechanics | Attest transaction |
| --- | --- | --- | --- | --- |
| `AQUA` | 0 clear | `0` | — | `1b6bafc1226570b2415299f5531256716f4d8dc489a9784fcd6ea347d0f63f5f` |
| `USDC` | 2 medium | `18` | `auth_revocable`, `domain_unverified` | `9869957e510ac6cb9ba4e5ffaff66ad0286e420e824efc0095d9e578be37564e` |
| `USDZ` | 3 high | `6` | `auth_revocable`, `auth_clawback_enabled` | `069d519fa20c472bbc3756291307fb30719219903c1e62a27b4967c0b07ecfd6` |
| `BERKSHIRE` | 4 critical | `54` | `auth_revocable`, `auth_clawback_enabled`, `domain_unverified`, `blocklisted` | `322f4bb5fcc84cea9231b7d12e0a964a304a7bd4ea78f97991ca335426e5e2ff` |
| `ARST` | 0 clear | `0` | — | `f497b91ab84340bcb7418940e620d080c8566e0cdf27346c8d74e165b5d66506` |
| `USDGLO` | 3 high | `6` | `auth_revocable`, `auth_clawback_enabled` | `6016ed7d908cd20237f114b0cb6778886027ddc8336952acb77ddbeff16caf42` |
| `DOGE` | 4 critical | `48` | `domain_unverified`, `blocklisted` | `ac1a89a64159e6ac2e9ed61bd67a79cd1584287cf57d19f9dc188d80e81298a6` |
| `VELO` | 0 clear | `16` | `domain_unverified` | `dcae1dd810f3e310e71e006f175857b12a8925e173e6d62d9f023ee91582e85b` |
| `REPO` | 4 critical | `48` | `domain_unverified`, `blocklisted` | `a6b5fa3058c3f7f25cbf45b22603f721de7767e4b853e644932e72215eb940e0` |
| `KALE` | 0 clear | `16` | `domain_unverified` | `db36e5ece6c52d01287da2bdb9722affab84047d58ec21a332edd9d1e7392c90` |

Issuers, SAC addresses, and the evidence hash each attestation commits to:

| Asset | Issuer | Testnet SAC address | `evidence_hash` |
| --- | --- | --- | --- |
| `AQUA` | `GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA` | `CDJF2JQINO7WRFXB2AAHLONFDPPI4M3W2UM5THGQQ7JMJDIEJYC4CMPG` | `688453bd…61a4a9` |
| `USDC` | `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN` | `CA2E53VHFZ6YSWQIEIPBXJQGT6VW3VKWWZO555XKRQXYJ63GEBJJGHY7` | `e7fc765d…d790bd` |
| `USDZ` | `GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR` | `CAOM5NKBTSGEXTZZKH3STWSFWURMODC3TZ4NS2THN7W5YUDFK3IOHIHU` | `ca9b13a6…65fb4d` |
| `BERKSHIRE` | `GA22QHSHQEHDJS2ZOINSC77XPPQ24G5EFRJGVEIZLKC5FAW3PQ5XNSDQ` | `CALAZXOC32XF2DFRKDOFQK7XQETZZTUK7C2OKC6YKPX6KY2YWU2YSPQW` | `dc2bbf08…171a0d` |
| `ARST` | `GCSAZVWXZKWS4XS223M5F54H2B6XPIIXZZGP7KEAIU6YSL5HDRGCI3DG` | `CBARCMJYRRNSYCWCR3EU2PEHAHWHBCQSMIKQIUSDWR3BK7CBCP622Q2R` | `82a6103f…fccacb` |
| `USDGLO` | `GBBS25EGYQPGEZCGCFBKG4OAGFXU6DSOQBGTHELLJT3HZXZJ34HWS6XV` | `CDGBOKCE25PVUKFWST2EEK52NHRS5WQ7TN26DFJYCEQNZNROQRSPIBQA` | `69b8c4f8…7c27a5` |
| `DOGE` | `GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P` | `CDUV37BUTYKKWNGECZZNRYMM7JIQYYWAI7L2TPTXWQAEMIPG4SXRBRPD` | `396c9f7c…91647e` |
| `VELO` | `GDM4RQUQQUVSKQA7S6EM7XBZP3FCGH4Q7CL6TABQ7B2BEJ5ERARM2M5M` | `CDHI6B6HBY2Q7BVGQ74C23GN3TKPGLCCMOSSRTEQDTTX4ELO5V6A6IOM` | `3ed390fe…49e02a` |
| `REPO` | `GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR` | `CBLZSCLVU3ZXRUJ3GEL7R3IP6CSN6VUEWPX7O4OYS3F3BYFUCJR7EEAA` | `4dacaa0f…43cede` |
| `KALE` | `GAKJM27QTNLBBZ352HQ4IDR3GWXUXQUEBKBDWOJG7RBH2NVEWUNSYCEF` | `CCVNR6CGD6NFQG7XC6AVU5HF4YAPVXW5KZJCD73XFKUUO4YZUNEFKU2Z` | `874087f2…dc6112` |

`USDZ` is the case the [severity model](severity-model.md) exists to handle: a
confiscation-capable issuer with a *verified* domain. It scores `high` on
capability anyway, because a verified domain does not weaken clawback — it only
names who holds it. `BERKSHIRE` is the escalation case: capability alone puts it
at `high`, and StellarExpert's blocklisting of `nasdaq.finance` raises it to
`critical`. Reputation moved it up; nothing in the pipeline can move an asset
down.

`DOGE` is the same escalation shown at its extreme, and is the more instructive
of the two: base severity `0`, final severity `4`. Its issuer holds no
authorization flags at all, so capability analysis honestly returns `clear` for
an asset the curated directory tags `malicious`. Everything separating it from
a harmless asset lives on the reputation axis.

### The assets are mainnet; the attestations are testnet

These assets live on pubnet. Their **testnet** SAC addresses are what the
registry is keyed on here, because a contract ID is derived from the network
passphrase and so differs per network. Scanning reads pubnet, where the assets
actually are; attesting writes to testnet, where the contract actually is. A
pubnet deployment would key the same assets under their pubnet SAC addresses.

## Reproducing the round trip

Scanner output and on-chain state, read back after the fact:

```
$ ./assay attestation -raw USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
3	6	ca9b13a66f3a0a4b43d66dea29a505658447e08eee200d2bdb5e66aa1065fb4d

$ make read ASSET=USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
{"attested_at":1786771651,"evidence_hash":"ca9b13a66f3a0a4b43d66dea29a505658447e08eee200d2bdb5e66aa1065fb4d","flags":6,"severity":3}
```

The severity, the bitset, and the evidence hash match, and the hash was
recomputed from a *fresh* scan after the write — which is the point of leaving
retrieval timestamps out of the preimage. A verifier who re-scans an asset whose
sources have not changed reproduces the on-chain hash exactly. If it does not
reproduce, either the asset changed or the attestation is not what it claims.

`attested_at` is the ledger timestamp of the write: `1786771651` is
2026-08-15T05:27:31Z.

## Fail-closed, verified live

Checked against the deployed contract before any attestation existed
(2026-08-15), again that day afterwards, and again on 2026-09-17, using `native` XLM as a control asset that is deliberately never
attested (SAC `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC`):

| Call | Result |
| --- | --- |
| `get_safety(unattested)` | `null` |
| `is_safe(unattested, max_severity=4, max_age_secs=0)` | `false` |
| `is_safe(unattested, max_severity=0, max_age_secs=0)` | `false` |

The middle row is the one that matters: severity 4 is the maximum and age 0
disables the freshness check, so those are the most permissive arguments the
gate accepts. It still returns `false`, because there is nothing to admit. An
unknown asset is unknown, not safe.

`is_safe` across the attested set, read live (2026-08-15; re-read 2026-09-17 with
identical results — `max_age_secs=0` disables freshness, so these do not expire):

| Asset | `max_severity=0` | `max_severity=2` |
| --- | --- | --- |
| `AQUA` (0) | `true` | `true` |
| `USDC` (2) | `false` | `true` |
| `USDZ` (3) | `false` | `false` |
| `BERKSHIRE` (4) | `false` | `false` |
| unattested | `false` | `false` |

And through the deployed example gate, which is a real cross-contract call
rather than a direct read. The gate was redeployed on 2026-09-16 with the
severity ceiling that [#26](https://github.com/use-assay/Assay/issues/26)
tracked (deploy tx `21376057…7bfa4`); the results below are against the new
instance. Assets whose attestations are older than the gate's 24-hour window
are refused as stale, which exercises that branch live as well:

| Asset | `would_admit` | `deposit` |
| --- | --- | --- |
| `KALE` (clear, attested 2026-09-16) | `true` | succeeded, balance credited (`e3d2825c8e5a6615236904643873f0f325329c8a112ae338272a34abeab2f592`) |
| `AQUA` (clear, re-attested 2026-09-16) | `true` | succeeded, balance credited (`2cb3ce286c6f0874af9e8c86948c2cafad5ef4ef64edf055997595266d3da33f`) |
| `REPO` (critical, attested 2026-09-16) | `false` | `Error(Contract, #4)` — `SeverityTooHigh` |
| `DOGE` (critical by reputation, re-attested 2026-09-16) | `false` | `Error(Contract, #4)` — `SeverityTooHigh` |
| `USDZ` (clawback, attested 2026-08-15) | `false` | `Error(Contract, #2)` — `AttestationStale` |
| unattested (`native`) | `false` | `Error(Contract, #1)` — `NotAttested` |

Refusals fail at simulation, so no transaction is submitted for them; the admit
path is proven with submitted deposits whose balances read back. Every row
depends on the gate's 24-hour freshness window, so these results were observed
on 2026-09-16 and will not reproduce unchanged a day later without
re-attestation.

### The #26 fix, before and after

The first run of this table found `DOGE` and `AQUA` refused as stale
(`#2`), because their attestations predated the freshness window — which
refused `DOGE` for the wrong reason and left the fix itself unobserved on the
asset that exposed the bug. So both were re-attested from live scans, and the old
and new instances were queried against the same fresh attestations:

| Re-attestation | Transaction | `attested_at` | `evidence_hash` |
| --- | --- | --- | --- |
| `DOGE` | `5012431be06a49f0bdc9b77e274aafaafabc6b30f6a5de535616050617ccd64c` | `1789546342` | `396c9f7c…91647e` (unchanged) |
| `AQUA` | `595f89b53c897f583132e302ea6f78f1c334ce819423a27c5dd7981174fe39e7` | `1789546357` | `688453bd…61a4a9` (unchanged) |

Both hashes are byte-identical to the original attestations, so the refresh
changed only `attested_at` — the reproducibility property holding over a month
for `AQUA`.

| Gate | `AQUA` | `DOGE` |
| --- | --- | --- |
| Old, `CANO57JR…` (capability mask only) | admitted | **admitted** — the bug |
| Fixed, `CAL5VYSW…` (mask + severity ceiling) | admitted | **refused, `#4` `SeverityTooHigh`** |

The old instance admitted `DOGE` because it masked capability bits only, and
DOGE's severity `4` comes entirely from reputation, which sets no capability bit.
The old instance is still deployed — contracts cannot be removed — and nothing in
these docs points to it any more.

## Entry lifetime

Soroban persistent entries have a time-to-live measured in ledgers. When it
runs out the entry is **archived**. What that means for Assay was checked
against testnet rather than assumed, because the parameters are network
configuration set by validator vote.

### The network parameters

Read on 2026-09-27 with `stellar network settings --network testnet`
(protocol 28):

| Setting | Ledgers | At ~5 s per ledger |
| --- | --- | --- |
| `min_persistent_ttl` (what a fresh write gets) | 120 960 | ~7 days |
| `max_entry_ttl` (the most an extension can grant) | 3 110 400 | ~180 days |

### The live registry is already archived

`getLedgerEntries` for five of the attestations (`USDZ`, `USDC`, `KALE`,
`AQUA`, `DOGE`) at ledger 4 900 421 returned each entry with
`liveUntilLedgerSeq: 0`. Their last writes were at ledgers 4 150 015 to
4 704 554, so each one's minimum TTL ran out long ago. Simulating a read showed
more than that: the **contract instance and the contract code are archived
too**. The simulated footprint lists all three under `archived_soroban_entries`.
The deployed contract predates any TTL handling, so nothing ever extended any
of it.

### What a read of an archived entry actually does

The obvious guess is that an archived attestation reads as `None` and gates
fail closed. **That is not what happens.** Since protocol 23 an archived
persistent entry is restored automatically when a transaction's footprint marks
it for restoration, and simulation adds that marking by itself:

```
$ stellar contract invoke --id CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73 \
    --source-account <any> --network testnet --send=no \
    -- get_safety --asset CAOM5NKBTSGEXTZZKH3STWSFWURMODC3TZ4NS2THN7W5YUDFK3IOHIHU
{"attested_at":1786771651,"evidence_hash":"ca9b13a6…65fb4d","flags":6,"severity":3}

$ … -- is_safe --asset CAOM5NKB… --max_severity 4 --max_age_secs 0
true

$ … -- get_safety --asset CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC   # native, never attested
null
```

That is USDZ, archived, returned with its original `attested_at` from
2026-08-15. The simulated read carried a minimum resource fee of 11 589 615
stroops (about 1.16 XLM), which is the price of restoring the entry, the
instance and the code. The SDK 27 test host behaves the same way, and
`read_after_archival_returns_original_attestation` in the contract tests pins
it.

So, for a consumer:

- **Archived is distinguishable from never attested.** Archived restores to
  the stored attestation; never attested is `None`. (Revoked is `None`, the
  same as never attested; see
  [contract-interface.md](contract-interface.md#revoke-withdrawing-an-attestation).)
- **Archival is not expiry.** It never makes an attestation vanish, and it
  never makes one read as fresh either: the original `attested_at` survives.
  What protects a gate from a months-old attestation is `max_age_secs`. A
  caller passing `max_age_secs = 0` is served the restored attestation as-is.
- **Somebody pays to restore it.** The first transaction that touches an
  archived entry pays the restore fee. Reading an archived attestation from
  inside a gate makes that gate's user pay it.
- **Not verified live:** a transaction submitted with a hand-built footprint
  that lists an archived entry read-only, without marking it for restoration,
  should fail rather than read. That follows from the protocol rules but was
  not exercised against testnet here.

### The policy: extend on write, never on read

From this change onward the contract extends TTLs itself:

| Call | Extends |
| --- | --- |
| `init` | contract instance and code, to the network maximum |
| `attest` | the attestation entry, plus the instance and code, to the network maximum |
| `attest_many` | every attestation entry in the batch, plus the instance and code, to the network maximum |
| `revoke` | the instance and code (the entry is removed, so it has no TTL) |
| `get_safety`, `is_safe`, `is_safe_masked` | nothing |

The maximum comes from the host (`env.storage().max_ttl()`), not from a
constant in the contract, so a change in network parameters needs no redeploy.

Why writes only:

- **Retention follows the writer.** Keeping an attestation live is the
  attester's decision, made by re-attesting. With extend-on-read, a popular
  asset's attestation would be kept alive by the gates reading it, whether or
  not anyone still stands behind it.
- **Gates stay cheap and read-only.** A TTL extension in a read path charges
  every consumer rent and adds a ledger write to what is otherwise a read.
- **No maintenance entrypoint is needed.** Anyone can extend or restore any
  entry with the standard operations (`stellar contract extend`,
  `stellar contract restore`). A contract entrypoint would add authorization
  surface and do nothing those operations cannot.

### What happens as an entry ages

With this policy, an attestation written or refreshed today:

1. **Days 0 to ~180:** live. It reads normally. Whether a gate accepts it is
   the gate's `max_age_secs` call, per [freshness.md](freshness.md). Every
   recommended window there is 30 days or less, so for every gating use an
   attestation is stale long before it is archived.
2. **After ~180 days without a re-attestation:** archived. The next read
   restores it, at the reader's cost, and it reads with its original
   `attested_at`. Any gate with a window under 180 days refuses it as stale.
3. **Re-attesting** at any point pushes the TTL back out to the maximum. The
   `reattest_renews_ttl` test pins that.

Keeping entries live is therefore a by-product of keeping them fresh. The
schedule that does that is the re-attestation loop designed in
[attestation-writer.md](attestation-writer.md), with the cadence set in
[freshness.md](freshness.md). This document does not define a second schedule.
An asset dropped from that loop simply ages through the steps above. To make
an attestation unreadable on purpose, `revoke` it. Do not wait for archival,
because archival does not do that.

To inspect or extend one entry by hand:

```sh
KEY=$(echo '{"vec":[{"symbol":"Safety"},{"address":"<SAC>"}]}' | stellar xdr encode --type ScVal)
stellar contract extend --id <CONTRACT_ID> --key-xdr "$KEY" --durability persistent \
  --ledgers-to-extend 3110399 --source-account assay-attester --network testnet
```

## Checking for drift

The tables in this file are the record of what is deployed, and they have
drifted before: the docs named a superseded gate after the redeploy, and an
unexplained duplicate instance existed before anything recorded it. Drift is
silent, because a stale table reads exactly like a correct one.

`scripts/check-deployment.sh` reads these tables and the network, and reports
the difference:

```sh
scripts/check-deployment.sh                          # public testnet endpoint
scripts/check-deployment.sh --rpc https://… --timeout 30
ASSAY_RPC_URL=https://… ASSAY_RPC_TIMEOUT=30 scripts/check-deployment.sh
scripts/check-deployment.sh --deployment /tmp/copy.md   # a copy, not this file
```

It checks the registry and gate addresses, the wasm hash of the registry and of
all three gate instances, the registry each gate was constructed with, and the
severity, flags and evidence hash of all ten attestations — 21 checks. Chain
state is read with one `getLedgerEntries` call, as in
[Entry lifetime](#entry-lifetime) above, so it needs no `stellar` CLI and no
transaction: restoring an archived entry is what a transaction would do, and
reading what is documented does not require it.

Every check gets one of four outcomes, and only the first is a pass:

| Outcome | Meaning |
| --- | --- |
| `valid` | The documented value matches chain state. |
| `invalid` | A mismatch, reported with **both** values. For an address, "no contract at this address" is the on-chain value. |
| `absent` | A documented attestation with no entry on chain — the expected outcome for an archived or withdrawn attestation. Distinct from a mismatch, and never a match. |
| `unknown` | The RPC was unreachable, timed out, or answered with an error. Inconclusive by definition: neither a match nor a mismatch, and never a pass. |

Exit codes follow `scripts/reproducibility.sh`: **0** if every check is valid,
**1** if any is `invalid` or `absent` (drift, named, with both values), and
**2** if no drift was found but at least one check is `unknown`, or the tables
could not be parsed. Exit 2 never means "no drift" — it means the run could not
answer the question, so a run with any `unknown` never exits 0. When drift and
an `unknown` occur together the run exits 1 and reports the unknowns too: the
finding is the more important information.

The script only reads. It never edits this file and never submits a
transaction; fixing drift is a decision for whoever owns the deployment.

[`.github/workflows/check-deployment.yml`](../.github/workflows/check-deployment.yml)
runs it weekly and on demand. It is deliberately not on the PR path, for the
reason given in [CONTRIBUTING.md](../CONTRIBUTING.md#the-reproducibility-job): a
change that touches no deployment state would fail here for reasons unrelated
to itself.

**This checks the document against the chain, not the chain against the
source.** Whether the recorded wasm hashes come from the code in this
repository is [#93](https://github.com/use-assay/Assay/issues/93), which is
still open and needs a reproducible build rather than a ledger read.

## Redeploying

A rebuilt wasm only reproduces the recorded hashes if it comes from the same
toolchain. [CONTRIBUTING.md](../CONTRIBUTING.md#contract-toolchain) names the
`stellar` CLI version, the Rust target and the `soroban-sdk` version, and gives
the command that verifies them before you build.

```sh
make build-contract          # stellar contract build -> assay-contracts/out/
make deploy-testnet          # upload + deploy, prints the new contract ID
stellar contract invoke --id <NEW_ID> --source-account assay-attester \
  --network testnet -- init --admin $(stellar keys address assay-attester)
```

Then update `CONTRACT_ID` in the [Makefile](../Makefile) and the addresses in
this file. `init` is single-shot; a second call fails with
`AlreadyInitialized`.

### Migrating to a registry with `revoke`

`revoke` and TTL-on-write ship in new contract code, and the registry at
`CBK4FBIH…` has no upgrade entrypoint, so it cannot pick them up. Moving to
them means a new deployment. **Not done in the change that introduced them.**
The live addresses above are still the old registry until someone with the
`assay-attester` key does this:

1. `make deploy-testnet`, then `init` the new ID as shown above.
2. Re-attest the ten assets from live scans with `make attest`. Attestations
   cannot be copied across: the new contract has no import path, and re-scanning
   is the only way to write them with a truthful `attested_at`.
3. Redeploy the example gate with the new registry address as its constructor
   argument. It binds the registry address at construction.
4. Update `CONTRACT_ID` in the [Makefile](../Makefile), the tables in this
   file, [integrating.md](integrating.md) and
   [contract-interface.md](contract-interface.md).
5. Leave the old registry in place and mark it superseded here, as was done for
   the old gate instances. Contracts cannot be deleted, and anyone still
   pointed at it keeps reading its archived attestations, restored on access.

Attesting and reading, once deployed:

```sh
make attest ASSET=AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA
make read   ASSET=AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA
```

`make attest` scans the asset live, derives the arguments with
`assay attestation`, and submits them. There is no path through it that lets a
hand-written severity reach the contract.

## Admin Transfer and Rotation

Admin authority can be rotated using a two-step process (`transfer_admin` followed by `accept_admin`).
Two-step transfer prevents accidental transfer to an unowned address or typo:

1. **Initiate Transfer** (Current Admin):
   ```sh
   stellar contract invoke --id <CONTRACT_ID> --source-account <CURRENT_ADMIN_KEY> \
     --network testnet -- transfer_admin --new_admin <NEW_ADMIN_ADDRESS>
   ```
2. **Accept Transfer** (New Admin):
   ```sh
   stellar contract invoke --id <CONTRACT_ID> --source-account <NEW_ADMIN_KEY> \
     --network testnet -- accept_admin
   ```

After `accept_admin` succeeds, `new_admin` becomes the sole authorized attester and the old admin key loses all write permissions.

> [!NOTE]
> Redeploying contract code: Adding `transfer_admin` and `accept_admin` requires redeploying the registry contract on testnet because Soroban contract WASM is immutable without an explicit upgrade entrypoint. Redeploying requires running `init(admin)` on the newly deployed instance and re-submitting attestations for the corpus assets.

## What this deployment is not

- **Not mainnet, and not a candidate for it.** The list below is why.
- **One key can write anything.** The admin is a single ed25519 account whose
  seed lives on one machine. Anyone holding it can attest any severity for any
  asset. Custody, backup, loss and compromise response, and why rotation
  currently means redeploy are documented in
  [attester-key.md](attester-key.md). A real deployment wants a threshold of
  independent attesters;
  [multi-attestor.md](multi-attestor.md) compares the options.
- **10 attested assets.** Everything else on the network reads as `None`. That is the
  correct answer — unknown, not safe — but it means the registry is not useful
  as a general lookup yet.
- **No re-attestation schedule.** These attestations are as fresh as the
  `attested_at` in the table and nothing is refreshing them. A caller must pass
  a `max_age_secs` it is actually willing to accept rather than trusting that
  someone is keeping the registry current. [freshness.md](freshness.md) has
  the measured flag-change rates behind that advice.
- **Testnet data is not durable.** Testnet is periodically reset, which removes
  everything. Separately, this deployment predates TTL handling, so its
  instance, code and attestations are all archived today. They are restored on
  access at the caller's expense, not lost. See [Entry lifetime](#entry-lifetime).
