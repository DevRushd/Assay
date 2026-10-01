# Attester key management and rotation procedure

The registry's entire write path is one ed25519 key. This document states
where that key lives, how it is (and is not) backed up, who can use it, what
an attacker holding it can and cannot do, and what happens on loss or
compromise. It documents the current situation honestly, including the gaps,
rather than describing a posture that does not exist yet.

Scope: the **testnet** deployment recorded in
[deployment.md](deployment.md). The immediate financial risk is nil; the
procedural gap is the point. Nothing here publishes secret material — only
the public address and the operational procedure around it.

Related work:

- Admin rotation in the contract: [#89](https://github.com/use-assay/Assay/issues/89).
  There is no rotation entrypoint today; until one lands, redeploy is the
  only rotation (see [Rotation](#rotation-no-in-place-rotation-today)).
- Threat model: [#30](https://github.com/use-assay/Assay/issues/30).
  `docs/threat-model.md` does not exist yet. The attacker-capability
  statements below are kept consistent with the trust-boundary documentation
  that does exist: the single-admin threat model in
  [attestation-writer.md](attestation-writer.md#threat-model), the comparison
  table in [multi-attestor.md](multi-attestor.md#what-a-compromised-attestor-can-do-today),
  and [integrating.md](integrating.md#what-you-are-trusting).

## Where the key lives

- **Identity:** the `assay-attester` Stellar CLI identity, created with
  `stellar keys generate assay-attester` and stored in the local CLI
  configuration on the deployment machine.
- **Address (public):** `GALIEUOBDLTFJHTVH5E3MT2BMDTQ3PKMX2U6BRXVKLEB7ARFORFNNMVY`.
- **Role on-chain:** the `admin` passed to `init` on the testnet registry
  `CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73`
  ([deployment.md](deployment.md#live-addresses)). `attest` and `revoke`
  both require this admin's authorization; no other key can write.
- **Role off-chain:** the default `SOURCE` in the [Makefile](../Makefile)
  (`SOURCE ?= assay-attester`). Every write path uses it:

  ```sh
  stellar keys address assay-attester   # confirm the identity resolves to GALIEUOBD…
  make attest ASSET=CODE-ISSUER         # scans live, derives args, submits as assay-attester
  make read ASSET=CODE-ISSUER           # simulates a read; needs no signature
  ```

  TTL maintenance also signs as this identity
  ([deployment.md](deployment.md#entry-lifetime)).

Confirm the wiring at any time with the check from the issue:

```sh
grep -rn 'assay-attester' docs/ Makefile
```

## Custody and backup — current state, stated plainly

- **One key, on one machine.** The seed exists as a single copy in the
  deployment machine's Stellar CLI key store. There is no HSM, no
  multisig, and no second operator holding an independent copy.
- **No documented backup exists today.** If the machine's key store is
  deleted and no out-of-band copy was taken, the key is gone. This document
  does not claim a backup that has not been made.
- **Who has access:** whoever controls the deployment machine controls the
  key. Access is not shared, split, or logged by any Assay mechanism; it is
  whatever operating-system and physical access control that machine has.
- **What this means:** loss and compromise are both single events with
  registry-wide effect. The responses below assume exactly that.

Recommended but **not yet done** (do not read these as claims):

1. Write the seed to two encrypted offline copies (e.g. age/PGP-encrypted
   files on separate removable media), each decryptable only by its
   holder, and record their locations out of band.
2. Never copy the seed to CI, chat, screenshots, or shell history; pass the
   identity name (`assay-attester`), never the seed, on the command line.
3. On any move toward value-bearing use, replace the single key first —
   either with a threshold admin account as the interim step or with the
   consumer-chosen quorum recommended in
   [multi-attestor.md](multi-attestor.md#recommendation) — before widening
   attested-asset coverage.

## Semantics

- **Valid state** — key available and controlled: attestation proceeds via
  `make attest`, which derives every submitted number from a live scan.
- **Missing state** — key lost: the registry is permanently unwritable; the
  consequence and the recovery path (redeploy and re-attest) are stated
  below.
- **Invalid state** — key compromised: the response and the attacker's exact
  capabilities are stated below.

## What an attacker with the key can and cannot do

Consistent with [attestation-writer.md](attestation-writer.md#threat-model)
and [multi-attestor.md](multi-attestor.md#what-a-compromised-attestor-can-do-today).
"The attester" below means whoever holds the admin key — including an
attacker.

### Can do

| Action | Effect on a consumer | Direction |
| --- | --- | --- |
| Attest **any severity for any asset**, including `clear` for a dangerous asset or `high` for a harmless one | A gate **admits** an asset it should refuse | Unsafe: funds at risk — the only row that puts funds at risk |
| **Overwrite** any existing attestation with new values | The old values are gone; `attest` keeps no history | Unsafe, same row as above |
| `revoke` a correct attestation (on a registry build that has `revoke`) | `get_safety` returns `None`; gates refuse | Safe: denial of service, fails closed |
| Attest an asset **never scanned**, with a fabricated `evidence_hash` | Detectable after the fact by re-scanning ([verifying.md](verifying.md)); not preventable on-chain | Detective control only |
| Stop writing, or refuse to write | Attestations go stale; the consumer's `max_age_secs` converts staleness to refusal | Safe: denial of service, fails closed |

Notes:

- A fabricated write is a **checkable lie, not an invisible one**.
  `evidence_hash` commits to the evidence bundle
  ([contract-interface.md](contract-interface.md#evidence_hash-commits-to-the-claims-not-to-the-clock)),
  so anyone can re-scan and recompute it per
  [verifying.md](verifying.md). A consumer that gates *without* verifying
  hashes is still fully exposed; verification is detective, after the fact.
- The hash does not survive a scanner downgrade or a compromised build
  (check-set and version binding are separate issues), and three of the ten
  live attestations embed machine-dependent transport text, so a hash
  mismatch alone is inconclusive about cause ([verifying.md](verifying.md#6-interpret)).
- Archived entries restore on access with their original `attested_at`
  ([deployment.md](deployment.md#entry-lifetime)); an attacker gains nothing
  from archival and cannot make an archived attestation read as fresh.

### Cannot do

- **Move funds, mint assets, or change any gate's code.** The key authorizes
  registry writes only. It is not a signer on any holder account and cannot
  alter the example gate or any consumer contract.
- **Make an unattested asset read as safe without writing.** `get_safety`
  returns `None` for anything never attested (or revoked), and `is_safe`
  fails closed on `None`. Admission requires an explicit false attestation,
  which is the detectable write above.
- **Rewrite history invisibly.** Overwritten values leave no on-chain
  history, but the previous attestation's `evidence_hash` was already
  checkable by anyone who recorded it, and Soroban events (`attest`,
  `revoke`) give indexers the write and its withdrawal.
- **Escalate beyond the registry.** The key cannot change Stellar network
  parameters, validator behaviour, Horizon state, or third-party signals
  (StellarExpert directory, blocklist) that the scanner consumes.
- **Be distinguished on-chain from the honest operator.** There is one admin;
  the contract cannot tell compromise from legitimate use. Detection is
  entirely off-chain, via the verification procedure.

## Response to loss

**Consequence:** the registry becomes permanently unwritable. `attest` and
`revoke` both require the admin; with the seed gone, no new attestation and
no revocation can ever be submitted. Every existing attestation then ages in
place: gates with a `max_age_secs` window refuse them as stale, and after
roughly 180 days without re-attestation the entries archive (restored on
read at the reader's expense, still carrying the original `attested_at` —
archival is not expiry and not a recovery,
[deployment.md](deployment.md#entry-lifetime)).

**Recovery path (today, the only one): redeploy and re-attest.**

1. Generate a fresh identity on the deployment machine
   (`stellar keys generate assay-attester`) and record its address.
2. `make deploy-testnet`, then `init` the new registry with the new admin
   address, per [deployment.md](deployment.md#redeploying).
3. Re-attest the assets from **live scans** with `make attest` — one asset
   at a time. Attestations cannot be copied across: the new contract has no
   import path, and re-scanning is the only way to write them with a
   truthful `attested_at`.
4. Redeploy the example gate against the new registry address (it binds the
   registry at construction) and update `CONTRACT_ID` plus the address
   tables in [deployment.md](deployment.md),
   [integrating.md](integrating.md) and
   [contract-interface.md](contract-interface.md).
5. Mark the old registry superseded in [deployment.md](deployment.md), as
   was done for the old gate instances. Contracts cannot be deleted; anyone
   still pointed at the old ID keeps reading its (stale) attestations.

There is no faster path: `init` is single-shot (`AlreadyInitialized` on a
second call) and no transfer entrypoint exists — see
[Rotation](#rotation-no-in-place-rotation-today).

## Response to compromise

Treat any suspected compromise as confirmed until the verification below
says otherwise.

1. **Stop using the registry immediately.** Tell integrators to fail closed
   (they already do on stale/`None`, but a compromised key writes *fresh
   false* attestations, which no `max_age_secs` window catches). Do not
   submit further writes with the compromised key — including "corrective"
   overwrites, which are new claims over tainted authorship.
2. **Verify every live attestation** with [verifying.md](verifying.md):
   re-scan each attested asset, recompute `severity`, `flags` and
   `evidence_hash`, and compare against the on-chain values. Any mismatch
   that is not explained by asset change or the documented transport-text
   caveat is a malicious or erroneous write — escalate it as a
   severity-under-reporting issue per [SECURITY.md](../SECURITY.md).
3. **Rotate by redeploying.** Because there is no on-chain rotation (next
   section), generate a fresh `assay-attester` identity on a clean machine,
   deploy a new registry, `init` it to the new address, re-attest from live
   scans, redeploy the gate, and update the address tables — the same five
   steps as loss recovery. The compromised admin has no power over the new
   registry.
4. **Leave the old registry in place and mark it superseded** in
   [deployment.md](deployment.md). It cannot be deleted or frozen from the
   outside; the protection for its remaining readers is the same
   verification procedure plus a `max_age_secs` they actually enforce.
5. **Record what happened** in the deployment history: when the compromise
   was suspected, which attestations verified and which did not, the new
   registry address, and the transactions that established it.

Do not attempt to "reclaim" the old registry. Any transaction the old admin
could submit, the attacker can submit too.

## Rotation: no in-place rotation today

The contract has no rotation path: `init` is single-shot and rejects a
second call with `AlreadyInitialized`, and there is no transfer entrypoint.
Rotating the admin therefore **requires contract support**, tracked as
[#89](https://github.com/use-assay/Assay/issues/89) (admin-authorized
transfer, immediate versus two-step still to be decided there). That issue
is deliberately out of scope here — this issue documents custody and
response; #89 implements the on-chain half.

Until #89 lands and a registry carrying it is deployed, **redeploy is
rotation**: the migration sequence in
[deployment.md](deployment.md#migrating-to-a-registry-with-revoke) is the
procedure, and any schedule that assumes a cheaper rotation is assuming a
contract that does not exist yet.

## What this document does not publish

Only the public address `GALIEUOBD…` and the identity name `assay-attester`
appear here. No seed, no secret key, no backup contents, and no machine
identifiers. If a future edit ever needs to reference backup locations, it
must describe them by holder and medium, never by contents.
