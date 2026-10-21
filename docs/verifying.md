# Verifying an attestation end to end

How a third party checks, from scratch, that an on-chain attestation corresponds
to real evidence — without reading Assay's source and without trusting the
attester.

This is the procedure `evidence_hash` exists for. It was previously assembled
from three places: [contract-interface.md](contract-interface.md) for the
encoding, [integrating.md](integrating.md) for a two-command sketch, and
[attestation-run.md](attestation-run.md) for worked results. This document is
the single place, in the order you run it.

It starts at step 0 rather than at the registry on purpose. The procedure is
only as good as the scanner running it, and the scanner is itself a downloaded
binary that has to be checked before it is trusted to check anything else.

## What you are checking, and what you are not

Verification establishes exactly one thing: **the severity and flags stored
on-chain are the ones this evidence produces.** It does not establish that the
attester was honest about *which* evidence it read, that the attestation is
fresh, or that `severity` is the right judgment — that model is argued in
[severity-model.md](severity-model.md).

Freshness is a separate check against `attested_at`. An attestation whose
evidence verifies perfectly can still be a year stale. Nothing here refreshes
anything; see [contract-interface.md](contract-interface.md) for why
`max_age_secs` is the caller's policy.

If the attester published an offline bundle, steps 3 and 4 can be replaced by
`assay verify -bundle`. The bundle contains the exact source bytes, so it
answers "does this evidence produce this hash" without re-scanning or contacting
a source. Steps 0–2 and 5–6 still apply: verify the binary, read the on-chain
attestation, compare, and interpret. The format and what it does not prove are
in [offline-bundle.md](offline-bundle.md).

## Step 0: verify the binary before you run it

Everything below runs `./assay`. If you have not checked where that binary came
from, a matching `evidence_hash` is still a statement made by an unverified
program: the scanner computes the hash, so whoever built the scanner chooses
what the hash is computed over. That is the weak link this section closes, and
it is why it is step 0 and not an appendix — **do not run step 1 or later
before this passes.**

Two separate claims, and they are not substitutes for each other:

| Check | Question it answers | What it cannot tell you |
| --- | --- | --- |
| `sha256sum -c` | Is the file I downloaded the file the release published? | Whether the release itself is honest — both files come from the same place |
| `gh attestation verify` | Was this exact digest built by the tagged commit in the project's own workflow? | Anything about whether the code at that commit is correct |

### 0a. Download the binary and its checksum together

Both assets are attached to every release. Download them into the same
directory:

```sh
REPO=use-assay/assay
TAG=v0.1.0                       # the release you are verifying

gh release download "$TAG" --repo "$REPO" --dir ./assay-check \
  --pattern assay --pattern assay.sha256
```

`--pattern assay.sha256` is not optional. Without it `gh release download`
matches `assay` loosely and you can end up with only one of the two files,
which turns every check below into a file-not-found error.

### 0b. Check the checksum

```sh
cd assay-check && sha256sum -c assay.sha256
```

Produces `assay: OK`. Anything else — `FAILED`, `No such file`, or a
`WARNING` line count — means stop.

This is an integrity check, not a trust check. It detects a truncated or
corrupted download and it detects the two files not belonging to each other.
It does not detect a tampered release: `assay` and `assay.sha256` are uploaded
by the same job, so anyone who can replace one can replace both. That is what
step 0c is for, and skipping 0c leaves you with a check that only proves the
download arrived intact.

### 0c. Check the build provenance

`REPO` is still set from step 0a in the same shell. On a fresh shell, set it
again:

```sh
REPO=use-assay/assay
gh attestation verify assay --repo "$REPO"
```

Produces `Loaded digest sha256:… for assay` and a `✓ Verification succeeded!`
line, ending in a link to the attestation on GitHub. Anything else is a
failure, including `✗ No attestations found for subject assay` — see below.

This is the check that binds the bytes to the tag. The release workflow
([.github/workflows/release.yml](../.github/workflows/release.yml)) signs a
provenance statement over the binary's digest with a short-lived OIDC token
minted for that run, and GitHub records it in a public transparency log.
`gh` then checks that the certificate chains to GitHub's OIDC issuer, that the
workflow it names is in *this* repository, and that the digest is the digest of
the file you downloaded. A substituted binary has a different digest and fails.

Read the output for three things, not just the last line:

- the **digest** it loaded, which must equal the one `sha256sum` printed in 0b;
- the **workflow and repository** in the certificate, which must be this repo's
  release workflow and not a fork or a lookalike;
- the **linked attestation**, which is worth opening once to confirm the
  subject name is the binary you hold.

`--repo` scopes the *lookup* to this repository. It does not pin *which*
workflow in it was allowed to sign. If you want the second guarantee enforced
rather than read off the output, ask for it:

```sh
gh attestation verify assay --repo "$REPO" \
  --signer-workflow "$REPO/.github/workflows/release.yml"
```

This fails unless the attestation was signed by that exact workflow file, which
is what closes the gap where a compromised or careless second workflow in the
same repository produces a valid-looking attestation for the same subject. If
it rejects an attestation 0c accepted, that is a finding — treat it as such
rather than retrying without the flag.

Run this as a user outside the project's own workflow. `gh` accepts a token
belonging to the repository being verified, so a check performed from inside
that repository's CI with its own token proves less than it appears to; for an
independent result, use a personal account that cannot write to the repository.

If `gh` reports no attestation found, the most likely cause is that you
downloaded from a fork, or that the release predates provenance being published
— in which case 0b is all that exists and you have no provenance claim at all.
Record that as a limitation of your verification rather than treating the
checksum as equivalent.

### What this does and does not establish

It establishes that the binary is byte-identical to one built by this
repository's release workflow from this tag. It does **not** establish that the
code is correct, that the build was free of a compromised dependency, or that
the tag is the version its name suggests. Provenance says *where the bytes came
from*, not *what the bytes do* — and what they do is what steps 1–6 below
check, against evidence rather than against the binary's own report.

To reproduce the build yourself instead of trusting the attestation, see
"Reproducible scanner builds" in
[CONTRIBUTING.md](../CONTRIBUTING.md) — `make build-release` is built to be
byte-reproducible across machines.

## The procedure

Each step says what it produces and how to tell it succeeded. Run them in order;
step 3 in particular gates everything after it.

Steps 1–6 assume a binary that has already passed
[step 0](#step-0-verify-the-binary-before-you-run-it). If you skipped it, stop
and go back — steps 3 and 4 shell out to `./assay`, so the rest of the
procedure is measuring the trustworthiness of a program you have not checked.

### 1. Derive the asset's SAC address for the network

The registry keys on an asset's **Stellar Asset Contract address**, which is
derived from the network passphrase. The same asset has a different address on
testnet than on pubnet, so derive it for the network you are verifying against
and do not copy one across.

```sh
stellar contract id asset \
  --asset USDZ:GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR \
  --network testnet
```

Produces a `C…` contract ID. On testnet, USDZ is
`CAOM5NKBTSGEXTZZKH3STWSFWURMODC3TZ4NS2THN7W5YUDFK3IOHIHU`, recorded in
[deployment.md](deployment.md). If your derived address differs, stop: you are
about to read a different asset's attestation, and every comparison after this
would be meaningless.

### 2. Read the attestation from the registry

`get_safety` simulates rather than submits, so this costs nothing and needs no
signature.

```sh
stellar contract invoke \
  --id CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73 \
  --network testnet --send=no \
  -- get_safety --asset <SAC_FROM_STEP_1>
```

or, from a checkout, the wrapper:

```sh
make read ASSET=CODE-ISSUER
```

Record four values: `severity`, `flags`, `evidence_hash`, and `attested_at`.

**If it returns `null`, stop.** The asset was never attested. That is not a
failed verification — there is nothing to verify, and `null` must not be read as
`clear`. Every gate fails closed on it by design
([contract-interface.md](contract-interface.md)).

### 3. Re-scan the asset and confirm the scan is complete

```sh
./assay scan CODE-ISSUER        # JSON report
```

The report has an `undetermined` field and, when it is true, an
`undetermined_checks` list naming the checks that could not complete.

**If `undetermined` is true, the answer is `unknown`, and verification is
impossible rather than failed.** A source that did not answer could have changed
the evidence — in either direction — and no hash can be computed from a partial
scan that means anything. `assay attestation` refuses to produce one for this
exact reason:

```
attest: scan is undetermined, so there is nothing to attest: reputation could not complete
```

Do not proceed to step 4 with an undetermined report, and never compare the hash
of one. Retry, or verify on a machine where the source answers. See
[attestation-run.md](attestation-run.md#finding-1) for the outage this rule was
written to catch.

### 4. Recompute the hash from the scan

```sh
./assay attestation -raw CODE-ISSUER
# severity<TAB>flags<TAB>evidence_hash

./assay attestation -preimage CODE-ISSUER
# the exact bytes hashed
```

An attestation written before the current encoding was hashed over *its own*
version's bytes, so render the recorded version rather than whatever the
current scanner emits. `docs/deployment.md` records that version per asset; a
recorded `v1` is reproduced with:

```sh
./assay attestation -raw -preimage-version v1 CODE-ISSUER
# severity<TAB>flags<TAB>hash(v1)<TAB>hash(current)
```

`-raw` prints the components step 5 compares. With `-preimage-version` it
prints a fourth field, the hash under the encoding the current binary picks,
so you can tell an evidence change (neither matches) from a mislabelled
version (only the fourth matches) — the same distinction
`scripts/reproducibility.sh` reports as `MISMATCH` versus `ENCODING`.
`-preimage` prints the canonical bytes those hashes are SHA-256 over, so the
check is independent of Assay: the encoding is specified line by line in
[contract-interface.md](contract-interface.md#evidence_hash-commits-to-the-claims-not-to-the-clock),
including the escaping, the sort order of `evidence` lines, and the deliberate
exclusion of retrieval timestamps.

One gap worth knowing before you reimplement it: the JSON `scan` report renders
severity as its level name and mechanics as a list of names, while the preimage
wants integers. Join the report to the ABI tables in
[contract-interface.md](contract-interface.md#abi) to convert them. The scan
report alone is not enough.

### 5. Compare

Compare three pairs, all of which must match:

| From the registry (step 2) | From the re-scan (steps 3–4) |
| --- | --- |
| `severity` | the severity `-raw` prints |
| `flags` | the flags `-raw` prints |
| `evidence_hash` | the hash `-raw` prints |

The hash commits to the severity and the flags along with the evidence, so a
matching hash with a differing severity cannot happen for an honest attestation;
if you see it, you are comparing against the wrong record or the wrong network.

### 6. Interpret

**valid — the hashes match.** The stored severity and flags are exactly the ones
this evidence produces. The attestation corresponds to its stated evidence. This
says nothing about whether the evidence is *current* — check `attested_at`
against your own tolerance to answer that.

**invalid — the hashes differ.** A mismatch has three possible causes, and the
hash cannot tell you which. They are not equally likely or equally serious:

1. **The asset changed since the attestation.** Issuer flags are mutable, and a
   failed `stellar.toml` fetch can succeed later. The attestation was correct
   when written and is now describing a different state. This is the benign
   case, and it is exactly why `attested_at` and `max_age_secs` exist: refresh
   or re-attest rather than treating it as fraud.
2. **The attestation is wrong.** It does not correspond to the evidence the
   attester claims to have read. This is the case `evidence_hash` exists to
   make detectable, and the one to escalate.
3. **Your environment differs from the attester's.** The evidence text is not
   machine-independent today. When a source is unreachable, the raw transport
   error is recorded verbatim and hashed — including a **DNS resolver address**
   (`lookup nasdaq.finance on 10.255.255.254:53`), timeout text, and resolved
   IPs. A verifier on another host gets different bytes, therefore a different
   hash, **when nothing is wrong at all**.

   This is [#24](https://github.com/use-assay/Assay/issues/24), it is not fixed,
   and it means a mismatch is *not* by itself evidence of a bad attestation. The
   fix is to normalise transport errors before they enter the preimage, which
   changes the preimage and needs an `assay-evidence-v2` version bump; until
   then, treat a mismatch on an asset whose `stellar.toml` did not resolve as
   *inconclusive on cause* rather than as a failed verification. The
   2026-09-17 audit found three of the ten on-chain hashes exposed this way —
   `BERKSHIRE`, `DOGE`, and `KALE` — plus `REPO`, whose parser error is stable
   only while the remote file is unchanged. Before you reach cause 2, check
   whether the report's evidence contains a transport error and whether you are
   on the same host as the attester.

   The `preimage` from step 4 is what makes this diagnosable: diff it against a
   preimage built on the attester's machine and the differing line says which
   source, and which kind of failure, moved the bytes.

**unknown — the scan could not complete.** Step 3 returned
`undetermined: true`. Verification is impossible, not failed: there is no
complete evidence bundle to hash, and the honest answer is that this asset
cannot be verified right now. This is the same rule the rest of the project
enforces — *"we could not check" and "this is fine" are different answers and
must never render the same* ([checks.md](checks.md)) — applied to verification
instead of to a single scan.

**stale — the evidence verifies but is old.** `attested_at` is the ledger
timestamp of the write. `max_age_secs` in your own gate is the only freshness
policy; Assay deliberately has none. An attestation that verifies and is a year
old has not failed verification, but you should not act on it as current.

## Worked example: USDZ

The values below are recorded in [deployment.md](deployment.md) and the
[attestation run](attestation-run.md). Reproduce them with the procedure above.

```
Asset            USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
Testnet SAC      CAOM5NKBTSGEXTZZKH3STWSFWURMODC3TZ4NS2THN7W5YUDFK3IOHIHU
severity         3 (high)
flags            6  (auth_revocable | auth_clawback_enabled)
evidence_hash    ca9b13a66f3a0a4b43d66dea29a505658447e08eee200d2bdb5e66aa1065fb4d
attested_at      1786771651  (2026-08-15T05:27:31Z)
```

Step 1 must re-derive `CAOM5NKB…`; step 2 must read back severity `3`, flags
`6`, and that hash; steps 3–4 must produce a *complete* report whose `-raw`
output under the recorded version is

```sh
./assay attestation -raw -preimage-version v1 USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
# 3	6	ca9b13a66f3a0a4b43d66dea29a505658447e08eee200d2bdb5e66aa1065fb4d	<current-encoding hash>
```

Step 5 matches on severity, flags and the first hash, and step 6 returns
**valid**. The reason `USDZ`
reproduces reliably is that its evidence carries no transport error: its domain
`zeam.money` answers, so nothing machine-dependent enters the preimage. That is
not true of every attested asset — see cause 3 above.

Note the freshness trap in the same example. `attested_at` is 2026-08-15, so a
gate with a 24-hour `max_age_secs` refuses USDZ as stale
([integrating.md](integrating.md)) even though its hash verifies. Verification
and freshness are different questions and the procedure answers only the first.

## Verification of this document

There is no automated test for it; the procedure *is* the test. A reviewer
follows the steps for USDZ and confirms the re-scan reproduces the hash recorded
in [deployment.md](deployment.md). If a step cannot be followed without reading
the source, that is a defect in this document.

Step 0 is verified the other way round, by construction rather than by
following it: it names the two assets
[release.yml](../.github/workflows/release.yml) publishes for every tag, and the
`gh` subcommands are the documented interface of GitHub's artifact attestations
rather than anything from this repository. What a reviewer *can* check without
a release to hand is that the release assets and the documented commands agree
— `assay` and `assay.sha256` are both attached by the `publish` step, and the
`attest build provenance` step runs before it, so a release that went up
without an attestation does not exist. Confirming that against a real tag is
left to the first release cut, which is recorded here as **not yet
verified**: this document's step 0 has not been executed end to end against a
published release, because no release has been published yet (#278).

## Related

- [contract-interface.md](contract-interface.md) — the `evidence_hash` encoding
  and the `get_safety` ABI.
- [offline-bundle.md](offline-bundle.md) — the archive that lets steps 3–4 be
  checked without a network, and its redistribution rules.
- [attestation-run.md](attestation-run.md) — every asset scanned and the
  reproducibility audit behind the #24 caveat.
- [integrating.md](integrating.md) — how a contract consumes an attestation, and
  the two-command version of this check.
- [deployment.md](deployment.md) — addresses, transaction hashes, and the
  attested-asset table this example is drawn from.
- [SECURITY.md](../SECURITY.md) — the reporting path if a check here fails in a
  way that looks like tampering rather than drift.
