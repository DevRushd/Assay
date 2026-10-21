# The CLI

`assay` is one binary with several subcommands. Commands that emit a document
(`scan`, `attestation`, `history`) print human-readable JSON by default, and
scripts can ask for a tab-separated `-raw` form where one exists. `verify` and
`diff` print a human-readable verdict by default and take `-json` for scripting.

```
usage:
  assay scan CODE-ISSUER          classify one asset and print the report as JSON
  assay attestation CODE-ISSUER   print the on-chain attest() arguments for one asset
  assay verify [-json] [-max-age SECS] CODE-ISSUER
                                  compare a live scan with the on-chain attestation
  assay verify -bundle IN [-json]
                                  verify an offline bundle without a network
  assay diff [-json] A.json B.json
                                  compare two saved reports and print what changed
  assay history [-guarantee] [-raw] CODE-ISSUER
                                  print the asset's observation history
  assay registry-history [-rpc URL] [-contract C...] [-json] ASSET
                                  print the registry's attest/revoke events for an asset
  assay serve [-addr] [-history PATH]
                                  serve the HTTP API and UI
```

Commands that scan also accept:

- `-asset-lists URL[,URL...]` — SEP-0042 Stellar Asset Lists to consume, given
  as a comma-separated list or repeated. **No list is used by default**: nothing
  is hardcoded as authoritative, and no report changes unless you opt in. See
  [asset-lists.md](asset-lists.md).

## assay scan

Scans one asset and prints the full report: the findings, the reasoning behind
each, and the evidence every conclusion is attributed to.

```
./assay scan CODE-ISSUER              # the findings and reasoning
```

The network's native asset is not scannable: it has no issuer account, so
there are no authorization flags to read. `assay scan native` (or `XLM`, any
case) recognises the input and refuses it with an explicit explanation rather
than a parse error, prints nothing to stdout, and exits 2:

```
assay: native asset has no issuer and no authorization flags: "XLM" cannot be scanned or attested
```

Every command that takes an asset — `scan`, `attestation`, `history`,
`verify` — refuses it the same way, so the native asset can never be scanned
or attested from the CLI. A credit asset whose code merely happens to be XLM
(`XLM-G…`) is scanned as the ordinary asset it is.

## assay attestation

Derives the arguments of an on-chain `attest()` call from a live scan. It
deliberately does not submit anything: signing belongs to whoever holds the
attester key, and keeping derivation separate from submission means the
numbers going on-chain can be inspected before a key ever touches them.

```
./assay attestation CODE-ISSUER       # severity, flags, evidence_hash
./assay attestation -preimage CODE-ISSUER   # + the bytes the hash commits to
./assay attestation -raw CODE-ISSUER  # just `SEVERITY<TAB>FLAGS<TAB>HASH`
```

`-preimage-version vN` renders the report under a historical encoding instead
of the one it binds, and accepts `v1`, `v2`, `v3`, `v4` or the full
`assay-evidence-vN` line. It can withhold bindings the scan carries (a live
scan is `v4`), but never add one: asking for a version that binds something
the report lacks is refused.

```
./assay attestation -preimage -preimage-version v1 CODE-ISSUER
```

This is how an attestation already on chain is reproduced: the recorded
`evidence_hash` was hashed over the bytes of its recorded version, so a
verifier must re-render those bytes rather than compare against whatever the
current scanner emits. The version the report itself binds is unchanged; only
the rendering is. An unknown version is refused before anything is printed.

With `-raw` and no `-preimage-version`, the output is unchanged: three fields,
`SEVERITY<TAB>FLAGS<TAB>HASH`. With `-preimage-version`, a fourth field is
appended — the hash the report renders under the version the current binary
would pick — so a caller can tell evidence drift from metadata drift:

```
SEVERITY<TAB>FLAGS<TAB>HASH(version)<TAB>HASH(current)
```

`scripts/reproducibility.sh` is the reference consumer: when the first hash
does not match the recorded one but the second does, the evidence is unchanged
and it reports `ENCODING` rather than a misleading `MISMATCH`.

`-bundle OUT` writes an offline verification bundle while deriving the
attestation: the exact response bytes the scan read, the report, the preimage,
the digest and the scanner identity. The scan is recorded into a private
temporary directory first, so a failed scan leaves no half-written archive.

```
./assay attestation -bundle attestation.tar.gz CODE-ISSUER
./assay verify -bundle attestation.tar.gz
```

See [offline-bundle.md](offline-bundle.md) for the archive layout and the
redistribution rules.

## assay verify

Checks one asset end to end: re-scans it, recomputes the evidence hash, reads
the on-chain attestation through the `stellar` CLI, and reports whether the two
agree. It replaces two commands and a human comparing hex by eye.

```
./assay verify CODE-ISSUER
./assay verify -json CODE-ISSUER
./assay verify -max-age 3600 CODE-ISSUER   # also treat an old attestation as stale
```

Flags:

- `-max-age SECS` — treat an attestation older than this many seconds as stale.
  `0` (the default) disables the age check; freshness is the caller's policy.
- `-json` — print the full verdict as JSON for scripting.

The contract and network come from `ASSAY_CONTRACT_ID` and `ASSAY_NETWORK`,
with the same defaults as the Makefile. The verdict classes are deliberately
distinct, and each has its own exit code:

| Outcome | Meaning | Exit |
| --- | --- | --- |
| `agree` | the scan, recomputed hash and chain match | 0 |
| `mismatch` | one or more of severity, flags or `evidence_hash` differs | 1 |
| `stale` | they match, but the attestation is older than `-max-age` | 2 |
| `absent` | no attestation exists on chain for this asset | 3 |
| `unverifiable` | the scan is undetermined or unevaluated, so no verdict is possible | 4 |

An undetermined scan never reports agreement. A mismatch names the differing
fields and prints both sides.

### Offline bundles

`-bundle IN` verifies an archive written by `assay attestation -bundle`. It
touches no network and runs no scan: it recomputes the digest from the archived
preimage and checks every file the manifest binds.

```
./assay verify -bundle attestation.tar.gz
./assay verify -bundle attestation.tar.gz -json
```

A valid bundle exits 0, a tampered or incomplete one exits 1, and an archive
that cannot be opened exits 4 — a broken file is not a mismatch. `-max-age`
cannot be combined with `-bundle`, because the archive records the report but
not when the attestation was written. The format, the files it contains and
the redistribution terms are in [offline-bundle.md](offline-bundle.md).

## assay diff

Compares two saved reports (`assay scan` output) and prints what moved:
capability bits added and removed, severity movement, accountability movement,
and evidence-only changes. It runs the same detectors the history API uses, so
"what changed" has one definition across the CLI and HTTP surfaces.

```
./assay scan CODE-ISSUER > before.json
# ... time passes ...
./assay scan CODE-ISSUER > after.json
./assay diff before.json after.json
./assay diff -json before.json after.json
```

Both documents must carry the same `schema_version` and describe the same
asset. An undetermined side is reported as undetermined, not as "no change";
[transitions.md](transitions.md) defines each state. The command validates the
saved files but does not re-derive either verdict.

## assay history

Prints an asset's observation history: one line per recorded observation, in
time order, derived from the report's evidence entries. Where `scan` answers
"what is true now", `history` answers "what did we observe, and when" — the
view an auditor needs when an asset's state changed and someone wants to know
whether it was ever different.

Each entry carries the asset, the report's severity at scan time, the
**transition** — what the issuer was observed doing, reduced to a term
(`malicious`, `listed as`, `blocked`, `unverified`, `not retrievable`, …) — the
observation's reason verbatim, and the time it was retrieved.

An observation that does not reduce to a known transition prints as
`unknown`. The history view deliberately does not re-derive the verdict; it
reports what each observation said.

```
./assay history CODE-ISSUER           # the observations as JSON
./assay history -raw CODE-ISSUER      # `ASSET<TAB>SEVERITY<TAB>TRANSITION<TAB>REASON`
```

Flags:

- `-raw` — print the history tab-separated instead of as JSON, for scripting.
- `-guarantee` — exit non-zero when the asset has no observations, so a script
  can distinguish "no history" from "history ran fine" without parsing output.

Semantics:

- **valid state** — the observations print in time order.
- **missing state** — a clear message (`no observations for ASSET`), and exit
  0 unless `-guarantee` was given.
- **unknown state** — an observation whose claim matches no known transition
  prints with transition `unknown` rather than being dropped.

## assay serve

Serves the HTTP API and UI. The API exposes the same reports the CLI prints;
see `docs/integrating.md` for what a consumer reads out of it, and
[history.md](history.md) for the observation history endpoint.

```
./assay serve -addr :8080
./assay serve -addr :8080 -history /var/lib/assay/history.jsonl
```

Each successful `GET /api/v1/scan` records an observation, and
`GET /api/v1/history?asset=CODE-ISSUER` returns them in time order with the
derived transitions. `-history` points that store at an append-only JSON Lines
log so it survives a restart; without it, history is in memory and lost when the
process exits. The default retention is 256 observations per asset and the
policy is in [history.md](history.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | Generic failure: the command ran but could not deliver a result. |
| 2 | Usage error: the command or its arguments cannot be used as given — an unknown command, a missing or malformed `CODE-ISSUER`, or an identifier naming the native asset, which is never scannable. |
| 3 | Not found: the asset or attestation does not exist on the ledger. |
| 4 | Upstream unavailable: a source the scan depends on could not be reached. |
| 5 | Undetermined: the scan ran, but a source outage or an inconsistency left no verdict to report. |

The native-asset refusal is deliberately a usage code rather than a generic
failure: it is answered from the ledger's own rules before any fetch, so it is
permanent and no retry will change it — a script can distinguish "this
identifier will never scan" from a transient failure without parsing stderr.
The same input is answered by the HTTP API as `400 Bad Request` with the same
message; see [api.md](api.md).
