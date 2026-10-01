# Contributing to Assay

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). If you
have found a way to make Assay under-report risk, that is a security issue —
see [SECURITY.md](SECURITY.md) and report it privately rather than opening an
issue.

## Ground rules

Assay makes claims about whether someone's money can be taken. Two rules
follow from that, and they are not negotiable:

**Never display a value you did not fetch.** No placeholder balances, no
example ratings, no "typical" flag sets. If a source is unreachable, the
output says the source is unreachable.

**Never re-derive a consumed signal.** StellarExpert's directory, ratings,
and blocklist are inputs. Assay attributes them to their source and passes
them through. If you find yourself writing a scam heuristic over domain
names, stop — that layer already exists and is better maintained than
anything we would write.

## Debugging a verdict

If Assay reports something unexpected for an asset, see [docs/debugging-a-verdict.md](docs/debugging-a-verdict.md) for a step-by-step workflow to trace the verdict to its cause and determine whether the discrepancy is in the live source ("the source says so") or in Assay's code.

## Adding a check

Full guide: [docs/adding-a-check.md](docs/adding-a-check.md).

A check is not done when it detects something. It is done when its
*judgment* has been measured.

1. Implement `mechanics.Check`.
2. Verify every flag name, field name, and endpoint against a live source
   before encoding it. Cite what you verified in the PR.
3. Add it to the labelled set in `docs/eval.md` with at least one asset that
   should trip it and one that has the same mechanics *legitimately* and
   should not be over-flagged.
4. Record the eval result. **A check whose judgment isn't evaluated against
   that set doesn't ship.**
5. Run `make eval` and verify the confusion matrix shows agreement for
   the new subject's severity level and checks. See [Running the
   evaluation](docs/eval.md#running-the-evaluation) for how to read the
   output and what a disagreement may mean.

Point 3 is the whole discipline. Any check can find `auth_revocable: true`;
the reason to have a check at all is that it knows when that is fine.

## Development

```sh
make test     # tests with -race
make lint     # golangci-lint
make cover    # per-package coverage table, lowest first
make run      # start the API on :8080
```

Shell scripts are checked with ShellCheck at warning severity in CI. Run the
same check locally from the repository root:

```sh
find . -type f \( -name '*.sh' -o -name '*.bash' \) -not -path './.git/*' -print0 | xargs -0 shellcheck -S warning
```

The Soroban side, which needs the [stellar CLI](https://developers.stellar.org/docs/build/smart-contracts/getting-started/setup):

```sh
make contract-test    # cargo test
make contract-lint    # cargo fmt --check + clippy -D warnings
make build-contract   # optimized wasm into assay-contracts/out/
make deploy-testnet   # upload + deploy, prints the new contract ID

make attest ASSET=CODE-ISSUER   # scan live and write the result on-chain
make read   ASSET=CODE-ISSUER   # read it back with get_safety
```

### Contract toolchain

Reproducing a wasm hash recorded in [docs/deployment.md](docs/deployment.md)
takes the same toolchain the deployment was built with, not just the same
source. Three versions decide the optimized bytes:

| Component | Recorded build |
| --- | --- |
| `stellar` CLI | 27.1.0 |
| Rust target | `wasm32v1-none` |
| `soroban-sdk` | 27.0.5 |

**The Rust compiler channel is not pinned.** There is no
`assay-contracts/rust-toolchain.toml` yet ([#127](https://github.com/use-assay/Assay/issues/127)),
so `rustup` selects whichever channel happens to be installed, and the
compiler version changes the optimized bytes: the same source under the same
`stellar` CLI hashes differently on rustc 1.95.0 and rustc 1.98.1. Until that
pin exists, a build here cannot be expected to reproduce a hash recorded in
[docs/deployment.md](docs/deployment.md), and `make verify-wasm` reports
`unpinned` and exits 2 rather than guessing — see
[docs/deployment.md](docs/deployment.md#does-the-source-still-build-what-is-deployed).
Check the environment before any contract work:

```sh
stellar --version && rustup target list --installed && make build-contract
```

`stellar --version` must print 27.1.0 and the target list must contain
`wasm32v1-none`; `make build-contract` then writes the optimized wasm to
`assay-contracts/out/`. A mismatch on any of the three changes the optimized
bytes, and therefore the hash, even when the contract source is byte for byte
identical — the CLI also runs the wasm optimizer and checks the exported
interface, so it is not a pass-through to `cargo build`. If
`sha256sum assay-contracts/out/assay_safety_registry.wasm` does not match the
[recorded wasm hash](docs/deployment.md#live-addresses), check these versions
before suspecting a source change — and note that a mismatch is only evidence
once the compiler is pinned, since an unpinned one changes the hash on its
own.

`make attest` derives every value from a live scan via `assay attestation`.
Never hand-write a severity, a bitset, or an evidence hash into a transaction —
see [docs/deployment.md](docs/deployment.md).

Run `make fmt` before committing; CI enforces `gofmt -l` being empty.

### Coverage

Every CI run reports Go coverage per package. Open the run, select the **Go**
job, and the table is in the job summary under **Go coverage**. It lists the
lowest coverage first, and packages with no test files are shown rather than
left out. The same table is printed in the **coverage report** step's log, and
the raw profile is attached to the run as the `coverage-profile` artifact.
From the command line:

```sh
gh run view <run-id> --log | grep coverage
gh run download <run-id> -n coverage-profile && go tool cover -html=coverage.out
```

`make cover` prints the same table locally.

Coverage is **reported, not gated**. There is no threshold, so a drop does not
fail CI. Adopting one is a separate decision
([#130](https://github.com/use-assay/Assay/issues/130)), and so is adding a
hosted coverage service. The report is computed in the workflow from `go test`
output and nothing is sent anywhere else.

### The merge gate

CI runs a merge gate on every PR. When a PR touches a **maintainer-owned
safety-critical path** or a dependency file, the gate flags it so a maintainer
reviews it before merge. The flag is **advisory: it does not fail CI**. Much of
the contributor backlog legitimately touches these paths — an issue asking you
to change the severity model cannot be completed without editing the severity
model — so a flag means "a maintainer should look at this", not "your work is
wrong". Owned paths: the [severity model](docs/severity-model.md)
and the code implementing it, the checks, the scanner's source handling, the
[evidence_hash encoding](docs/contract-interface.md), both contracts, the eval
fixtures, and the gate and CI workflow themselves. They are listed, with
reasons, in `scripts/merge-gate.sh`. PRs touching only other docs or other
tests pass.

Two limits, stated plainly. The gate checks paths, not the checklist: it
prints the checklist but cannot tell whether a box was ticked honestly. And
because the flag is advisory, the gate does not by itself prevent a merge — it
writes its finding to the job summary and relies on a maintainer reading it.
The gate does still fail CI in one case: when it cannot run at all, because
then its finding is unknown rather than clean.

Note that `make verify-gate` still exits non-zero on a flag, which is what
makes it useful as a local check. Only CI treats the flag as advisory.

Verify your PR against the gate before opening it:

```sh
make verify-gate BASE=main HEAD=HEAD
```

The checklist it prints (also in the PR template) covers the part CI cannot
check: no unjustified dependency, no threshold moved without a reason
traceable to the attestation run, nothing published that the evidence does
not support.

Tests must not require network access. Fetchers are interfaces; tests use
fixtures captured from real responses under `internal/*/testdata/`. When you
capture a new fixture, follow
[Capturing a fixture](docs/adding-a-check.md#capturing-a-fixture): it lists the
files a subject is made of, the URL for each, how to record provenance, and what
to do when a source errors at capture time.

### The reproducibility job

`.github/workflows/reproducibility.yml` recomputes the `evidence_hash` for
the ten attested assets by scanning them live and diffs each fresh hash
against the table in `docs/deployment.md`. The logic lives in
`scripts/reproducibility.sh` so it can be run locally exactly as CI runs it.
It is the regression test for [#24](https://github.com/use-assay/Assay/issues/24):
three of the ten on-chain hashes embed host-specific transport error text,
so until #24 is fixed the job is expected to report mismatches from any
machine whose DNS resolver differs from the attester's.

It runs weekly (`cron: 0 6 * * 1`) and on demand (`workflow_dispatch`):

```sh
gh workflow run reproducibility.yml && gh run watch
```

It is deliberately **not on the PR path and never gates merges**. It depends
on live third-party sources — Horizon, StellarExpert, issuer `stellar.toml`
hosts — so running it per-PR would make CI flaky for reasons unrelated to
the change under review. An upstream outage must not turn a contributor's
green PR red, and a scanner change must not be judged by what the live
network happened to answer that hour. The merge gate above is the per-PR
check; this job is the scheduled detector.

Semantics, matching the script's exit codes:

- **valid (exit 0)** — every fresh hash matches: pass.
- **invalid (exit 1)** — a genuine mismatch fails and names the asset with
  both hashes (`MISMATCH ASSET expected … actual …`).
- **unknown (exit 2)** — a scan that returns undetermined, or any scan error
  such as an unreachable source, is reported as **inconclusive**, never as a
  pass and never as a hard failure. An upstream outage is not a
  reproducibility bug. GitHub has no neutral job conclusion, so the workflow
  records inconclusive as a warning with a green check; the step summary
  says `INCONCLUSIVE`, not `PASS`.
- **stale — n/a.** The hash commits to what the sources claimed, not to when
  they were asked, so attestation age is irrelevant to this comparison.
  Freshness policy lives in [docs/freshness.md](docs/freshness.md).

Run it locally before relying on a scheduled result:

```sh
go build -o assay ./cmd/assay
./scripts/reproducibility.sh
```

Exercise the inconclusive path by pointing a source at an unreachable
address (supported via `ASSAY_HORIZON_URL` / `ASSAY_STELLAREXPERT_URL`, which
`internal/scan` reads; empty means the public default):

```sh
ASSAY_STELLAREXPERT_URL=http://127.0.0.1:1 ./scripts/reproducibility.sh --attempts 1 --delay 0
# expect: exit 2, every asset INCONCLUSIVE with "scan is undetermined"
```

Two overrides exist for debugging; neither changes what the scanner checks,
only where it fetches from.

### Mutation testing: decision recorded

**Decision (2026-09-27, issue #110): do not adopt mutation tooling in CI.
The manual catalogue is the standing practice.**

Mutation testing measures whether the safety tests actually constrain the
code — nothing else does. The baseline catalogue ([docs/mutation-catalogue.md](docs/mutation-catalogue.md))
proves the practice has teeth: of 14 safety-critical mutations, 13 were
cought and one (R-M4) was a real test gap, now closed. So the technique is
adopted; only automation is declined. The evaluation:

| Option | Runtime cost (measured) | Verdict |
| --- | --- | --- |
| **Do nothing** (no mutation measurement at all) | 0 | Rejected — the baseline found a gap the suite did not know about; skipping the practice is how the next one ships |
| **Manual catalogue** (current) | ~45–60 min of contributor time per run, no dependency | **Adopted as standing practice** |
| **CI-integrated tooling** (`go-mutesting`-style Go mutation runners, `cargo-mutants` for the contracts) | even at one mutation per invocation, the full catalogue is ≥14 package builds + test runs; measured suite times (0.6 s Go, 0.4 s registry) put the floor near 10–20 min per PR, with the real cost several times that because mutation runners recompile per mutant | Declined for CI |

The reasoning, in the project's own terms: the catalogue found 13/14 the
first time it was run, which is the argument for keeping the practice. It is
declined for CI because a mutation check is inherently slow and its failures
are noisy — a surviving mutant often means "add a test", not "your change is
broken", and a red-for-that-reason check on every PR becomes a check everyone
learns to ignore. The project's dependency rule also applies and is recorded:
any third-party mutation framework would need a decision that it is
warranted, and the manual procedure is reproducible from
[docs/mutation-catalogue.md](docs/mutation-catalogue.md) with no dependency
at all. **Advisory, not blocking, and not over any package: the catalogue
runs when safety-critical branches change, and its result is the PR
description's job to record.**

If the corpus of safety-critical branches grows to the point that the manual
run is skipped in practice, reopen the decision — a standing measurement that
nobody runs is worse than none.

## Commits

Present tense, explain the why when it isn't obvious. Keep unrelated changes
in separate commits. Don't commit binaries, coverage output, or logs.
