# Mutation catalogue and baseline

Mutation testing measures whether the safety tests actually constrain the code.
Three mutations were applied by hand on 2026-09-17 — removing `require_auth`,
making an unattested asset pass, removing the severity ceiling — and all three
were caught. That is encouraging and unrepeatable. This catalogue makes it a
standing measurement: the mutations are named in advance, tied to the property
each one violates, and run against the suite. A mutation the suite does not
catch is a test gap, and test gaps are filed as issues, not explained away.

## Scope and rules

- The mutations are **safety-critical**: each one, if it survived, would make
  Assay or its gate produce a more permissive answer than the truth. That is
  the class of bug #23 and #25 belong to.
- The catalogue is defined in terms of **properties that must not regress**,
  not lines of code. A code edit that renames everything but keeps the
  properties would leave this catalogue valid.
- **No tooling dependency.** The procedure is manual and reproducible with
  `git` and a Rust/Go toolchain alone (see [Procedure](#procedure)). Whether
  to adopt mutation tooling is a separate decision — #110 records it.
- A surviving mutation is a test gap. File it, fix the gap with a test, and
  re-run the catalogue. Do not weaken the mutation until it trips something.

## The catalogue

Each row: the mutation, the property it violates, where it is applied, and the
baseline verdict. **caught** means at least one test in the suite failed with
the mutation applied; **survived** means the run found a test gap.

### Go — the engine and the severity model

| ID | Mutation | Property violated | Target | Baseline |
| --- | --- | --- | --- | --- |
| G-M1 | Severity downgrade in aggregation: replace `rep.Base = f.Severity` with `rep.Base = Clear`, so the max over findings always returns Clear | Base severity is the maximum over non-escalation findings; a clawback flag must reach High | `internal/mechanics/mechanics.go`, `Engine.Run` aggregation | **caught** |
| G-M2 | Removal of the escalation branch: delete the body of `if f.Escalation { ... }` so escalation findings cannot raise the final level | Reputation is monotonic upward: a confirmed malicious listing escalates to Critical | `internal/mechanics/mechanics.go`, `Engine.Run` escalation aggregation | **caught** |
| G-M3 | Unknown treated as safe: in `CapabilityCheck.Run`, return `Clear` instead of `Unevaluated` when `s.Stat == nil` | An unread flag must never render as the ABI's safest value; Clear requires a read | `internal/mechanics/check_capability.go`, nil-Stat branch | **caught** |
| G-M4 | Missing evidence treated as safe: in `ReputationCheck.Run`, disable the `len(unreachable) > 0` branch so an outage returns a clean finding | An unreachable reputation source must render as undetermined, never as "not listed" | `internal/mechanics/check_reputation.go`, undetermined branch | **caught** |
| G-M5 | Missing evidence treated as safe at attestation: skip the `rep.Undetermined` refusal in `FromReport` | A partial scan must never be attestable; on-chain there is nowhere to put the caveat | `internal/attest/attest.go`, `FromReport` undetermined refusal | **caught** |
| G-M6 | Escalation sets a capability bit: add `MechClawbackEnabled` to the reputation escalation finding | An escalation must never grant a power the ledger does not; CapabilityMask must stay clean | `internal/mechanics/check_reputation.go` | **caught** |
| G-M7 | Flag disagreement resolved in the holder's favour: change `reconcileFlags`'s clawback OR to AND | A power is held if either Horizon copy reports it; indexer lag must not lower severity | `internal/mechanics/check_capability.go`, `reconcileFlags` | **caught** |

### Rust — the safety registry

| ID | Mutation | Property violated | Target | Baseline |
| --- | --- | --- | --- | --- |
| R-M1 | `require_auth` removed from `attest` | Only the admin may write attestations | `assay-contracts/contracts/safety-registry/src/lib.rs` | **caught** |
| R-M2 | Unattested asset passes: `is_safe` returns `true` when `get_safety` yields `None` | Unknown must fail closed; None is not safe | same, `is_safe` | **caught** |
| R-M3 | Severity ceiling removed at write time: delete the `severity > SEVERITY_CRITICAL` rejection | The ABI range is enforced at write time so readers can rely on it | same, `attest` | **caught** |
| R-M4 | Confiscation invariant removed at read time: delete the defence-in-depth clawback check in `is_safe` | A gate must not depend on the writer having been correct | same, `is_safe` | **survived → closed in #111's PR** (see below) |
| R-M5 | Staleness check removed from `is_safe` (always treat as fresh) | An attestation is only as fresh as `attested_at`; a caller's `max_age_secs` must bind | same, `is_safe` | **caught** |

### Rust — the example gate

| ID | Mutation | Property violated | Target | Baseline |
| --- | --- | --- | --- | --- |
| E-M1 | Unattested branch inverted: `assert_safe` returns `Ok` on `None` | An asset nobody scanned is unknown, not safe | `assay-contracts/contracts/example-gate/src/lib.rs`, `assert_safe` | **caught** |
| E-M2 | Severity ceiling removed from the gate: delete the `severity > MAX_SEVERITY` refusal | A critical-by-reputation asset with no capability bits must be refused by the ceiling — the DOGE case | same, `assert_safe` | **caught** |

## Baseline run — 2026-09-27

Procedure: each mutation applied by hand in a scratch `git worktree` of
`main` (`31a099f`), the suite run, the tree restored. A mutation is **caught**
when the suite fails for the mutated package. Every row above was executed in
this run.

| ID | Suite run | Result | Caught by (first failing test) |
| --- | --- | --- | --- |
| G-M1 | `go test ./internal/mechanics/` | caught | `TestEval` (usdz/usdc/berkshire drop to clear), `TestConfiscationImpliesHigh`, `TestMutabilityLeavesBaseSeverityUnchanged` |
| G-M2 | `go test ./internal/mechanics/` | caught | `TestEval` (berkshire no longer escalates), `TestPositiveListingStillEscalatesWhenTheOtherSourceIsDown` |
| G-M3 | `go test ./internal/mechanics/` | caught | `TestNilStatIsUnevaluatedNotClear`, `TestNilStatEngineRunIsUndeterminedNotClear` |
| G-M4 | `go test ./internal/mechanics/` | caught | `TestOutageDoesNotRenderAsNotListed`, `TestEitherSourceFailingIsEnough` (directory and blocklist) |
| G-M5 | `go test ./internal/attest/` | caught | `TestUndeterminedReportIsRefused`, `TestCapabilityClearWithReputationDownIsNotAttestable` |
| G-M6 | `go test ./internal/mechanics/` | caught | the escalation-capability-bit suite (`TestAgreedSourcesKeepSeverityAndOneEvidenceEntry`, `TestMutabilityLeavesBaseSeverityUnchanged`) |
| G-M7 | `go test ./internal/mechanics/` | caught | `TestDisagreementResolvesAgainstTheHolder`, `TestResolutionNeverSitsBelowEitherSource` |
| R-M1 | `cargo test -p assay-safety-registry` | caught | `test::attest_rejects_unauthorized_caller` |
| R-M2 | `cargo test -p assay-safety-registry` | caught | `test::gate_fails_closed_on_unattested_asset`, `test::admin_revokes_attestation` |
| R-M3 | `cargo test -p assay-safety-registry` | caught | `test::attest_rejects_out_of_range_severity` |
| R-M4 | `cargo test -p assay-safety-registry` | **survived** | — (`30 passed, 0 failed`) |
| R-M5 | `cargo test -p assay-safety-registry` | caught | `test::stale_attestation_fails_closed`, `test::read_after_archival_returns_original_attestation` |
| E-M1 | `cargo test -p assay-example-gate` | caught | `test::unattested_asset_is_refused` |
| E-M2 | `cargo test -p assay-example-gate` | caught | `test::severity_above_ceiling_is_refused`, `test::critical_by_reputation_without_capability_bits_is_refused`, `test::confiscation_capable_asset_is_refused` |

### Baseline verdict: 13/14 caught, 1 survived

**R-M4 survived, and that is the measurement working, not failing.** The
existing `gate_blocks_confiscation_below_high_threshold` test cannot
distinguish the defence-in-depth branch from the severity ceiling: it attests
a *valid* HIGH+clawback asset, so the severity check refuses the gate call
before the bitset re-check is ever reached. Deleting the re-check changes
nothing the suite can see. The branch only becomes observable when a stored
attestation violates the write-time invariant — exactly the situation it
exists for, and exactly what no test exercised.

The gap was closed in the same change that measured it
(#111's PR, commit recorded there): the new test
`test::fail_closed::fail_closed_gate_refuses_confiscation_when_the_write_time_check_is_bypassed`
inserts an inconsistent entry (severity MEDIUM, clawback bit set) into storage
directly via the host — as a buggy or pre-invariant writer would have — and
requires the gate to refuse it on the bitset. Re-running R-M4 with that test
present: **caught**, by that test alone. The catalogue row's verdict now reads
caught-in-the-PR; the original run's survivor is recorded here rather than
erased, because an honest baseline that found one gap is worth more than a
tidy one that found none.

The first run of that new test in the mutated tree also surfaced a mechanics
note for future runs: the Soroban SDK writes a snapshot file on first
execution of a gated test, and a first-run snapshot failure looks exactly like
a mutation catch. Commit the snapshot with the test, and verify a "catch"
against the committed snapshot — a failing test whose message is "Writing test
snapshot file…" is not a catch.

## Procedure

Reproduce the baseline from this document alone:

1. Create a scratch tree: `git worktree add /tmp/mutrun HEAD` (or a fresh
   clone). The mutation must never be applied to a working tree you care
   about.
2. Pick a row. Open the target file listed for it and apply the mutation
   exactly as described in the *Mutation* column. The mutations are small by
   design — most are one line deleted, one branch inverted, or one expression
   replaced by a constant.
3. Run the suite listed in the baseline table for that row.
4. **Caught** if the suite fails; note the first failing test by name, as the
   baseline does. **Survived** if the suite passes: that is a test gap — file
   an issue quoting this catalogue and the mutation, add the missing test, and
   update the row. (R-M4's closure above shows the shape.)
5. Restore the file (`git checkout -- <file>`) and remove the worktree before
   touching the next row. Never commit a mutated tree; the catalogue is a
   measurement, not a change.

For the Rust rows, `cargo test -p assay-safety-registry` or
`-p assay-example-gate` from `assay-contracts/`; for the Go rows,
`go test ./internal/...` from the repository root.

## Extending the catalogue

When a new safety-critical branch is added — a new check, a new gate
condition, a new refusal in `attest.FromReport` — add a row in the same change:
mutation, violated property, target, and a baseline verdict from actually
running it. The catalogue is only as good as its last run; a row whose
baseline is stale is a row that documents nothing.
