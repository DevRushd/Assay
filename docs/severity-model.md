# The severity model

This is the part of Assay worth arguing about. Reading a flag is trivial and
deterministic. Deciding what a flag *means* is the whole product.

The vocabulary this page argues with — `clear`, `unevaluated`, `valid`,
`unknown`, `stale`, `undetermined` — is defined, together with the state each is
most often confused with, in [the glossary](glossary.md).

## The problem

`auth_clawback_enabled` lets an issuer confiscate your balance and burn it,
without your signature. It is also the mechanism a regulated issuer uses to meet
legal obligations — sanctions enforcement, court-ordered reversal, recovering
provably stolen funds. The flag is identical in both cases. The ledger cannot
tell you which one you are looking at, because the difference is not on the
ledger.

A scanner that paints every clawback-capable asset red is wrong about every
well-run regulated asset, and a tool that is wrong about the largest assets on
the network gets ignored. A scanner that waves through anything issued by a
recognizable name is worse: it has quietly become a brand-recognition service
wearing a security tool's clothes.

## The resolution: two axes, never merged

Assay reports **severity** and **accountability** as separate values, and
refuses to combine them into a single score.

| | Severity | Accountability |
| --- | --- | --- |
| Question | What *can* the issuer do to my balance? | Who, if anyone, stands behind that power? |
| Source | Issuer authorization flags | Reciprocal SEP-1 domain, curated directory |
| Nature | Consensus-enforced fact | Published claim |
| Effect | Gates on-chain decisions | Informs a human |

The user decides what to do with the combination. Assay does not decide for
them by averaging a fact with an opinion.

## Rule 1: severity is capability-only

Severity is derived from issuer flags and nothing else. Not reputation, not age,
not trustline count, not who the issuer is.

**Two assets whose issuers hold identical power over holders receive identical
severity.** A household-name regulated stablecoin and an anonymous account
created an hour ago, with the same flags, classify the same.

This is not an oversight. It is the property that makes the on-chain gate sound.
A contract reading `severity <= MEDIUM` is relying on a statement about ledger
mechanics. The moment reputation could lower a severity, that contract would be
relying on a third party's opinion, delivered through a data feed, about an
issuer — and it would have no way to tell the two kinds of claim apart.

It also removes the attack. If attribution lowered severity, the cheapest way
past the gate would be to buy attribution: register a domain, publish a
stellar.toml, get listed. Capability-only severity makes that pointless, because
the flags are what is measured and the flags do not care who you are.

The tests enforce this directly: stripping every trace of attribution from a
subject must not change its severity.

## Rule 2: reputation is monotonic upward

A confirmed malicious listing escalates severity to **Critical**, regardless of
flags. Nothing ever lowers severity.

The asymmetry is deliberate, and it is the correct reading of what the evidence
supports:

- **Presence** on a curated malicious list is a positive observation. Someone
  investigated and concluded abuse. That is decisive.
- **Absence** is not an observation at all. Most legitimate assets are absent
  from scam lists. So is every scam nobody has reported yet. Treating absence as
  a safety signal would mean every brand-new trap scores well precisely when it
  is most dangerous.

Every escalation is auditable: the report carries `base_severity` (capability
alone) next to `severity` (after escalation) and a boolean `escalated`, so you
can always see exactly what reputation contributed.

### Escalation never sets a capability bit

Stronger than the level rule, and the invariant the on-chain gate's correctness
rests on: an escalation finding contributes **no capability bit** to the report
bitset. Bits 0-2 (`auth_required`, `auth_revocable`, `auth_clawback_enabled`)
are the ledger's own record of what the issuer can do, and `CapabilityMask`
(names those three bits in `internal/mechanics/severity.go`) is how a consumer
masks them out of the bitset to read that record. Reputation raising a level
must never read as the ledger granting a power.

Today reputation sets `blocklisted` (bit 5) on escalation — a non-capability
bit, which is exactly the point: a CRITICAL asset with no auth flags must mask
to an empty capability set, and it does.

Nothing relies on convention here. `Engine.Run` rejects an escalation finding
that carries any capability bit with an error rather than masking the bits and
carrying on — silently dropping them would hide exactly the bug the guard
exists to catch — and `TestEscalationNeverSetsCapabilityBits` asserts the
invariant across every eval fixture and over hand-built escalated subjects,
with a negative test proving the assertion fires on a deliberately bugged
finding.

### What a blocklist hit is keyed on

The directory's `malicious`/`unsafe` tags are keyed on the **issuer address**:
StellarExpert made the association between an address and its reputation, so a
directory hit needs no further corroboration to escalate.

The malicious-domain blocklist is keyed on a **domain**, and the only domain
Assay has is the issuer's advertised `home_domain` — a free-text field the
account controls. Using it as the escalation key has a false-positive and a
false-negative face, and the decision below was made with both in view.

| State | What Assay sees | What it does |
| --- | --- | --- |
| verified | blocklist hit on a domain whose `stellar.toml` reciprocally claims this asset | escalates to critical |
| unverified | blocklist hit on a domain that has not claimed this asset | escalates to critical, with the unverified link stated in the finding's reasoning |
| missing | no `home_domain` at all | the lookup cannot be put; reputation is marked `undetermined` and the report names it |

**A hit on an unverified domain still escalates.** A blocklist entry is a
positive observation from a curated source — the same class of evidence as a
`malicious` directory tag — and this model never suppresses positive adverse
evidence. Requiring reciprocal verification before escalating was rejected
because it introduces a silent false negative: the recorded `REPO` scan
escalated *only* through the blocklist, on a domain whose toml did not resolve,
and a verification precondition would have dropped a real scam to `clear`.
Under-reporting risk is a security issue in this project; over-escalating a
legitimate issuer is not the mirror image, because an issuer whose advertised
domain is blocklisted is itself part of the finding. What the report adds is
honesty about the link: the escalation is stated *with the caveat that the
domain has not reciprocally claimed the asset*, so a reader is never handed an
unverified association presented as a confirmed one.

**No `home_domain` is a gap, not a clean result.** With no domain there is
nothing to key the lookup on, so the blocklist is never read. A hit would
escalate, which makes the reported severity a floor. The project's rule that
"we could not check" and "this is fine" must never render the same therefore
applies, and the reputation finding is marked `undetermined` — which also means
such a report is not attestable (`attest.FromReport` refuses it, exactly as it
does for an unreachable source). This is what closes the evasion the issue
raises: an issuer that clears `home_domain` to dodge the blocklist no longer
receives a clean, attestable verdict. The consequence is deliberate and stated:
an issuer that advertises no `home_domain` cannot be checked against the domain
blocklist, and therefore cannot be attested until the lookup can be keyed on
something else. Keying it on the directory's curated domain is the fix, and it
belongs to [#4](https://github.com/use-assay/Assay/issues/4) (directory domain
versus advertised domain) rather than to this decision.

## Rule 3: accountability is reported, never discounted

Reciprocal SEP-1 verification produces `verified`, `unverified`, or `unknown`.
It never moves severity.

Verifying who an issuer is does not reduce what they can do to your balance. It
tells you there is a named party to sue, complain about, or subpoena — which is
genuinely valuable, and is exactly why it gets its own field instead of being
dissolved into a number.

Live data makes the case better than argument does. Circle's USDC issuer
advertises `home_domain = circle.com`, and `circle.com/.well-known/stellar.toml`
returns **404** — on 2026-09-17 it answers with a 301 to `www.circle.com`, which
then returns 404. By SEP-1's own definition, the single most reputable regulated
stablecoin on Stellar failed reciprocal domain verification every time it was
checked (2026-08-10 through 2026-09-17). Had
accountability been wired into severity, USDC would have scored *worse* than a
scam asset that took ten minutes to publish a valid toml.

Assay reports this honestly — `accountability: unverified` — and does not
special-case it.

## Rule 4: do not double-count what the protocol requires

CAP-0035 makes `auth_revocable` a **precondition** for `auth_clawback_enabled`.
Setting clawback without revocable fails with
`SET_OPTIONS_AUTH_REVOCABLE_REQUIRED`, and revocable cannot be cleared while
clawback is set.

So "revocable AND clawback" is not a suspicious combination — it is the only
legal way to have clawback at all. Scoring the two as independent signals would
inflate every clawback asset for a reason the protocol mandates.

Severity is therefore the **highest single capability present**, not a sum.
Confirmed empirically: across 2,400 sampled live assets, exactly zero have
clawback without revocable.

## The levels

Each level is pinned to a specific capability, so the number is
self-documenting on-chain.

| | Level | Flag | What the issuer can do |
| --- | --- | --- | --- |
| 0 | `clear` | *(none)* | Nothing. No special power over holders. |
| 1 | `low` | `auth_required` | Decide who may open a trustline. Cannot touch existing holders. |
| 2 | `medium` | `auth_revocable` | Freeze an existing holder's balance in place. |
| 3 | `high` | `auth_clawback_enabled` | Confiscate and burn a balance, without the holder's signature. |
| 4 | `critical` | *(reputation)* | Reserved for escalation. Never produced by reading flags. |

## What unevaluated means

There is a fifth value on the Go side, `unevaluated`, and it is deliberately
not a level.

**`clear` means the issuer holds no powers — and that is a fact someone
established by reading the flags.** The ledger was asked, the answer came back,
and it said: no `auth_required`, no `auth_revocable`, no `auth_clawback_enabled`.

**`unevaluated` means the flags were never read at all.** No question was
asked, so no answer exists — including the answer "no powers". Collapsing the
two would put the ABI's safest value on a subject nobody assessed, which is
exactly the failure shape behind the bugs already found and fixed: a missing
answer silently rendering as the most permissive one.

In practice the live scanner cannot produce this state — it aborts the whole
scan when Horizon cannot find the asset (`internal/scan/scan.go`), so a
`Subject` with no flags on it only exists when one is built by hand. The value
exists anyway, at the type level, so that nothing can accidentally attest an
unread-flag report: such a finding carries `undetermined`, and
`attest.FromReport` refuses it with `ErrUnevaluated`.

`unevaluated` is not part of the on-chain ABI. It never serializes into an
attestation (see [the contract interface](contract-interface.md)), and the
contract's own range check would reject it as a second backstop. It also never
appears in eval expectations: an eval subject always has flags to read.

## What stale means

A verdict has three potential lifecycle states: **valid**, **unknown**, and **stale**.

- **`valid`** — A fresh, complete verdict. All required sources answered, flags were evaluated, and the observation is within the freshness policy window.
- **`unknown`** — A check could not conclude. Either a required source was unreachable (`undetermined`) or flags were never read (`unevaluated`).
- **`stale`** — The verdict was complete when made, but is now older than the policy window.

Assay learned this distinction through three related failure modes:
1. An unreachable source once rendered as a clean result (#23).
2. Clear doubled as not-evaluated (#32).
3. Stale was unrepresented off-chain, risking an expired verdict being consumed as currently safe (#57).

On-chain, the Soroban example gate already distinguished staleness via `Error::AttestationStale` (`#2`). Off-chain, `Report` now represents `state` (`"valid"`, `"unknown"`, `"stale"`) and `stale` (`true`/`false`) distinctly in JSON. A program reading the report can never confuse an expired clean report with a fresh one. Furthermore, `attest.FromReport` refuses any stale report (`ErrStale`), guaranteeing that an expired verdict cannot be attested as fresh.

`auth_immutable` is deliberately **not** a level. It is not a power over
holders; it fixes whether the power set can change. Which direction that cuts
depends entirely on what is already set:

- Locked with no dangerous flags — a genuine safety property. Clawback can never
  be added.
- Locked with clawback — permanent. The power can never be given up.

Assay reports this as its own finding — [`mutability`](checks.md#mutability) —
rather than scoring it, because a single number cannot carry a conditional.

## What severity does not tell you

**Whether the issuer will use the power.** Assay measures capability, not
intent. Nothing on the ledger reveals intent.

**Whether an existing holder is exposed.** Under CAP-0035 the trustline flag
`TRUSTLINE_CLAWBACK_ENABLED_FLAG` is set *when the trustline is created*.
Enabling clawback later does not reach trustlines that already exist.

Assay reports risk for a **prospective** holder — "what happens if I open a
trustline now" — which is what current issuer flags answer exactly. It is not a
claim about anyone's existing position. Checking an existing trustline's own
flags is [a separate check that does not exist yet](checks.md).

**That a `clear` asset is safe.** It means the *issuer* has no special power.
The asset can still be worthless, a rug pull by another mechanism, or an
outright impersonation. `DOGE-GA22IDJN…` in the eval set carries no auth flags
at all and is a known scam.

Assay scans one specific attack surface. It says so rather than implying
coverage it does not have.
- [Temporal Trust Model](temporal.md)
