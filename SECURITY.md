# Security policy

## Reporting a vulnerability

Report privately via [GitHub's security advisory form](https://github.com/use-assay/Assay/security/advisories/new),
or by email to deekhay7534@gmail.com.

Please do not open a public issue for anything in the first category below.

There is no bug bounty. Assay is an early open-source project and cannot
offer payment.

## What counts as a vulnerability here

Assay is not a service holding user data, so the usual list does not map
cleanly. What Assay produces is a **claim about whether someone's money can be
taken**, and a contract that gates on that claim. The security-relevant failures
are the ones that make a claim wrong in the dangerous direction.

[docs/threat-model.md](docs/threat-model.md) names the actors, what each can do,
and every attack class that is already known — defended, accepted as a bounded
risk, or out of scope, with the reason in each case. Read it before reporting:
a gap listed there as accepted is still worth a report if you think the accepted
reasoning is wrong, but it is not a discovery, and the answer will be the
reasoning rather than a fix.

### Critical: anything that under-reports risk

These are the bugs that matter most, because someone acts on the output.

- A scan reporting a severity **lower** than the issuer's flags justify.
- An asset whose issuer can confiscate (`auth_clawback_enabled`) classifying
  below `high`, or `ConfiscationMask` failing to imply `high`.
- Any path where attribution, reputation, age, or popularity **lowers** a
  severity. Severity is capability-only by design; a discount is a
  vulnerability, not a feature request. It would also create the obvious attack:
  buy attribution to get past a gate.
- `is_safe` returning `true` for an asset that is unattested, stale, or above
  the caller's threshold — any failure to fail closed.
- A forged or replayed attestation accepted by the registry.
- A parsing bug letting a stellar.toml claim an asset it does not issue, or
  letting a code-only match pass as reciprocal verification.

### Also in scope

- Severity **inflation** that is systematic rather than incidental. A scanner
  that cries wolf gets ignored, and an ignored scanner protects nobody.
- Presenting a consumed third-party signal as an Assay conclusion, or dropping
  the attribution and source URL from evidence.
- Displaying a value that was never fetched, or rendering a failed fetch as a
  clean result. "We could not check" and "this is fine" must never look the
  same.
- Injection through issuer-controlled content — asset codes, `home_domain`,
  stellar.toml fields, directory names — into the API response or the UI.
  Issuer-controlled strings are untrusted input.
- Denial of service in the fetch layer: unbounded reads, missing timeouts, or a
  hostile domain able to stall a scan.

### Out of scope

- **An asset being a scam that Assay rates `clear`.** Assay measures issuer
  trap mechanics, not fraud in general. An asset with no authorization flags
  genuinely gives its issuer no special power, and Assay says so; the asset can
  still be worthless or an impersonation. This is documented in
  [docs/severity-model.md](docs/severity-model.md#what-severity-does-not-tell-you)
  and there is a subject in the eval set for exactly this case.
- Accuracy of third-party data. StellarExpert's directory and blocklist are
  consumed and attributed, not curated by us. Report those upstream.
- An issuer changing its flags after a scan. Reports are point-in-time and carry
  a timestamp; the contract exposes `attested_at` so callers can set their own
  staleness policy.
- Missing checks. A mechanic Assay does not examine yet is a feature request —
  open an issue.

## Attester key

The testnet registry's entire write path is the single `assay-attester` key.
Where it lives, how it is backed up, what an attacker holding it can and
cannot do, and the response to loss or compromise are documented in
[docs/attester-key.md](docs/attester-key.md). A suspected key compromise that
produces under-reporting attestations counts as a critical report under the
policy above — report it privately first.

## Supported versions

Pre-1.0. Only `main` is supported; there are no maintained release branches.

## The contract is not deployed

`assay-contracts` has no testnet or pubnet deployment, so there is nothing live
to attack. Please still report design flaws in the ABI or the gate logic — the
value of finding them is highest before anything depends on them.

Known limitations, documented rather than hidden, in
[docs/contract-interface.md](docs/contract-interface.md#not-done-yet):
a single admin key can write any attestation, and `evidence_hash` has no
canonical encoding yet, so it cannot currently be verified independently.
The full list, with the direction each one fails in, is
[docs/threat-model.md](docs/threat-model.md).
