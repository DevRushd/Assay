# Debugging a surprising verdict

When Assay reports something unexpected for an asset, you need a systematic way to investigate why the scanner reached that conclusion. A surprising verdict usually stems from one of two root causes:

1. **"The source says so" (Correct-but-surprising)** — The live data source (Horizon, `stellar.toml`, or StellarExpert) actually contains the flag or state that triggered the verdict, even if it contradicts the reader's expectation.
2. **Code bug** — Assay's check misread or misinterpreted valid source data.

> [!IMPORTANT]
> If you discover a way to make Assay under-report risk, that is a security issue. Do not open a public issue — report it privately per [SECURITY.md](../SECURITY.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).

## Ground rules

- **Severity is capability-only**: Severity measures what the issuer *can* do to a holder's balance (consensus-enforced flags), not a prediction of intent, age, or reputation.
- **Never display a value you did not fetch**: Every finding is backed by attributed evidence lines containing exact URLs and retrieved timestamps.
- **Never re-derive a consumed signal**: Third-party reputation signals (StellarExpert directory and blocklists) are passed through as external evidence; Assay does not maintain its own scam lists.
- **Accountability is reported, never discounted**: Reciprocal domain verification (`verified`, `unverified`, `unknown`) informs a human and never lowers severity.

---

## Step 1: Reproduce and read the report (`./assay scan CODE-ISSUER`)

Run `./assay scan CODE-ISSUER` to generate the complete JSON report from a live scan:

```sh
./assay scan CODE-ISSUER
```

Examine the fields in the report:
- `severity` and `base_severity`: The assigned severity level (`clear`, `low`, `medium`, `high`, `critical`) and whether it was raised by reputation escalation.
- `accountability`: The reciprocal domain verification status (`verified`, `unverified`, `unknown`).
- `findings`: The list of findings produced by each check (`capability`, `mutability`, `sep1-domain`, `reputation`), including their prose reasoning and assigned mechanics.
- `evidence`: The raw attributed evidence items, each containing a `source`, `url`, `claim`, and `retrieved_at` timestamp.

### Worked example (Captured 2026-09-28)

Run `./assay scan` for USDC (`USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`):

```sh
./assay scan USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

Captured output:

```json
{
  "asset": {
    "code": "USDC",
    "issuer": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
  },
  "severity": "medium",
  "base_severity": "medium",
  "escalated": false,
  "accountability": "unverified",
  "state": "valid",
  "stale": false,
  "undetermined": false,
  "undetermined_checks": [],
  "checks": [
    "capability",
    "mutability",
    "reputation",
    "sep1-domain"
  ],
  "mechanics": [
    "auth_revocable",
    "domain_unverified"
  ],
  "findings": [
    {
      "check": "capability",
      "title": "Issuer capability",
      "severity": "medium",
      "escalation": false,
      "undetermined": false,
      "reasoning": "The issuer can freeze your balance so you cannot move it (auth_revocable). ",
      "mechanics": [
        "auth_revocable"
      ],
      "evidence": [
        {
          "source": "horizon",
          "url": "https://horizon.stellar.org/assets?asset_code=USDC\u0026asset_issuer=GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
          "claim": "issuer flags: auth_required=false auth_revocable=true auth_immutable=false auth_clawback_enabled=false",
          "retrieved_at": "2026-09-28T14:16:06.786753523Z",
          "attempted": false
        }
      ]
    },
    {
      "check": "mutability",
      "title": "Issuer flag mutability",
      "severity": "clear",
      "escalation": false,
      "undetermined": false,
      "reasoning": "The issuer's flag set is not locked (auth_immutable is unset), so it can still change. The issuer can freeze an existing holder's balance (auth_revocable) today, and it may give that power up, or add another, later. Under CAP-0035 a flag added later applies only to trustlines opened after the change — it does not reach a trustline that already exists — so this verdict is correct for a trustline opened now but is not guaranteed to stay correct for one opened later. Severity is unchanged; mutability is reported, not scored.",
      "mechanics": [],
      "evidence": []
    },
    {
      "check": "sep1-domain",
      "title": "Issuer domain verification",
      "severity": "clear",
      "escalation": false,
      "undetermined": false,
      "reasoning": "The issuer advertises home_domain \"circle.com\", but its stellar.toml could not be read (sep1: fetch https://circle.com/.well-known/stellar.toml: status 404). The domain claim is unverified: anyone can set home_domain to any value, so an unreachable toml proves nothing about who issued this.",
      "mechanics": [
        "domain_unverified"
      ],
      "accountability": "unverified",
      "evidence": [
        {
          "source": "stellar.toml",
          "url": "https://circle.com/.well-known/stellar.toml",
          "claim": "not retrievable: sep1: fetch https://circle.com/.well-known/stellar.toml: status 404",
          "retrieved_at": "2026-09-28T14:16:07.164190056Z",
          "attempted": true
        }
      ]
    },
    {
      "check": "reputation",
      "title": "Curated reputation signals",
      "severity": "clear",
      "escalation": true,
      "undetermined": false,
      "reasoning": "Curated sources returned data for this issuer and none of it flags the issuer as malicious. Recorded as attributed evidence only: it does not lower the capability severity, because a named issuer holds the same power over your balance as an anonymous one.",
      "mechanics": [],
      "evidence": [
        {
          "source": "stellar.expert/directory",
          "url": "https://api.stellar.expert/explorer/directory/GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
          "claim": "listed as \"Centre\" (domain \"centre.io\", tags: anchor, issuer)",
          "retrieved_at": "2026-09-28T14:16:08.875742985Z",
          "attempted": false
        },
        {
          "source": "stellar.expert/blocked-domains",
          "url": "https://api.stellar.expert/explorer/directory/blocked-domains/circle.com",
          "claim": "domain \"circle.com\" blocked=false",
          "retrieved_at": "2026-09-28T14:16:08.726540741Z",
          "attempted": false
        }
      ]
    }
  ],
  "evidence": [
    {
      "source": "horizon",
      "url": "https://horizon.stellar.org/assets?asset_code=USDC\u0026asset_issuer=GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
      "claim": "issuer flags: auth_required=false auth_revocable=true auth_immutable=false auth_clawback_enabled=false",
      "retrieved_at": "2026-09-28T14:16:06.786753523Z",
      "attempted": false
    },
    {
      "source": "stellar.toml",
      "url": "https://circle.com/.well-known/stellar.toml",
      "claim": "not retrievable: sep1: fetch https://circle.com/.well-known/stellar.toml: status 404",
      "retrieved_at": "2026-09-28T14:16:07.164190056Z",
      "attempted": true
    },
    {
      "source": "stellar.expert/directory",
      "url": "https://api.stellar.expert/explorer/directory/GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
      "claim": "listed as \"Centre\" (domain \"centre.io\", tags: anchor, issuer)",
      "retrieved_at": "2026-09-28T14:16:08.875742985Z",
      "attempted": false
    },
    {
      "source": "stellar.expert/blocked-domains",
      "url": "https://api.stellar.expert/explorer/directory/blocked-domains/circle.com",
      "claim": "domain \"circle.com\" blocked=false",
      "retrieved_at": "2026-09-28T14:16:08.726540741Z",
      "attempted": false
    }
  ],
  "scanned_at": "2026-09-28T14:16:05.461780023Z"
}
```

---

## Step 2: Check the attributed evidence URLs against live sources

Fetch each evidence URL cited in the report directly (using `curl` or a browser) to inspect what the live upstream source returns:

1. **Horizon asset endpoint**: Open the URL cited in the `horizon` evidence line to verify the raw flag booleans.
2. **`stellar.toml` URL**: Query the exact URL cited in the `stellar.toml` evidence line. Check the HTTP status code and response body.
3. **StellarExpert endpoints**: Check the directory and blocklist response JSONs for the issuer address and home domain.

### Worked example (Captured 2026-09-28)

To check why USDC scored `accountability: unverified`, query the cited `stellar.toml` evidence URL directly:

```sh
curl -i -L https://circle.com/.well-known/stellar.toml
```

Captured output:

```http
HTTP/2 301 
date: Mon, 28 Sep 2026 14:16:44 GMT
content-type: text/html; charset=UTF-8
location: https://www.circle.com/.well-known/stellar.toml

HTTP/2 404 
date: Mon, 28 Sep 2026 14:16:45 GMT
content-type: text/html; charset=utf-8
```

The response is an HTTP 404 error from `circle.com` (redirecting to `www.circle.com`).

---

## Step 3: Decide where the disagreement lives

Compare the live source data with Assay's report to isolate the cause:

- **The source says so (Correct-but-surprising)**: The live data source actually has the flag or state recorded in the evidence line. Assay's verdict matches what the source provided, even if that surprises the reader. The answer is **"the source says so"**, not a bug in Assay.
- **Code bug**: The live source data is valid and clean, but Assay's check misread a field, incorrectly parsed a payload, or misapplied a severity level rule.
- **Stale attestation**: The live scan produces a different verdict than what is stored on-chain because the issuer changed flags after the attestation was written. (Check `attested_at` against current time).

### Worked example (USDC verdict breakdown)

Readers are often surprised that USDC scores `severity: medium` and `accountability: unverified`:

1. **Why `severity: medium`?** Horizon reports `auth_revocable=true` for issuer `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`. Under Rule 1 of the [severity model](severity-model.md), severity is capability-only: `auth_revocable` allows freezing balances, which maps to `medium`. Reputation cannot lower this severity.
2. **Why `accountability: unverified`?** The evidence line cites `https://circle.com/.well-known/stellar.toml`, which returns HTTP 404. Reciprocal domain verification requires a matching `stellar.toml`. Because the file returns 404, reciprocal verification fails.

The evidence lines prove that **the source says so**. The result is correct-but-surprising, not a code bug.

---

## Step 4: Look at what was hashed and what's on-chain (`./assay attestation` and `make read`)

To inspect how the report maps to an on-chain attestation:

1. **Inspect `attest()` arguments**: Run `./assay attestation -raw CODE-ISSUER` to view the `severity`, `flags` bitset, and `evidence_hash` produced by the scan.
2. **Inspect the preimage**: Run `./assay attestation -preimage CODE-ISSUER` to view the canonical text preimage hashed to produce `evidence_hash`.
3. **Read on-chain state**: Run `make read ASSET=CODE-ISSUER` to query the deployed Soroban safety registry via `get_safety`.

> [!NOTE]
> `make read ASSET=CODE-ISSUER` requires the `stellar` CLI binary installed and network access to Stellar testnet. On environments without the `stellar` CLI installed, `make read` fails with `/bin/sh: stellar: not found`.

### Worked example (Captured 2026-09-28)

Run `./assay attestation -raw` for USDC:

```sh
./assay attestation -raw USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

Captured output:

```
2	18	d9f2c2ce9542299ab57a2873b25fc121f3bafd0ee560afae1a5da61ae5a7dc3d
```

Run `./assay attestation -preimage` for USDC:

```sh
./assay attestation -preimage USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

Captured output:

```json
{
  "asset": {
    "code": "USDC",
    "issuer": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
  },
  "severity": 2,
  "severity_name": "medium",
  "flags": 18,
  "mechanics": [
    "auth_revocable",
    "domain_unverified"
  ],
  "checks": [
    "capability",
    "mutability",
    "reputation",
    "sep1-domain"
  ],
  "evidence_hash": "d9f2c2ce9542299ab57a2873b25fc121f3bafd0ee560afae1a5da61ae5a7dc3d",
  "scanned_at": "2026-09-28T14:17:21Z",
  "preimage": "assay-evidence-v2\nasset\tUSDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN\nseverity\t2\nbase_severity\t2\nescalated\tfalse\nmechanics\t18\naccountability\tunverified\nchecks\tcapability,mutability,reputation,sep1-domain\nevidence\thorizon\thttps://horizon.stellar.org/assets?asset_code=USDC\u0026asset_issuer=GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN\tissuer flags: auth_required=false auth_revocable=true auth_immutable=false auth_clawback_enabled=false\nevidence\tstellar.expert/blocked-domains\thttps://api.stellar.expert/explorer/directory/blocked-domains/circle.com\tdomain \"circle.com\" blocked=false\nevidence\tstellar.expert/directory\thttps://api.stellar.expert/explorer/directory/GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN\tlisted as \"Centre\" (domain \"centre.io\", tags: anchor, issuer)\nevidence\tstellar.toml\thttps://circle.com/.well-known/stellar.toml\tnot retrievable: sep1: fetch https://circle.com/.well-known/stellar.toml: status 404\n"
}
```

When run on a host with `stellar` CLI and testnet access, `make read ASSET=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN` returns the stored record from `get_safety`:

```
USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN -> CA5ZSEJY...
severity 2, flags 18, evidence_hash d9f2c2ce...
```

---

## Step 5: Decide bug vs. correct-but-surprising, and what to do next

Once you have isolated the cause:

1. **If the verdict is correct-but-surprising ("The source says so")**:
   - The scanner worked correctly. Explain to the user or contributor that Assay reports facts from live ledger and domain sources, and does not alter severity based on reputation or brand recognition.
2. **If it is a code bug**:
   - File a bug issue on GitHub describing the discrepancy between the live source evidence and Assay's verdict. Include the captured `./assay scan` JSON output and live `curl` outputs.
3. **If it is a security vulnerability (under-reporting risk)**:
   - If the bug causes Assay to report a severity *lower* than the issuer's flags justify, or fails to fail closed, **do not open a public issue**. Follow [SECURITY.md](../SECURITY.md) and report it privately.
