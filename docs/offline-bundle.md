# Offline verification bundles

An attestation answers two questions that a fresh scan cannot separate:

1. **Was this `evidence_hash` computed from this evidence?** A fact about the
   attestation, and one that must remain checkable forever.
2. **Is the evidence still current?** A fact about the issuer today, and one
   that legitimately changes when a domain moves, a flag changes, or a source
   is temporarily unavailable.

A re-scan answers (2), but when it diverges from the stored hash it cannot say
whether the evidence changed or the original hash was never honest. An offline
bundle preserves what the scanner actually read, so a verifier can answer (1)
without a network, without a fresh scan, and without trusting the attester.

This document specifies the bundle written by `assay attestation -bundle` and
checked by `assay verify -bundle` (issue #465).

## Commands

```sh
# Write the bundle while deriving the on-chain arguments.
./assay attestation -bundle attestation.tar.gz CODE-ISSUER

# Later, anywhere, with no network:
./assay verify -bundle attestation.tar.gz
./assay verify -bundle attestation.tar.gz -json
```

`verify -bundle` exits 0 when every check passes, 1 when a file or digest does
not match, and 4 when the archive cannot be opened. An unreadable archive is
not a mismatch: nothing was verified.

## Format

The bundle is a gzip-compressed tar with a fixed, deterministic layout:

| Path | Contents |
| --- | --- |
| `manifest.json` | format version, asset, scanner identity, digest, file digests and response index |
| `report.json` | the report the attestation was derived from, as `assay scan` prints it |
| `preimage.txt` | the exact bytes `evidence_hash` commits to |
| `responses/<sha256>.body` | one raw upstream response body, named by its own SHA-256 |

Files are sorted by name, modes and modification times are fixed, and the gzip
header carries no filename or timestamp. Two bundles built from the same inputs
therefore differ only if their manifests differ, which keeps review diffs
meaningful.

Response bodies are addressed by digest, so the same response fetched twice is
stored once and a manifest entry cannot silently point at different bytes. A
source that failed has no body; the report's attributed evidence records the
failure, and the manifest carries a note rather than inventing an empty body.

Every file the manifest names is bound by a digest:

```json
{
  "version": 1,
  "created_at": "2026-10-20T12:00:00Z",
  "asset": "USDC-GA5Z…",
  "scanner": "v0.1.0",
  "digest": "<sha256 of preimage.txt>",
  "preimage": "preimage.txt",
  "report": "report.json",
  "report_sha256": "<sha256 of report.json>",
  "responses": [
    {
      "method": "GET",
      "url": "https://horizon.stellar.org/…",
      "status": 200,
      "content_type": "application/json",
      "path": "responses/<sha256>.body",
      "sha256": "<sha256 of the body>",
      "recorded_at": "2026-10-20T11:59:58Z"
    }
  ]
}
```

An unknown `version` is refused rather than guessed: a misread archive would
be a silently wrong verification.

## What verification checks

`verify -bundle`:

- hashes `preimage.txt` and compares it with `manifest.digest`;
- hashes `report.json` and compares it with `manifest.report_sha256`;
- hashes every response body and compares it with the manifest entry;
- parses the preimage header and compares its asset with the manifest;
- cross-checks the report's asset, severity, base severity, accountability,
  mechanics and (when bound) checks and network against the preimage.

The last cross-check catches an archive whose report was swapped for one
describing different evidence while the preimage was left untouched. The digest
alone would still match; the report would not.

## What it proves, and what it does not

**Proves:** the archived bytes are the bytes the manifest names, and they
produce the archived digest. If that digest equals the on-chain
`evidence_hash`, the attestation was derived from this evidence.

**Does not prove:**

- that the evidence was honest, complete or current — only that it is what was
  read;
- that an attestation exists on chain. The bundle carries no chain state; read
  `get_safety` separately if that is the question;
- that the scanner binary is trustworthy. Verify the binary first, as
  [verifying.md](verifying.md) step 0 describes;
- that the sources permitted redistribution of their response bodies. See the
  next section.

Freshness remains a separate check against `attested_at`. A perfectly verified
bundle can describe evidence from a year ago.

## Publishing and redistribution

A bundle contains third-party response bodies. The bundle's own manifest and
the Assay-authored report are Apache-2.0, but the archived bodies remain
subject to the terms of the source that served them:

| Source | What the bundle may contain |
| --- | --- |
| Stellar Development Foundation Horizon | ledger asset and account records, under the Stellar terms of service |
| StellarExpert | directory and blocked-domain records; check the current terms before redistributing a new raw copy |
| Issuer domains | the published `stellar.toml`, under the issuer's terms |

The same boundary is stated in
[`internal/mechanics/testdata/manifest.json`](../internal/mechanics/testdata/manifest.json):
the dataset licence covers the manifest and annotations, not the upstream
payloads. A bundle is therefore safe to keep privately, and safe to share when
the sources' terms allow it. When they do not, publish the preimage and digest
(which commit to the evidence) and the report, and keep the raw bodies
private — the verifier can still check the digest, but cannot inspect the
source bytes. Do not publish a bundle containing bodies whose terms forbid
redistribution.

Where bundles are published is deliberately not fixed here: a release asset, an
attestation-run archive and a private auditor's object store are all valid
choices with different retention and access rules. The format does not assume
one.
