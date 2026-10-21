# seq4 — no-change pair (real)

**Synthetic: false — captured from on-chain attestation records.** This is the
genuine no-change pair recorded in
[docs/attestation-run.md](../../../../docs/attestation-run.md): `DOGE-GA22IDJN…`
was attested from a live scan on 2026-09-05 and re-attested from a live scan on
2026-09-16, and the re-scan reproduced `evidence_hash 396c9f7c…91647e`
exactly — only the timestamp moved.

On-chain records agree at both observations: `severity 4`, `flags 48`
(`domain_unverified` | `blocklisted`), base severity clear — no capability bit
is set, so all of `severity 4` is reputation. `mechanics` here is those flags
as the report computes them; the severity fields are the ABI levels.

| observation | at (UTC) | source |
| --- | --- | --- |
| `obs1.json` | 2026-09-05T07:23:02Z | https://stellar.expert/explorer/public/tx/ac1a89a64159e6ac2e9ed61bd67a79cd1584287cf57d19f9dc188d80e81298a6 |
| `obs2.json` | 2026-09-16T08:12:22Z | https://stellar.expert/explorer/public/tx/5012431be06a49f0bdc9b77e274aafaafabc6b30f6a5de535616050617ccd64c |
