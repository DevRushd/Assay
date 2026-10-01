# seq1 — capability addition

**Synthetic: true.** Constructed, not captured. The asset is the eval-set
subject whose shape this sequence borrows; it is not a record of that asset's
history. No sequence in this repository captures an issuer gaining a capability
between two scans, so this one is built to the shape
[docs/transitions.md](../../../../docs/transitions.md) describes for an addition
under CAP-0035: an issuer that could already freeze gains clawback, and
`base_severity` moves medium → high with it.

`mechanics` is the raw bitset and the severity fields are the ABI levels — see
[which bits are capabilities](../../../../docs/transitions.md#which-bits-are-capabilities)
and the [severity model](../../../../docs/severity-model.md).

| observation | at (UTC) | source |
| --- | --- | --- |
| `obs1.json` | 2026-09-01T00:00:00Z | synthetic: constructed for this fixture, shape per docs/transitions.md |
| `obs2.json` | 2026-09-08T00:00:00Z | synthetic: constructed for this fixture, shape per docs/transitions.md |
| `obs3.json` | 2026-09-15T00:00:00Z | synthetic: constructed for this fixture, shape per docs/transitions.md |
