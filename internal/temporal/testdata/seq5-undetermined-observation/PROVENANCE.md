# seq5 — undetermined observation

**Synthetic: true.** Constructed from the real failure recorded as
[Finding 1](../../../../docs/attestation-run.md#finding-1) in the attestation run:
a StellarExpert outage mid-sweep, where the reputation source did not answer
and the scan was refused rather than reported clean. The first observation is
that partial answer — `undetermined: true`, `reputation` named — and the second
is the completed scan of the same asset the next day.

A sequence containing an undetermined observation is a legitimate test case:
the transition between these two must come back `unknown`, never "no change"
and never a derived difference, because what the outage hid could have been
exactly the change being asked about.

| observation | at (UTC) | source |
| --- | --- | --- |
| `obs1.json` | 2026-09-16T12:00:00Z | synthetic: modelled on docs/attestation-run.md#finding-1 (StellarExpert outage during the 2026-09-16 sweep) |
| `obs2.json` | 2026-09-17T12:00:00Z | synthetic: modelled on docs/attestation-run.md#finding-1 |
