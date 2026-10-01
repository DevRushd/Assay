# seq3 — evidence-only change

**Synthetic: true.** Constructed, not captured. The issuer's advertised domain
is initially unreachable (`domain_unverified` set, `mechanics 18`) and later
serves a stellar.toml that claims the asset, so the bit clears (`mechanics 2`).

The capability bits, `base_severity` and `severity` are identical on both
sides — the only thing that moved is evidence about who the issuer is, which is
exactly what the reported-only bits carry
([which bits are capabilities](../../../../docs/transitions.md#which-bits-are-capabilities)).

The detectors must report no capability addition, no capability removal and no
severity movement, while the pair kept whole still shows that something did
move: an empty capability difference with `valid` state is "we looked and
nothing moved", and here the capability half really is unchanged even though
the observations differ.

| observation | at (UTC) | source |
| --- | --- | --- |
| `obs1.json` | 2026-09-01T00:00:00Z | synthetic: constructed for this fixture, domain unreachable |
| `obs2.json` | 2026-09-08T00:00:00Z | synthetic: constructed for this fixture, domain serves a claiming toml |
