# Temporal Trust Model

An attestation in Assay says what was true at one instant in time. It asserts the state of an asset's capabilities and accountability at the exact moment of observation.

It does **not** assert what is true now, and it does not say for how long the claim stays good. An attestation never renews itself, so after that instant whether it may still be relied on is the caller's decision: `attested_at` is exposed and the caller passes `max_age_secs`. See [Freshness] for the policy itself — who decides how old is too old, what can change under an attestation, and how often it does — and [Staleness is the caller's policy](./contract-interface.md#staleness-is-the-callers-policy) for why freshness is a parameter rather than a contract constant.

A capability removal does not undo past exposure. If a freeze capability existed yesterday, the asset's history carries that risk even if the flag is cleared today. Assay's comparisons report a removal as a fact about what the issuer can do from here on, never as a statement that earlier exposure has been cancelled.

Assay's history is a record of Assay's own observations over time, not a playback of the ledger's history. The ledger between two observations is invisible, so an unchanged pair means "Assay saw no change when it looked", not "nothing changed". Freshness is the caller's policy for the same reason: Assay records when it looked, and only the caller can say whether that is recent enough.
