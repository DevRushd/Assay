# Severity and accountability are separate

Assay must never emit a single blended, combined, or composite score for
severity and accountability. Every API and UI surface must present the two
axes as independent values:

- **Severity** describes issuer capability over a holder's balance.
- **Accountability** describes whether an identifiable party publicly stands
  behind the asset.

The parameters travel concurrently in every result. A response that omits one
axis is incomplete, and accountability must never be used as a severity
discount or folded into a severity label. `base_severity` and `escalated` must
also remain available wherever escalation is reported so the capability
baseline and reputation transition stay auditable.

This document governs both machine-readable API envelopes and rendered UI.
The codebase license remains Apache-2.0; this is a behavioral contract, not a
separate license grant.