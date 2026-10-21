synthetic-reputation-outage — degraded reputation fixture

Not a live subject. Built 2026-09-27 by copying the payload files of
aqua-clear-verified (captured 2026-08-10, URLs in PROVENANCE.md) and adding an
error marker:

    blocked.err    "429" — the blocked-domains endpoint answered HTTP 429

The payloads are real captures; only the error state is constructed. The
resulting subject is a clean asset (no auth flags, reciprocal domain, benign
directory entry) whose malicious-domain blocklist lookup was consulted and
failed. That is the point: this directory exists to exercise the
degraded-scan path from the labelled corpus (#111), which a missing
blocked.json cannot express, because a missing file means only "the source was
not captured" and the loader cannot tell it from "the source was not asked".

The base payloads deliberately come from a clean, fully-answered subject, not
from DOGE: a fixture whose directory entry carries the malicious tag would
escalate to critical regardless of the blocklist outage, because a positive
listing decides the question at the severity ceiling. The degraded property
under test — an outage that must render as undetermined, never as "not
listed" — is only observable when no positive signal is present.

The directory name carries the `synthetic-` prefix used by
synthetic-flag-disagreement: it marks a fixture assembled for a property under
test rather than captured from a real asset, so no one mistakes its severity
numbers for a live measurement of any asset. The 429 mirrors the real
rate-limit response documented in docs/eval.md and in the hand-built
degraded-scan tests.
