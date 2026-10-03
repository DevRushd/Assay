# Adding a check

A practical guide to writing a new mechanic check. Read
[the severity model](severity-model.md) first — most review feedback on new
checks is about judgment, not code.

## The one rule: checks do no I/O

Everything a check needs is fetched **once, up front**, by
[`internal/scan`](../internal/scan/scan.go) into a `Subject`. A check is then a
pure function from `Subject` to `Finding`.

```
scan.Scanner.Subject()   ← the only place a scan touches the network
        ↓  *mechanics.Subject
mechanics.Engine.Run()   → runs every Check, aggregates into a Report
```

This buys three things, and all three are load-bearing:

- Checks are deterministic and testable from fixtures with **no network**, so CI
  cannot go red because a third-party API had a bad day, nor green because one
  silently changed.
- Each fetcher stays in its own package with a clean signature, so it can be
  extracted later without untangling judgment logic from transport.
- A check *cannot* quietly add a network dependency, because it has nowhere to
  put one.

If your check needs data that isn't in `Subject` yet, add the fetch to
`internal/scan` and the field to `Subject`. Do not fetch from inside `Run`.

## The interface

From [`internal/mechanics/mechanics.go`](../internal/mechanics/mechanics.go):

```go
type Check interface {
	// ID is the stable identifier used in reports and issue tracking.
	ID() string
	// Describe states what the check concludes, and what it does not.
	Describe() string
	// Run classifies the subject.
	Run(ctx context.Context, s *Subject) (Finding, error)
}
```

`Describe()` must state the limits, not just the capability. "Says nothing about
who the issuer is" is the kind of sentence that belongs there — it is what stops
a caller over-reading the result.

### What `Subject` gives you

```go
type Subject struct {
	Asset           Asset
	Stat            *horizon.AssetStat // asset record, incl. Flags
	StatFetchedAt   time.Time          // when Horizon answered /assets
	Issuer          *horizon.Account   // issuer account, incl. Flags + HomeDomain
	IssuerFetchedAt time.Time          // when Horizon answered /accounts

	Toml            *sep1.Doc  // nil if it did not resolve; carries its own FetchedAt
	TomlURL         string
	TomlErr         string     // why it did not, verbatim
	TomlRefused     bool       // TomlErr is a host-policy refusal, not an outage
	TomlAttemptedAt time.Time  // when the fetch was attempted
	TomlLinked      *sep1.LinkedResolution // per-currency links followed; nil if none

	Directory            *stellarexpert.DirectoryEntry
	DirectoryURL         string
	DirectoryErr         string
	DirectoryFetchedAt   time.Time // when the source answered
	DirectoryAttemptedAt time.Time // when it was asked
	Blocked              *stellarexpert.BlockedDomain
	BlockedURL           string
	BlockedErr           string
	BlockedFetchedAt     time.Time
	BlockedAttemptedAt   time.Time
	BlockedSkipped       string     // set when no domain existed to key the lookup on

	ScannedAt time.Time // when the scan started
}
```

Every fetch records **its own** completion time, and every failed fetch records
its attempt time. Stamp evidence from the field matching the source the claim is
attributed to — never from a shared scan-start timestamp: a StellarExpert answer
that arrived twenty seconds after the Horizon one must not report Horizon's
instant. Failure evidence (`"not retrievable: …"`) carries the attempt time and
sets `Evidence.Attempted = true`, so a program can tell an attempt from an
answer without parsing the claim.

Any pointer field can be `nil`. Handle it explicitly — a missing source is not a
clean result. **"We could not check" and "this is fine" must never render the
same.**

## Where files go

| Thing | Location |
| --- | --- |
| Your check | `internal/mechanics/check_<name>.go` |
| Registration | `NewEngine()` in `internal/mechanics/mechanics.go` |
| Severity / mechanic bits | `internal/mechanics/severity.go` |
| Fixtures | `internal/mechanics/testdata/<case-name>/` |
| Eval cases | `internal/mechanics/eval_test.go` |

Use [`check_capability.go`](../internal/mechanics/check_capability.go) as the
template for a check that sets severity, and
[`check_domain.go`](../internal/mechanics/check_domain.go) for one that sets
accountability without touching severity.

## The severity rules your check must respect

Full reasoning in [docs/severity-model.md](severity-model.md). The short form:

**Severity is capability-only.** It answers "what can the issuer do to my
balance?" and is derived from authorization flags and nothing else. Two assets
whose issuers hold identical power must classify identically, however well
attributed one of them is. A test enforces this directly.

**Reputation escalates, never discounts.** Set `Finding.Escalation = true` and
the engine will only let that finding *raise* the level. Nothing may lower a
severity — a discount is treated as a security bug, because it would let someone
buy their way past the on-chain gate.

**Accountability is a separate field.** If your check establishes who is behind
an asset, set `Finding.Accountability` and leave `Severity` at `Clear`.

**Don't double-count protocol preconditions.** CAP-0035 makes `auth_revocable` a
precondition for `auth_clawback_enabled`, so scoring both would inflate every
clawback asset for a reason the protocol requires. Severity is the highest
single capability, not a sum.

**Reasoning always states the raw capability**, whatever the level works out to.
A reader is never given a number without being told what the issuer can actually
do.

### Evidence must be attributed

Consumed signals enter only as `Evidence{Source, URL, Claim, RetrievedAt}`.
Attribution is structural: because the only way to surface an outside claim is
to construct an `Evidence` carrying its source URL, there is no code path that
renders someone else's data as an Assay conclusion.

**Never re-derive a consumed signal.** StellarExpert's directory, ratings, and
blocklist are inputs. If you find yourself writing a scam heuristic over domain
names, stop — that layer exists and is better maintained than anything we would
write.

## Capturing a fixture

A fixture is evidence, so it has to be re-fetchable: someone else must be able
to pull the same URL and get the same answer. Capture from live public sources
into `internal/mechanics/testdata/<case-name>/`. A **subject** is the directory;
the files inside it are the per-source records below. Name the directory for the
case it pins (`usdc-revocable-regulated`), not the asset code alone.

### What a subject contains

| File | Source URL | When to include it |
| --- | --- | --- |
| `asset.json` | `https://horizon.stellar.org/assets?asset_code=<CODE>&asset_issuer=<ISSUER>` | always |
| `account.json` | `https://horizon.stellar.org/accounts/<ISSUER>` | always |
| `stellar.toml` | `https://<home_domain>/.well-known/stellar.toml` | the toml resolves |
| `stellar.toml.status` | same URL as above | the toml does **not** resolve |
| `directory.json` | `https://api.stellar.expert/explorer/directory/<ISSUER>` | StellarExpert returns an entry |
| `blocked.json` | `https://api.stellar.expert/explorer/directory/blocked-domains/<home_domain>` | the issuer has a `home_domain` |

- `<CODE>` and `<ISSUER>` are the two halves of the asset's `CODE-ISSUER`.
- `<home_domain>` is the `home_domain` field of the **`account.json` you just
  captured**, not the domain you expect it to be.
- `stellar.toml` and `stellar.toml.status` are mutually exclusive: exactly one
  of them exists in a subject whose issuer publishes a `home_domain`.

The loader, [`internal/eval/load.go`](../internal/eval/load.go), reads these
files with the same decoders the live fetchers use. So a fixture that parses in
the test is one the real client would have accepted. It also means the failure
mode to watch for is silence: a file the loader does not expect, or a missing
one, does not raise — it produces a `Subject` with that source `nil`. Handle
the error cases below instead of letting a gap render as a clean result.

### Fetching the records

Fetch every source for a subject in one sitting, so the files describe one point
in time. Save the response body byte-for-byte under the file name above:

```sh
DIR=internal/mechanics/testdata/<case-name>
mkdir -p "$DIR"

curl -fsS "https://horizon.stellar.org/assets?asset_code=<CODE>&asset_issuer=<ISSUER>" -o "$DIR/asset.json"
curl -fsS "https://horizon.stellar.org/accounts/<ISSUER>"                                    -o "$DIR/account.json"
curl -fsS "https://api.stellar.expert/explorer/directory/<ISSUER>"                            -o "$DIR/directory.json"
curl -fsS "https://api.stellar.expert/explorer/directory/blocked-domains/<home_domain>"       -o "$DIR/blocked.json"
curl -fsS "https://<home_domain>/.well-known/stellar.toml"                                    -o "$DIR/stellar.toml"
```

- Do not reformat the responses, reorder keys, or trim the toml. The one
exception is a toml that is large for reasons unrelated to the subject: it may
be abridged to the entries that matter, with the abridgement stated in the
provenance row (see `usdz-clawback-regulated` in `PROVENANCE.md`). When in
doubt, keep the whole file.
- `blocked.json` is a positive answer even when it is
`{"domain":"…","blocked":false}` — the domain was checked and is not blocked.
Keep it.
- A StellarExpert directory lookup that answers **404 (not listed)** is an
answer, so there is no `directory.json` to write. That is different from the
source erroring, below.

### When a source errors at capture time

A source that fails is recorded as a failure, never dropped: an omitted file
reads as "not asked" (or, for reputation, "not listed"), which can be the
opposite of what happened.

- **The issuer toml does not resolve.** This is the case the `.status`
  convention exists for. Write the HTTP status code into `stellar.toml.status`
  — `404` when the server answered that, or `000` when the request never
  completed (DNS failure, connection refused, timeout; `curl` exit 6, 7 or 28).
  Write the number alone, no body, and do not also write `stellar.toml`. The
  loader turns it into `TomlErr = "status 404"`, which is what the live fetcher
  reports, so the check sees "asked and failed" rather than "never asked".
  Existing examples: `usdc-revocable-regulated` (404), `doge-noflags-scam`
  (000).
- **Horizon `/assets` or `/accounts` errors.** There is no subject without
  them — the ledger record is the capability read, and inventing one would be
  exactly the placeholder CONTRIBUTING.md forbids. Re-capture when the source is
  back; do not commit a directory missing either file.
- **StellarExpert directory or blocked-domains errors (as opposed to answering
  "not listed").** The loader currently has no `.status` channel for these: an
  absent `directory.json` and a failed lookup both produce a `nil` source with
  no error. So do not silently omit an errored lookup. Retry the capture, and if
  the source stays down, leave the subject out of the corpus until it answers —
  note the gap in the PR rather than committing a partial subject. Giving these
  sources the same `.status` treatment as the toml is capture tooling, tracked
  separately.
- Either way, the failure is part of the provenance row below, including the
  status code when you wrote a `.status` file.

### Recording provenance

Two records are updated together, in the same commit:

1. [`internal/mechanics/testdata/PROVENANCE.md`](../internal/mechanics/testdata/PROVENANCE.md)
   — append one row per file, `<case-name>/<file>` → the exact URL it came from.
   Annotate the row with `(HTTP 404)` for a `.status` file and with
   `(captured YYYY-MM-DD)` when the subject's capture date is not the table's
   default. State any toml abridgement here.
2. [`internal/mechanics/testdata/manifest.json`](../internal/mechanics/testdata/manifest.json)
   — add the subject to `subjects[]`: `fixture` (directory name), `asset`
   (`CODE-ISSUER`), `label` (`legitimate` or `trap`), the measured
   `base_severity`, `severity`, `escalated`, `accountability` and `mechanics`,
   `capture_date` in UTC, every `source_urls` entry from the table above, and a
   `notes` string when the label needs justifying. The label criteria and the
   refresh pipeline are in
   [docs/eval.md](eval.md#dataset-labeling-and-refresh); never overwrite an old
   capture without preserving its date and provenance.

A subject is not ready until both records exist and the loader replays it. Then
add the eval case as described in the next section, and see
["Adding a subject"](eval.md#adding-a-subject) in `docs/eval.md` for the labelled
set's own rules.

## The eval is not optional

**A check whose judgment isn't evaluated against the labelled set doesn't ship.**

Detecting a flag is deterministic and uninteresting. What the eval measures is
whether the model separates a trap from a legitimate compliance feature. So
every new check adds **at least two** subjects to `TestEval`:

1. One asset that should trip it.
2. One asset with the **same mechanics used legitimately** that must not be
   over-flagged.

Point 2 is the whole discipline. Any check can find `auth_revocable: true`; the
reason to have a check is that it knows when that is fine.

Each case carries a `why` string stating what it proves. It is printed on
failure, so a future maintainer learns what they broke rather than just seeing a
number change.

```go
{
	dir:          "your-case-name",
	why:          "what this subject proves and why it is labelled this way",
	wantBase:     mechanics.Medium,   // capability only, pre-escalation
	wantSeverity: mechanics.Medium,   // after escalation
	wantEscalated: false,
	wantAccount:  mechanics.AccountabilityVerified,
},
```

Then record the result and the reasoning in [docs/eval.md](eval.md).

### Verifying the eval

After adding a subject, run `make eval` and confirm the confusion matrix
shows agreement for the new subject's severity level and checks. See the
**Running the evaluation** section in [docs/eval.md](eval.md) for how to
interpret the output. A disagreement may indicate the label is wrong
rather than the code — check the provenance before assuming the classifier
is at fault. See the section on **A disagreement may indicate a wrong label**
in [docs/eval.md](eval.md).

## Verify before you encode

**Never encode a flag name, field name, or endpoint you did not verify against a
live source.** Not from memory, not from an LLM, not from a blog post.

```sh
curl "https://horizon.stellar.org/assets?asset_code=USDC&asset_issuer=GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
curl "https://api.stellar.expert/explorer/directory/<ADDRESS>"
```

Protocol semantics come from the specs themselves —
[CAP-0035](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0035.md)
for clawback, [SEP-0001](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md)
for stellar.toml. Both have caught real errors in this codebase: that
`auth_revocable` is a *precondition* for clawback, and that a `CURRENCIES` entry
may be a bare link to another toml.

Cite what you verified in the PR.

## Checklist

```sh
make test    # go test -race ./...
make lint    # golangci-lint
make fmt     # gofmt -w .
```

- [ ] Check implements `ID`, `Describe`, `Run`; `Describe` states its limits
- [ ] No I/O in `Run`; new data added to `Subject` via `internal/scan`
- [ ] `nil` source fields handled; failures reported, not smoothed
- [ ] Registered in `NewEngine()`
- [ ] Severity capability-only; escalation-only findings set `Escalation: true`
- [ ] Consumed signals attributed as `Evidence` with source URL
- [ ] Reasoning states the raw capability
- [ ] Fixtures captured per [Capturing a fixture](#capturing-a-fixture), provenance recorded in `PROVENANCE.md` and `manifest.json`
- [ ] Eval subjects for a true positive **and** a legitimate use
- [ ] `docs/eval.md` updated
- [ ] Live-source verification cited in the PR
