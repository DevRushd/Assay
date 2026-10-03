# Package-level testing guide

Assay's tests come in three styles. They are not interchangeable: each is the
cheapest way to prove one kind of property, and reaching for the wrong one
produces a test that looks like it verifies something and does not. This guide
says which style each package uses, when each is appropriate, and where the
fixtures live.

Two rules from [CONTRIBUTING.md](../CONTRIBUTING.md) apply to all three:

- **Tests must not require network access.** Fetchers are interfaces; a test
  points them at a local `httptest.Server` or at a captured fixture. CI cannot
  go red because a third-party API had a bad day, nor green because one
  silently changed.
- **Fixtures come from real responses.** A body you invented can only prove
  the decoder agrees with your idea of the wire format, not with what the
  source actually sends.

## The three styles at a glance

| Style | What it proves | Where it lives |
| --- | --- | --- |
| **Recorded response bytes** over `httptest` | The client decodes what the source actually sends, and every transport outcome (404, 429, timeout, malformed body) is classified correctly. | `internal/horizon/client_test.go`, `internal/stellarexpert/client_test.go`, `internal/sep1/exhaustion_test.go`, `internal/scan/scan_test.go`, `internal/api/*_test.go` |
| **Hand-built subject/report** | Behaviour on states a captured response cannot represent: a fetch that failed, an impossible flag combination, aggregation and hash invariants. | `internal/mechanics/degraded_test.go`, `internal/mechanics/check_*_test.go`, `internal/mechanics/{escalation,stale,suppression,unevaluated}_test.go`; `internal/attest/*_test.go`; `internal/temporal/*_test.go`; `internal/history/store_test.go` |
| **Fixture-driven evaluation** | The *judgement*: does the severity model separate a trap from a legitimate compliance feature, and does escalation fire only on reputation? | `internal/mechanics/eval_test.go` via `internal/eval` and `internal/mechanics/testdata/`; golden vectors in `internal/attest/{golden,vectors}_test.go` via `internal/attest/testdata/vectors/` |

A package can use more than one. `internal/mechanics` uses style 2 and style 3;
`internal/attest` uses both as well. The choice is by *what the test is trying
to prove*, not by which is easier to write.

## Style 1 — Recorded response bytes over `httptest`

Use this when the subject under test is the wire: a fetcher, an HTTP handler,
or the transport layer beneath one. The assertion is about how the package
answers a real response.

`httptest.NewServer` replays captured bytes through the package's real HTTP
client, so both the decoder and the status/error handling are exercised:

```go
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{}`))
}))
t.Cleanup(srv.Close)
c := stellarexpert.New(srv.URL)
_, err := c.Directory(context.Background(), issuer) // must be an error, not a listing
```

The body is a response captured from the live source, with the capture date and
URL recorded in a comment at the top of the file (see
[`internal/stellarexpert/client_test.go`](../internal/stellarexpert/client_test.go)
and
[`internal/horizon/client_test.go`](../internal/horizon/client_test.go)).
Bodies small enough to inline are kept as constants; large or multi-file ones
belong in a `testdata/` directory.

**Do not build the response from the package's own structs and then assert the
decoder reads them back.** That only proves the decoder agrees with itself. The
two client test files say this in their headers, and it is the reason they use
captured JSON instead of marshalling a struct.

## Style 2 — Hand-built subject/report

Use this when the property is about a *state*, not a byte on the wire — in
particular a state a captured response cannot represent. Build the smallest
input that isolates the rule and set fields directly.

[`internal/mechanics/degraded_test.go`](../internal/mechanics/degraded_test.go)
is the canonical example: it constructs a `mechanics.Subject` in Go and sets
`DirectoryErr` to simulate an unreachable directory. Its header explains why it
does not use the fixture loader:

> `loadSubject` in `eval_test.go` builds a `Subject` from files on disk, so a
> missing `directory.json` is indistinguishable from a directory that never
> answered — which is precisely the confusion under test.

Other cases in this style:

- `check_mutability_test.go` builds subjects from `horizon.Flags` directly
  because no live fixture carries `auth_immutable` and clawback together, and
  `check_trustline_test.go` does the same for states with no pubnet specimen.
- `internal/attest` and `internal/temporal` use hand-built `Report`/`Finding`
  values to pin encoding and aggregation invariants that no single asset
  produces.
- `internal/history/store_test.go` builds observations in code to pin ordering
  and persistence behaviour.

Keep identifiers realistic (real-looking `G...` issuer keys, real dates) so a
failure reads the way the live system would. There is no need for a captured
body: the input is a state, so writing it as Go is the honest expression of it.

## Style 3 — Fixture-driven evaluation

Use this when you are adding or changing a check, a severity boundary, or a
mechanic, and you need to pin its *judgment* on real assets.

The eval is `TestEval` (aggregate) and `TestEvalPerCheck` (per check) in
[`internal/mechanics/eval_test.go`](../internal/mechanics/eval_test.go). Both
iterate `eval.Corpus()` and rebuild each subject with `eval.LoadSubject`, which
decodes files under `internal/mechanics/testdata/<case-name>/` using the same
decoders as the live fetchers. A fixture that parses in the test is therefore
one the real client would have accepted. The labels and their rationale live in
one place — [`internal/eval`](../internal/eval) and
[docs/eval.md](eval.md) — so the aggregate and per-check expectations cannot
describe different runs.

**A check whose judgment is not evaluated against this set does not ship.**
Every new check adds at least two subjects: one asset that should trip it, and
one that uses the same mechanic *legitimately* and must not be over-flagged.
See [docs/adding-a-check.md](adding-a-check.md) and [docs/eval.md](eval.md).

`internal/attest`'s golden tests are the same idea applied to bytes: `Preimage`
is run over fixtures and compared byte-for-byte against the committed
`.preimage` and `.digest` files under `internal/attest/testdata/vectors/`.

## Why the fixture loader cannot express a fetch error

This is the constraint that decides between style 2 and style 3, so it is worth
stating plainly.

`eval.LoadSubject` rebuilds a `Subject` from files on disk. For `stellar.toml`
it *can* represent a failed fetch: a present `stellar.toml` means success, and
a `stellar.toml.status` file sets `TomlErr`. But for the StellarExpert
directory and blocklist it has no such convention. It loads `directory.json` /
`blocked.json` when the file exists and otherwise leaves `Directory`/`Blocked`
nil with `DirectoryErr`/`BlockedErr` empty. There is no `directory.status`; the
only signal is file absence, and file absence is the same signal as "the source
answered and the address is not listed."

So a missing `directory.json` is indistinguishable from a directory that never
answered. That distinction — "we could not check" versus "this is fine" — is
exactly what `degraded_test.go` exists to test
(`TestOutageDoesNotRenderAsNotListed`), and it cannot be expressed through the
fixture loader. When the property under test is *how a failed fetch is
represented*, build the `Subject` directly, as degraded_test.go does. The
loader is deliberately not extended with a fake error-file convention: an
outage has no captured bytes to stand in for it, and inventing one would let a
test pass on input no real capture could produce.

## Where fixtures live

| Path | Contents | Style |
| --- | --- | --- |
| `internal/mechanics/testdata/<case-name>/` | One directory per labelled subject: `asset.json`, `account.json`, `stellar.toml` (success) or `stellar.toml.status` (fail), `directory.json`, `blocked.json` | Style 3 (and style 2 tests that reuse a captured case) |
| `internal/mechanics/testdata/PROVENANCE.md` | Every source URL and capture date | Provenance for all styles |
| `internal/mechanics/testdata/manifest.json` | Machine-readable dataset and labels | Style 3 |
| `internal/attest/testdata/vectors/` | `<name>.preimage` and `<name>.digest` golden bytes | Style 3 |
| Inline constants in `*_test.go` | Captured response bodies replayed by `httptest`, with the capture date and URL in the test header | Style 1 |

When you capture a new fixture, record the date and the URL it came from — in
`PROVENANCE.md` for the eval corpus, or in the test file's header for an inline
body. Reference fixtures the live source no longer serves cannot be refreshed,
so provenance is what lets a future maintainer tell a stale capture from a
fabricated one.

## Choosing a style

- Does the subject under test touch HTTP? → **Style 1.**
- Is the property about a state the wire cannot express — a fetch error, a flag
  combination, an invariant? → **Style 2.**
- Is the property whether the severity model's judgement is right on real
  assets? → **Style 3.**

Verify what exists before writing:

```sh
grep -rn 'testdata\|httptest' internal/ --include='*_test.go'
```

Then run the same checks CI runs:

```sh
make test    # go test -race ./...
make lint    # golangci-lint
make fmt     # gofmt -w .
```
