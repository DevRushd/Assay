# API versioning and compatibility

`assay serve` exposes `GET /api/v1/scan`. Nothing stated what that `v1`
promised, so this page does: which changes are allowed inside a version, which
force a new one, and how a version is retired.

The same report is printed by `assay scan`, so the policy covers the payload as
well as the route. Two version numbers identify the surface, and they are
independent:

| Version | Where it lives | What it covers |
| --- | --- | --- |
| Route version | the `v1` in `/api/v1/...` | paths, methods, query parameters, status codes, and error bodies |
| Report schema version | `schema_version` in the JSON report | the shape of the `Report` object, in both the API response and CLI output |

Both are needed because `/api/v1` is a URL namespace, not a payload contract. A
CLI consumer never sees the route, so the report carries its own version. The
field and its constant are added by
[#44](https://github.com/use-assay/Assay/issues/44); this page states the rule
that field follows and that the routes follow.

## The rule

**Within a version, only additive changes. Anything that breaks an existing
consumer requires a new version.**

Additive, and permitted without a version change:

- A new field in a JSON object. Consumers must ignore fields they do not know.
- A new `Finding`, a new check ID in `checks`, or a new `evidence` source.
- A new value in a field whose consumers are already required to treat unknown
  values as unknown rather than fail.

Breaking, and a new version:

- Removing or renaming a field, a route, a query parameter, or an error shape.
- Changing a field's type, its meaning, its units, or the set of values it can
  take.
- Adding a member to an ordered enumeration such as `severity`, where the level
  order is part of the contract.
- Making an optional field required, or letting an absent field mean something
  it did not mean before.

Additive changes do not move `schema_version`; breaking changes do. Because the
HTTP API returns the report directly rather than wrapping it, a breaking change
to the report shape also requires a new route version — a `schema_version` bump
is not a substitute for `/api/v2`, and `/api/v2` is not a substitute for the
bump.

The route version alone does not version the payload. Consumers should pin the
route and read `schema_version`; a path is not a promise about a body.

### Additive is not "anything goes"

Adding a field is additive only if an old consumer can keep working without
knowing it. That is why a new optional field is fine and a new **required**
field, or a new member of an ordered enum, is not: the first is invisible to a
consumer that ignores it, the second changes how a consumer must read a value it
already depends on.

## Absent is not an error

A field missing from a response is absent, not `null` and not an error. A
consumer must not require a field this policy is allowed to add later, and must
not reject a report because it carries a field the consumer does not recognize.

This is what makes additive change safe. It is also why `checks` is serialized
with `omitempty`: a report written before check-set binding carries no `checks`
key and is read as *unknown*, never as an error. See
[contract-interface.md](contract-interface.md), "The preimage binds the check
set".

## The precedent this rule covers

`undetermined` and `undetermined_checks` were added to the report after
`/api/v1` shipped, with no version change. Under this policy that was the
additive case: two new fields, absent from older responses, ignored by
consumers that did not know them, and meaningful to consumers that did.

The counterexample is the one the policy forbids: changing what an existing
field means without a version bump. A consumer that cached a `severity` under
the old meaning would keep acting on it after the meaning moved, and no version
number would have warned it.

## Deprecation

When a version is replaced, it is retired in stages, not switched off:

1. **Announce.** Open an issue, add a CHANGELOG entry, and state the old
   version, its replacement, and the sunset date in these docs. A version is not
   deprecated silently or only in a commit message.
2. **Serve both.** The old and the new version are available concurrently for
   the whole notice window. The old route keeps returning the old
   `schema_version`; it is not quietly upgraded in place.
3. **Signal at runtime.** Responses from a deprecated route carry a `Deprecation`
   header ([RFC 9745](https://www.rfc-editor.org/rfc/rfc9745)) and, once a
   removal date is fixed, a `Sunset` header
   ([RFC 8594](https://www.rfc-editor.org/rfc/rfc8594)). `Deprecation` is the
   date the route became deprecated; `Sunset` is the date it stops answering and
   must not be earlier.
4. **Keep the promise until the sunset date.** A deprecated route behaves as
   documented until then.

The default notice window is **90 days** from the announcement. A security fix
may require a shorter one — under-reporting risk is the failure this project
exists to prevent — but a shortened window is stated explicitly, with the
reason, in the announcement. Deprecating inside 90 days for convenience is not
allowed.

No version has been deprecated yet, so no window has been exercised. The first
one will be recorded here with its dates.

## What this policy does not cover

- **The `evidence_hash` preimage encoding.** `assay-evidence-v1` and `-v2`
  version a hash, not an API. They are separate by design: changing the preimage
  changes what an on-chain attestation commits to, and is governed by
  [contract-interface.md](contract-interface.md), not by this page.
- **The OpenAPI document.** Pinning the response shape in a machine-readable
  schema is [#21](https://github.com/use-assay/Assay/issues/21); that document
  should link here for the policy rather than restate it.
- **The on-chain ABI.** Severity values and mechanic bits are fixed by the
  contract, not by this page. "Do not renumber them" in
  [contract-interface.md](contract-interface.md) applies.

## Changing the API

1. Decide whether the change is additive or breaking against the lists above.
2. Additive: add it, tests and all, with no version change.
3. Breaking: add the new route or `schema_version`, keep the old one working,
   and follow the deprecation steps above.
4. Update this page when a version is deprecated or the window changes.

## Verification

Every route and every version claim is greppable:

```sh
grep -rn 'api/v1' docs/ README.md
```
