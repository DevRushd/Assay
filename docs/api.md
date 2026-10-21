# Assay API Contract

All API endpoints return JSON. All responses are utf-8 encoded.

## Scan Endpoint

`GET /api/v1/scan?asset=CODE-ISSUER`

Scans an asset and returns its capability report.

### Response Headers

- `X-Assay-Undetermined`: Set to `true` when a scan is degraded due to an upstream source outage (such as failure to reach StellarExpert). When present, the response body contains `undetermined: true` and `undetermined_checks`, indicating that the source data was incomplete and the severity should be treated with caution.

### Status Codes

- `200 OK`: Successful scan (check `X-Assay-Undetermined` header or `undetermined` field for source degradation).
- `400 Bad Request`: Invalid asset code or issuer, or missing `?asset=` parameter. Also returned for an identifier naming the network's native asset — see below.
- `404 Not Found`: Asset not found on the ledger.
- `502 Bad Gateway`: Scan failed due to an underlying network or upstream error.

### The native asset

The native asset (XLM) has no issuer account, so there are no authorization
flags to read and nothing to classify. An identifier that names it — `native`
or `XLM`, in any case, with no issuer half — is answered with
`400 Bad Request` and an explicit message, never a parse error and never a
report:

```json
{ "error": "native asset has no issuer and no authorization flags: \"XLM\" cannot be scanned or attested" }
```

It is refused by design: the native asset is never scanned and never attested,
so it stays exactly what [integrating.md](integrating.md) already uses it as —
a never-attested asset the on-chain gate refuses. `GET /api/v1/history?asset=XLM`
returns the same `400` and message. A credit asset whose code merely happens
to be XLM (`XLM-G…`) is an ordinary asset and scans normally.
## Exposure Endpoint

`GET /api/v1/exposure?account=G...&limit=10&cursor=0`

Lists the trustlines an account holds and answers, per asset, with the asset's
issuer-level severity and its holder-trustline finding — the per-wallet form of
`?holder=` on the scan endpoint. **There is no aggregate or portfolio score:**
every asset carries its own severity and its own undetermined flag, and an
undetermined asset says nothing about any other asset on the page.

### Parameters

- `account` (required): the holder's `G...` address.
- `limit` (optional): page size, default `10`, clamped to a maximum of `50`.
  One page is up to `limit` full scans, which is why the bound exists.
- `cursor` (optional): index of the first trustline to return, for the next
  page. `0` starts; a cursor at or past the end returns an empty page.

### Response

- `account`, `total` (trustlines on the account), `limit` (page size applied),
  `count` (assets in this page), and `next_cursor` — absent on the last page.
- `assets[]`: per asset, `asset` (`code`/`issuer`), `severity`,
  `undetermined`, `undetermined_checks`, the `finding` from the holder-
  trustline check, and `reason` when that asset's scan failed outright (the
  `finding` is then absent rather than rendered as a clear answer).

### Status Codes

- `200 OK`: Page returned. Individual assets may be undetermined — see each
  entry's `undetermined` field; there is no header equivalent for a page.
- `400 Bad Request`: Missing or invalid `account`, `limit`, or `cursor`.
- `404 Not Found`: Account not found on the ledger.
- `429 Too Many Requests`: Rate limited. `Retry-After` gives the wait in
  seconds. Exposure is rate-limited per client address because one request
  runs a full scan per asset; `/api/v1/scan` is not affected.
- `502 Bad Gateway`: The account's trustline list could not be fetched.
