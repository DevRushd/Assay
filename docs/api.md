# Assay API Contract

All API endpoints return JSON. All responses are utf-8 encoded.

## Scan Endpoint

`GET /api/v1/scan?asset=CODE-ISSUER`

Scans an asset and returns its capability report.

### Response Headers

- `X-Assay-Undetermined`: Set to `true` when a scan is degraded due to an upstream source outage (such as failure to reach StellarExpert). When present, the response body contains `undetermined: true` and `undetermined_checks`, indicating that the source data was incomplete and the severity should be treated with caution.

### Status Codes

- `200 OK`: Successful scan (check `X-Assay-Undetermined` header or `undetermined` field for source degradation).
- `400 Bad Request`: Invalid asset code or issuer, or missing `?asset=` parameter.
- `404 Not Found`: Asset not found on the ledger.
- `502 Bad Gateway`: Scan failed due to an underlying network or upstream error.
