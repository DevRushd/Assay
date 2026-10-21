package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
)

// Exposure bounds. One exposure request is up to maxExposureLimit scans, each
// of which fans out across every source a single-asset scan uses, so the page
// size is capped and the answer is always paginated: a wallet with hundreds
// of trustlines is served page by page, never scanned whole in one request.
const (
	defaultExposureLimit = 10
	maxExposureLimit     = 50

	// exposureTimeout bounds one page. It is deliberately larger than the
	// single-scan timeout: a page is many scans sharing one cache, but it
	// must still end, or one slow upstream would hold the request open.
	exposureTimeout = 90 * time.Second

	// defaultExposureBurst and defaultExposureRate are the rate limit applied
	// to exposure when the server is built without its own limiter. The burst
	// lets a wallet render its first page immediately; the refill lets it
	// walk the rest without tripping the limit.
	defaultExposureBurst = 5
	defaultExposureRate  = 1 // token per second
)

// exposureResponse is the body of GET /api/v1/exposure.
//
// There is deliberately no aggregate: a portfolio-level score would be a
// claim about the issuer mix the evidence does not support, and it would
// contradict the per-asset severity the on-chain gates read. The answer is a
// list of the same per-asset facts a single scan gives, plus the pagination
// needed to walk a large account.
type exposureResponse struct {
	Account string `json:"account"`
	// Total is the number of credit trustlines the account holds, known
	// because one /accounts fetch lists all of them; it is the size of the
	// whole listing, not of this page.
	Total int `json:"total"`
	// Limit is the page size actually applied (the requested limit, clamped
	// to the server's cap), so a caller can compute the next cursor without
	// guessing how its request was interpreted.
	Limit int `json:"limit"`
	// Count is how many assets this page returned.
	Count int `json:"count"`
	// NextCursor is the cursor of the first trustline not yet returned. It is
	// absent on the last page, and a cursor at or past the end yields an
	// empty page rather than an error, so a caller that raced ahead by one
	// still terminates.
	NextCursor *int            `json:"next_cursor,omitempty"`
	Assets     []exposureAsset `json:"assets"`
}

// exposureAsset is one asset on the page: the asset, its issuer-level
// severity, and the holder-trustline finding that answers "can the issuer act
// against my balance in this asset".
//
// Undetermined is per asset, exactly as it is per check in a scan: one asset
// whose source did not answer says nothing about the others on the page, and
// nothing on this page may be read as a green light for an asset marked
// undetermined.
type exposureAsset struct {
	Asset    mechanics.Asset    `json:"asset"`
	Severity mechanics.Severity `json:"severity"`
	// Undetermined marks an asset whose answer is incomplete — either the
	// scan itself reported undetermined checks, or the scan failed outright.
	Undetermined bool `json:"undetermined"`
	// UndeterminedChecks names the checks that did not complete. It is empty
	// for a scan that failed before any check ran; Reason then carries why.
	UndeterminedChecks []string `json:"undetermined_checks"`
	// Finding is the holder-trustline check's result for this asset. It is
	// absent when the scan failed, because a finding that was never computed
	// must not be rendered as one that came back clear.
	Finding *mechanics.Finding `json:"finding,omitempty"`
	// Reason explains a whole-scan failure for this asset. It is never set
	// when Finding is present.
	Reason string `json:"reason,omitempty"`
}

// handleExposure serves the holder-trustline finding and issuer severity for
// every asset in a page of an account's trustlines.
//
// The scans reuse the server's scanner, so the shared cache warms across
// pages and across single-asset scans: asking for a page and then asking for
// one asset on it does not fetch the issuer twice. Each asset is answered on
// its own — a failure marks that asset and the loop continues, because a
// page-wide failure would hide the assets that did answer.
func (s *Server) handleExposure(w http.ResponseWriter, r *http.Request) {
	account := r.URL.Query().Get("account")
	if account == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{"missing ?account=G... address"})
		return
	}
	if err := scan.ValidateHolder(account); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}

	limit := defaultExposureLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeJSON(w, http.StatusBadRequest, errorBody{"invalid limit: must be a positive integer"})
			return
		}
		// The bound is enforced by clamping rather than rejecting: a caller
		// asking for the whole account gets as much as the server will
		// serve, plus Limit in the response so it can continue correctly.
		if n > maxExposureLimit {
			n = maxExposureLimit
		}
		limit = n
	}
	cursor := 0
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeJSON(w, http.StatusBadRequest, errorBody{"invalid cursor: must be a non-negative integer"})
			return
		}
		cursor = n
	}

	ctx, cancel := context.WithTimeout(r.Context(), exposureTimeout)
	defer cancel()

	trustlines, err := s.Scanner.Horizon.Trustlines(ctx, account)
	if err != nil {
		if errors.Is(err, horizon.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errorBody{"account not found on the ledger"})
			return
		}
		s.loggerFrom(r.Context()).Error("exposure: trustline fetch failed", "account", account, "err", err)
		writeJSON(w, http.StatusBadGateway, errorBody{"exposure failed: " + err.Error()})
		return
	}

	start := cursor
	if start > len(trustlines) {
		start = len(trustlines)
	}
	end := start + limit
	if end > len(trustlines) {
		end = len(trustlines)
	}

	resp := exposureResponse{
		Account: account,
		Total:   len(trustlines),
		Limit:   limit,
		Assets:  []exposureAsset{},
	}

	for i := start; i < end; i++ {
		if ctx.Err() != nil {
			// The page deadline expired mid-page. The assets already
			// scanned are returned; the rest are the next page, at the
			// cursor where they would have been. Stopping here keeps every
			// entry on the page computed rather than padding it with
			// answers that were never made.
			next := i
			resp.NextCursor = &next
			break
		}
		entry := s.exposureFor(ctx, account, trustlines[i])
		resp.Assets = append(resp.Assets, entry)
	}
	resp.Count = len(resp.Assets)
	if end < len(trustlines) && resp.NextCursor == nil {
		next := end
		resp.NextCursor = &next
	}

	writeJSON(w, http.StatusOK, resp)
}

// exposureFor scans one held asset with the account as holder and shapes the
// per-asset answer. A scan error becomes an undetermined entry with the error
// as its reason — the asset is held, so silence would read as absence of a
// finding, and absence of a finding is exactly what must not be inferred.
func (s *Server) exposureFor(ctx context.Context, account string, tl horizon.TrustlineBalance) exposureAsset {
	asset := mechanics.Asset{Code: tl.AssetCode, Issuer: tl.AssetIssuer}
	entry := exposureAsset{
		Asset:              asset,
		Severity:           mechanics.Unevaluated,
		UndeterminedChecks: []string{},
	}

	report, err := s.Scanner.ScanWithHolder(ctx, asset, account)
	if err != nil {
		entry.Undetermined = true
		entry.Reason = err.Error()
		return entry
	}

	entry.Severity = report.Severity
	entry.Undetermined = report.Undetermined
	entry.UndeterminedChecks = report.UndeterminedChecks
	if entry.UndeterminedChecks == nil {
		entry.UndeterminedChecks = []string{}
	}
	for i := range report.Findings {
		if report.Findings[i].Check == "trustline" {
			f := report.Findings[i]
			entry.Finding = &f
			break
		}
	}
	return entry
}

// withExposureLimit wraps the exposure handler in the server's rate limit.
// Exposure is the only endpoint that turns one request into many scans, so
// it is the one wrapped: /api/v1/scan keeps its existing behavior, and a
// refused caller is told when to come back rather than being cut off
// silently.
func (s *Server) withExposureLimit(limiter *RateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			key = host
		}
		ok, retry := limiter.Allow(key)
		if !ok {
			secs := int64(retry / time.Second)
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
			writeJSON(w, http.StatusTooManyRequests, errorBody{
				"rate limit exceeded: exposure runs full scans per asset; retry in " +
					strconv.FormatInt(secs, 10) + "s",
			})
			return
		}
		next(w, r)
	}
}
