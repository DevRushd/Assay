package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
	"github.com/use-assay/assay/internal/temporal"
)

// History states. They are the same three words docs/transitions.md gives a
// comparison, applied to the history as a whole, and they carry the same rule:
// none of them is an error, and an empty or partial history must never render
// as an API failure or as silence.
const (
	// historyValid means at least one observation exists and every observation
	// returned is complete.
	historyValid = "valid"
	// historyUnknown means at least one returned observation is undetermined,
	// so it is marked and returned rather than dropped. Nothing may be read
	// from what an undetermined observation omits.
	historyUnknown = "unknown"
	// historyMissing means no observations have been recorded for the asset.
	// That is an explicit empty result, not a 404.
	historyMissing = "missing"
)

// historyResponse is the body of GET /api/v1/history.
//
// Observations are in time order, oldest first, and transitions are the derived
// difference between each consecutive pair — the view a consumer needs to ask
// "what changed", where /api/v1/scan answers "what is true now".
type historyResponse struct {
	Asset  mechanics.Asset `json:"asset"`
	State  string          `json:"state"`
	Reason string          `json:"reason,omitempty"`
	Count  int             `json:"count"`

	Observations []temporal.Observation `json:"observations"`
	Transitions  []temporal.Transition  `json:"transitions"`

	// LatestAt and LatestAgeSecs carry the freshness of the most recent
	// observation so a consumer can apply its own staleness policy. Assay does
	// not declare a history stale: the tolerance belongs to the consumer, the
	// same way max_age_secs does on-chain.
	LatestAt      *time.Time `json:"latest_at,omitempty"`
	LatestAgeSecs *int64     `json:"latest_age_secs,omitempty"`

	// Retention is the greatest number of observations kept per asset. A
	// consumer that sees exactly this many should read the history as possibly
	// truncated at the oldest end rather than as complete.
	Retention int `json:"retention"`
}

// handleHistory serves an asset's recorded observations and the transitions
// derived between them.
//
// It reads only what has been recorded; it never scans. An asset with no
// recorded history is a valid response with an empty list and state "missing",
// so a consumer can distinguish "we have never looked" from "the request
// failed" without inspecting an HTTP status.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("asset")
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{"missing ?asset=CODE-ISSUER"})
		return
	}

	asset, err := scan.ParseAsset(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}

	observations := []temporal.Observation{}
	retention := 0
	if s.History != nil {
		observations = s.History.List(asset)
		retention = s.History.RetentionLimit()
	}

	resp := historyResponse{
		Asset:        asset,
		State:        historyValid,
		Count:        len(observations),
		Observations: observations,
		Transitions:  []temporal.Transition{},
		Retention:    retention,
	}

	if len(observations) == 0 {
		resp.State = historyMissing
		resp.Reason = "no observations have been recorded for this asset. " +
			"GET /api/v1/scan records one per successful scan, so an asset that " +
			"has never been scanned has an empty history rather than an unknown " +
			"or failing one."
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Transitions are derived on demand between consecutive observations and
	// never stored; docs/transitions.md records why.
	for i := 1; i < len(observations); i++ {
		resp.Transitions = append(resp.Transitions,
			temporal.Between(observations[i-1], observations[i]))
	}

	if undetermined, named := undeterminedChecks(observations); undetermined {
		resp.State = historyUnknown
		resp.Reason = "one or more observations are undetermined because a source " +
			"did not answer (" + named + "), so what they omit must not be read " +
			"as unchanged. They are returned marked rather than omitted."
	}

	resp.LatestAt, resp.LatestAgeSecs = latestAge(observations, time.Now().UTC())
	writeJSON(w, http.StatusOK, resp)
}

// undeterminedChecks reports whether any observation is partial and, if so,
// which checks did not complete across the whole history, deduplicated and in
// first-seen order. An undetermined observation with no named check still
// counts, so state cannot depend on how loudly a scan failed.
func undeterminedChecks(observations []temporal.Observation) (bool, string) {
	var checks []string
	seen := map[string]bool{}
	anyUndetermined := false
	for _, o := range observations {
		if !o.Undetermined {
			continue
		}
		anyUndetermined = true
		for _, c := range o.UndeterminedChecks {
			if !seen[c] {
				seen[c] = true
				checks = append(checks, c)
			}
		}
	}
	if !anyUndetermined {
		return false, ""
	}
	if len(checks) == 0 {
		return true, "an unnamed check"
	}
	return true, strings.Join(checks, ", ")
}

// latestAge returns the most recent observation's time and its age, so a
// consumer can judge staleness itself. A zero timestamp is reported as absent
// rather than as an age measured from the zero instant.
func latestAge(observations []temporal.Observation, now time.Time) (*time.Time, *int64) {
	latest := observations[len(observations)-1].At
	if latest.IsZero() {
		return nil, nil
	}
	age := int64(now.Sub(latest).Seconds())
	if age < 0 {
		// A clock skew between the writer and the reader must not print a
		// negative age, which would read as "in the future" and confuse any
		// downstream comparison.
		age = 0
	}
	return &latest, &age
}
