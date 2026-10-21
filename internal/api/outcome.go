package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/use-assay/assay/internal/mechanics"
)

// One scan, one outcome, one log line. The issue names four outcome classes —
// complete, undetermined by source, not found, upstream failure — and requires
// a counter for each and for per-source failures. Counting lives in
// metrics.go; this file derives the class from what a scan actually produced
// and records it exactly once.
//
// The undetermined class is deliberately separate from the failure class. A
// scan that came back undetermined succeeded: the sources that were reached
// answered, the report is complete on its own terms, and it says which axis
// could not be checked. A scan that failed produced no report at all. They
// are different operational conditions — "the answer is partial" versus
// "there is no answer" — and counting them together would hide the number
// that decides whether retries are worth building.

// Outcome classes. These words are the log field value and the counter label,
// and they are what an operator greps for.
const (
	outcomeComplete     = "complete"
	outcomeUndetermined = "undetermined"
	outcomeNotFound     = "not_found"
	outcomeUpstreamFail = "upstream_failure"
)

// outcomeOf classifies one finished scan request.
//
// The order of the questions is the semantics. An error from the scanner is
// the answer — whether it names a missing asset or a dead upstream, and the
// status the error was served under separates the two. A report that says it
// is undetermined is undetermined, whatever else it also is. Anything else
// completed. Nothing here re-derives what the report concluded; it reads the
// report's own statements.
func outcomeOf(rep *mechanics.Report, err error, status int) (class string, sources []string) {
	if err != nil {
		if status == http.StatusNotFound {
			return outcomeNotFound, nil
		}
		return outcomeUpstreamFail, nil
	}
	if rep != nil && rep.Undetermined {
		return outcomeUndetermined, sourcesFromReport(rep)
	}
	return outcomeComplete, nil
}

// sourcesFromReport maps the report's attempted evidence to source names.
// Attempted evidence is the report's own record of a source that was asked
// and did not answer, so this reads what the scan recorded rather than
// re-deriving which fetch failed — the same attribution the evidence_hash
// already carries, reused for operations.
func sourcesFromReport(rep *mechanics.Report) []string {
	sources := make([]string, 0, 2)
	for _, ev := range rep.Evidence {
		if ev.Attempted {
			sources = append(sources, ev.Source)
		}
	}
	return sources
}

// logScanOutcome writes the single outcome line for one scan request and
// increments the counters for its class and its failed sources.
//
// It is the only place a scan outcome is logged, so "every scan logs its
// outcome class once" holds by construction. The line is Info, not Error:
// for the not-found and upstream-failure classes the line carries the error,
// but the outcome line itself is a record of what happened, and only the
// handler's existing Error call marks the operator-visible failure.
//
// Asset identifiers are public ledger data and are safe to log; the handler
// adds the asset when it has one. No secret can reach this line: the prober,
// the clients, and the attester key never pass through here, and nothing in
// the outcome struct carries credential material.
func (s *Server) logScanOutcome(ctx context.Context, rep *mechanics.Report, err error, status int, asset string) { //nolint:revive // see note above
	class, sources := outcomeOf(rep, err, status)
	if class == outcomeUndetermined && len(sources) == 0 {
		// An undetermined report that names no source would be unauditable.
		// Say so rather than leaving the counter silently unattributed.
		sources = []string{"unnamed"}
	}

	// Counters are incremented even if the logger write fails: metrics
	// describe the server, the log line describes the run.
	s.Metrics.IncOutcome(class)
	for _, src := range sources {
		s.Metrics.IncSourceFailure(src)
	}

	args := []any{
		"outcome", class,
		"status", status,
	}
	if asset != "" {
		args = append(args, "asset", asset)
	}
	switch class {
	case outcomeUndetermined:
		args = append(args, "sources", strings.Join(sources, ","))
	case outcomeNotFound, outcomeUpstreamFail:
		args = append(args, "error", err.Error())
	}

	s.loggerFrom(ctx).Info("scan outcome", args...)
}

// The status recorder was removed: the outcome status is derived by the
// handler's own decision (scanStatusFor), so there is no wrapper to maintain
// and no divergence possible between what the log says and what was served.
