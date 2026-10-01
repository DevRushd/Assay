// Package api serves the Assay HTTP interface and the single-file UI.
package api

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/use-assay/assay/internal/history"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
	"github.com/use-assay/assay/internal/temporal"
)

//go:embed ui/index.html
var uiFS embed.FS

// Scanner describes what the API server needs from a scanner.
type Scanner interface {
	ScanWithHolder(ctx context.Context, a mechanics.Asset, holder string) (*mechanics.Report, error)
}

// Server serves scan results and recorded observation history.
type Server struct {
// Server serves scan results and recorded observation history.
type Server struct {
	Scanner Scanner
	// History stores one observation per successful scan. It is a pointer so a
	// caller can replace the default in-memory store with a file-backed one
	// (history.Open) or with a pre-seeded store in a test.
	History *history.Store
	// Health reports per-upstream reachability for GET /readyz. It is a
	// pointer so a test can wire the prober to a stub upstream; when nil,
	// handleReadyz builds one from the server's own clients.
	Health *HealthProber
	// Metrics holds the scan outcome and per-source failure counters served
	// at GET /metrics. Nil-safe: the handlers treat a nil Metrics as
	// "nothing counted", never as a crash.
	Metrics *Metrics
	Log     *slog.Logger
}

// NewServer returns a Server backed by the production scanner and an in-memory
// observation history that does not survive a restart.
func NewServer(log *slog.Logger) *Server {
	return &Server{Scanner: scan.New(), History: history.New(), Metrics: NewMetrics(), Log: log}
}

// Handler returns the configured HTTP routes.
//
// Every route runs through the observability middleware, which assigns the
// request identifier, records the response status, and gives handlers a
// per-request logger — the correlation the outcome log line depends on is
// installed once, here, rather than remembered per handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/scan", s.handleScan)
	mux.HandleFunc("GET /api/v1/history", s.handleHistory)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	// Liveness and readiness are separate endpoints on purpose: /healthz says
	// the process is up and checks nothing, /readyz asks the upstreams. A
	// failing probe must never report healthy; a dying process must still be
	// able to answer /healthz.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /", s.handleUI)
	return s.withObservability(mux)
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

type errorBody struct {
	Error string `json:"error"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
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

	holder := r.URL.Query().Get("holder")
	if holder != "" {
		if err := scan.ValidateHolder(holder); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
			return
		}
	}

	maxAgeParam := r.URL.Query().Get("max_age_secs")
	if maxAgeParam == "" {
		maxAgeParam = r.URL.Query().Get("max_age")
	}
	if maxAgeParam != "" {
		secs, err := strconv.ParseInt(maxAgeParam, 10, 64)
		if err != nil || secs < 0 {
			writeJSON(w, http.StatusBadRequest, errorBody{"invalid max_age_secs"})
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	report, err := s.Scanner.ScanWithHolder(ctx, asset, holder)

	// One outcome line per scan, exactly once, with the request identifier
	// the middleware stamped on this request. The status recorded here is
	// the one the handler is about to write for this scan — derived by the
	// same decision the answer below makes, so the log joins against the
	// access log without guessing.
	s.logScanOutcome(r.Context(), report, err, s.scanStatusFor(report, err), asset.String())

	if err != nil {
		if errors.Is(err, horizon.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errorBody{"asset not found on the ledger"})
			return
		}
		// The per-request logger is used so this line carries the same
		// request identifier as the outcome line above it.
		s.loggerFrom(r.Context()).Error("scan failed", "asset", asset.String(), "err", err)
		// The upstream error is returned rather than a generic message: a user
		// deciding whether to trust an asset needs to know the difference
		// between "safe" and "we could not check".
		writeJSON(w, http.StatusBadGateway, errorBody{"scan failed: " + err.Error()})
		return
	}

if s.History != nil {
		if err := s.History.Append(temporal.ObservationFromReport(report)); err != nil {
			s.Log.Error("history append failed", "asset", asset.String(), "err", err)
		}
	}

	if report.Undetermined {
		w.Header().Set("X-Assay-Undetermined", "true")
	} else {
		w.Header().Set("X-Assay-Undetermined", "false")
	}
	writeJSON(w, http.StatusOK, report)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// scanStatusFor returns the HTTP status the handler will answer the scan
// with, from the same decision the handler makes. The outcome line carries
// it so the log can be joined against the access log without guessing.
func (s *Server) scanStatusFor(report *mechanics.Report, err error) int {
	if err != nil {
		if errors.Is(err, horizon.ErrNotFound) {
			return http.StatusNotFound
		}
		return http.StatusBadGateway
	}
	return http.StatusOK
}
