package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
)

// Every scan answer must be correlatable with the log line that describes it.
// A request identifier is attached to the context here and stamped on every
// log line the request produces, echoed to the caller in a response header —
// so an operator holding one identifier can pull the whole story of a scan
// out of the logs without guessing which lines belong together.
//
// The same wrapper gives handlers the per-request logger every call site
// shares. One pass, one place, so no handler has to remember to do any of it.

// requestIDHeader is the response header the identifier is echoed in. It is
// also accepted on input, so a caller that correlates across services can
// supply its own and see this server use the same value.
const requestIDHeader = "X-Request-Id"

// requestIDLogKey names the structured field the request identifier rides on
// in every log line this package emits.
const requestIDLogKey = "request_id"

type requestIDKey struct{}

type loggerKey struct{}

// RequestID returns the identifier the middleware assigned to the request.
// It returns the empty string outside a request, so call sites that log
// without one degrade to their uncorrelated form instead of printing an
// invented value.
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// withObservability assigns the request identifier and makes it available
// to the handler and to the logs.
//
// The identifier comes from the caller's header when one is offered and is
// otherwise freshly generated — 16 random bytes, hex-encoded. Both forms are
// logged the same way: the log line records what identified the request, not
// who chose it.
func (s *Server) withObservability(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if id == "" {
			var b [16]byte
			if _, err := rand.Read(b[:]); err != nil {
				// A missing identifier degrades correlation; it must not
				// degrade the request. Unreachable on any working crypto
				// source, and there is no meaningful recovery to attempt.
				http.Error(w, "no request identifier could be generated", http.StatusInternalServerError)
				return
			}
			id = hex.EncodeToString(b[:])
		}

		logger := s.Log.With(requestIDLogKey, id)
		ctx := r.Context()
		ctx = context.WithValue(ctx, requestIDKey{}, id)
		ctx = context.WithValue(ctx, loggerKey{}, logger)

		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loggerFrom returns the per-request logger the middleware built, falling
// back to the server's logger when a handler runs outside the middleware —
// so a call site never has to decide which logger to use.
func (s *Server) loggerFrom(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}
