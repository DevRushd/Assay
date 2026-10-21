// Package replay records the upstream HTTP responses of a live scan and
// serves them back so the same scan can be re-run offline and deterministically.
//
// It exists because a surprising live verdict is otherwise unreproducible:
// the sources change, so re-scanning answers a different question than the
// one that produced the bug report. internal/fixtures refreshes curated
// subjects one at a time; this wraps whatever a real scan fetches, for any
// subject, and turns the report into a replayable artifact.
//
// Both directions are http.RoundTrippers, because that is the seam every
// fetcher in Assay already has: the recorder wraps the transport each client
// uses, and the replayer replaces it. The replayer holds no inner transport
// at all, so "replay never touches the network" is structural, not a promise.
package replay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ManifestVersion is the on-disk format version. A reader that does not
// recognize the version refuses rather than guessing: a mis-decoded response
// is a silently wrong scan.
const ManifestVersion = 1

// ManifestName is the manifest's fixed filename inside a recording directory.
const ManifestName = "manifest.json"

// Entry is one recorded request/response pair.
//
// Only what a replay needs to answer identically is stored: method, URL,
// status, content type and the exact response body bytes. Request and
// response headers beyond the content type are not stored — no fetcher in
// Assay reads them, and keeping the recording minimal keeps it reviewable.
type Entry struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body"`
	RecordedAt  string `json:"recorded_at"`
}

// Manifest is the index of a recording directory.
type Manifest struct {
	Version    int     `json:"version"`
	RecordedAt string  `json:"recorded_at"`
	Entries    []Entry `json:"entries"`
}

// key identifies a request the way the replayer matches it: method and full
// URL. Everything a fetcher varies on in Assay is in the URL.
func key(method, url string) string { return method + " " + url }

// bodyName returns the body file for a key: a stable digest, so a repeated
// request overwrites its own file rather than accumulating duplicates.
func bodyName(method, url string) string {
	sum := sha256.Sum256([]byte(key(method, url)))
	return hex.EncodeToString(sum[:8]) + ".body"
}

// Recorder is an http.RoundTripper that saves every response it passes
// through into a directory, to be served back by a Replayer.
//
// A Recorder whose inner transport is nil records from http.DefaultTransport,
// which is what it gets when wrapped around Assay's fetchers — they build
// their http.Clients with the default transport and a timeout.
type Recorder struct {
	dir   string
	inner http.RoundTripper
	now   func() time.Time

	mu      sync.Mutex
	entries map[string]Entry
	bodies  map[string][]byte
}

// NewRecorder returns a Recorder writing into dir, creating it if needed.
func NewRecorder(dir string, inner http.RoundTripper) (*Recorder, error) {
	if dir == "" {
		return nil, fmt.Errorf("replay: empty recording directory")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("replay: create recording directory: %w", err)
	}
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &Recorder{
		dir:     dir,
		inner:   inner,
		now:     time.Now,
		entries: make(map[string]Entry),
		bodies:  make(map[string][]byte),
	}, nil
}

// RoundTrip passes the request through, saves the response, and returns the
// response unchanged — the caller cannot tell it is being recorded.
//
// A transport error is not recorded: there is no response to replay, and
// caching a failure would make an outage permanent in the recording. The
// scan's own undetermined handling covers the live failure, and a replay of
// a recording that lacks the request fails loudly instead.
func (r *Recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.inner.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("replay: forward request %s: %w", req.URL, err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("replay: read response body for %s: %w", req.URL, err)
	}
	// The caller gets the body back exactly as it was, from a fresh reader:
	// recording must be invisible to the fetcher decoding it.
	resp.Body = io.NopCloser(bytes.NewReader(body))

	e := Entry{
		Method:      req.Method,
		URL:         req.URL.String(),
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        bodyName(req.Method, req.URL.String()),
		RecordedAt:  r.now().UTC().Format(time.RFC3339),
	}
	r.mu.Lock()
	r.entries[key(e.Method, e.URL)] = e
	r.bodies[e.Body] = body
	r.mu.Unlock()
	return resp, nil
}

// Close writes the manifest and every recorded body to the directory.
//
// Entries are sorted by method and URL so re-recording the same responses
// rewrites the same bytes; a recording that only differs in fetch order is
// still diffable. Close is safe to call once, after the scan finishes.
func (r *Recorder) Close() error {
	// One critical section: Close runs after the scan, when nothing else is
	// fetching, and holding the lock across the writes keeps the manifest and
	// the body files consistent with each other.
	r.mu.Lock()
	defer r.mu.Unlock()

	entries := make([]Entry, 0, len(r.entries))
	for _, e := range r.entries {
		entries = append(entries, e)
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].URL != entries[j].URL {
			return entries[i].URL < entries[j].URL
		}
		return entries[i].Method < entries[j].Method
	})

	for _, e := range entries {
		path := filepath.Join(r.dir, e.Body)
		if err := os.WriteFile(path, r.bodies[e.Body], 0o644); err != nil {
			return fmt.Errorf("replay: write body %s: %w", path, err)
		}
	}

	m := Manifest{
		Version:    ManifestVersion,
		RecordedAt: r.now().UTC().Format(time.RFC3339),
		Entries:    entries,
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("replay: encode manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, ManifestName), append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("replay: write manifest: %w", err)
	}
	return nil
}

// Replayer is an http.RoundTripper that serves responses from a recording
// directory. It holds no inner transport: an unrecorded request is an error,
// never a network call.
type Replayer struct {
	dir     string
	entries map[string]Entry
	bodies  map[string][]byte
}

// NewReplayer loads a recording directory written by a Recorder.
//
// Every body named in the manifest must exist and be readable. A partial
// recording is refused rather than half-served: a replay that silently
// dropped one source's answer would produce a report that looks complete.
func NewReplayer(dir string) (*Replayer, error) {
	if dir == "" {
		return nil, fmt.Errorf("replay: empty recording directory")
	}
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, fmt.Errorf("replay: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("replay: decode manifest: %w", err)
	}
	if m.Version != ManifestVersion {
		return nil, fmt.Errorf("replay: manifest version %d, this build reads version %d",
			m.Version, ManifestVersion)
	}
	rp := &Replayer{
		dir:     dir,
		entries: make(map[string]Entry, len(m.Entries)),
		bodies:  make(map[string][]byte, len(m.Entries)),
	}
	for _, e := range m.Entries {
		body, err := os.ReadFile(filepath.Join(dir, e.Body))
		if err != nil {
			return nil, fmt.Errorf("replay: read body for %s %s: %w", e.Method, e.URL, err)
		}
		rp.entries[key(e.Method, e.URL)] = e
		rp.bodies[e.Body] = body
	}
	return rp, nil
}

// RoundTrip serves the recorded response for req.
//
// An unrecorded request is the whole point of the loud failure: reaching the
// network instead would let a replay quietly become a live scan the moment a
// new fetch path appeared, which is exactly the drift this package exists to
// make visible.
func (r *Replayer) RoundTrip(req *http.Request) (*http.Response, error) {
	k := key(req.Method, req.URL.String())
	e, ok := r.entries[k]
	if !ok {
		return nil, fmt.Errorf(
			"replay: unrecorded request %s %s: %s has no entry for it, "+
				"refusing to reach the network (re-record with -record)",
			req.Method, req.URL, r.dir)
	}
	h := http.Header{}
	if e.ContentType != "" {
		h.Set("Content-Type", e.ContentType)
	}
	return &http.Response{
		StatusCode: e.Status,
		Status:     fmt.Sprintf("%d %s", e.Status, http.StatusText(e.Status)),
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(r.bodies[e.Body])),
		Request:    req,
	}, nil
}
