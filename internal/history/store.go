// Package history stores per-asset observations so a consumer can ask what
// changed, not only what is true now.
//
// internal/temporal computes a transition between two observations and
// deliberately stores nothing — a transition is a pure function of its pair. A
// caller, though, has to get the pair from somewhere, and until this package
// existed Assay persisted nothing at all. This is that somewhere: an
// append-only sequence of observations per asset, which the API exposes as a
// history view and internal/temporal reduces to transitions on demand.
//
// Three design decisions are recorded here rather than left implicit, because
// this is the first component in Assay that retains state:
//
//   - Observations are stored; transitions are not. A stored transition would
//     be a second source of truth beside the pair it was derived from, and the
//     state of that pair can change (an observation can be replaced by a
//     complete one), so a frozen transition can disagree with its own inputs.
//     Recomputing is a handful of bitwise operations. See docs/transitions.md.
//
//   - The storage is an append-only JSON Lines log written with the standard
//     library. A registry whose whole threat model is "no third-party trust we
//     did not decide to take on" does not acquire a database dependency to keep
//     a few hundred small records per asset; encoding/json and os are already
//     part of the toolchain. The decision is recorded in docs/history.md.
//
//   - Retention is bounded per asset and drops the oldest observation first.
//     An unbounded log is a denial-of-service surface, and the oldest
//     observation is the one a consumer is least likely to need. The cap is
//     reported in every API response, so a history that has reached it is
//     visible to a consumer rather than passing as complete.
package history

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/temporal"
)

// DefaultRetention is the greatest number of observations kept for one asset.
//
// It is deliberately generous relative to the twenty-odd assets Assay has ever
// scanned: the cost of an observation is a few hundred bytes, so the bound
// exists to make an unbounded log impossible rather than to save space. When
// more than this many observations exist for one asset, the oldest are dropped.
const DefaultRetention = 256

// Store is an append-only, per-asset sequence of observations, ordered by time.
//
// The zero value is not usable; use New or Open. All methods are safe for
// concurrent use, which the HTTP server requires because scans and history
// reads arrive on separate connections.
type Store struct {
	mu        sync.Mutex
	byAsset   map[string][]temporal.Observation
	path      string
	retention int
}

// New returns an in-memory Store that retains DefaultRetention observations per
// asset. Nothing survives a restart, which is the right default for a process
// that has not been told where to write: losing history is honest, whereas
// writing to an unconfigured path would be a surprise.
func New() *Store { return NewWithRetention(DefaultRetention) }

// NewWithRetention returns an in-memory Store bounded to n observations per
// asset. A non-positive n is replaced by DefaultRetention rather than treated as
// "keep nothing", because silently retaining nothing would present as a
// permanently empty history.
func NewWithRetention(n int) *Store {
	if n <= 0 {
		n = DefaultRetention
	}
	return &Store{byAsset: map[string][]temporal.Observation{}, retention: n}
}

// Open returns a Store persisted to path as a JSON Lines log, loading whatever
// is already there.
//
// An empty path is equivalent to New: an in-memory store. A path that does not
// exist yet is not an error — the log is created on the first append — because
// "no history yet" and "the history file is broken" are different facts and the
// first must not fail startup.
func Open(path string) (*Store, error) {
	return OpenWithRetention(path, DefaultRetention)
}

// OpenWithRetention is Open with an explicit per-asset retention bound, for a
// deployment that wants a different one than DefaultRetention.
func OpenWithRetention(path string, n int) (*Store, error) {
	s := NewWithRetention(n)
	s.path = path
	if path == "" {
		return s, nil
	}

	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("history: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	// Observations carry evidence-derived check names and can legitimately be
	// longer than the default 64 KiB line limit.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec logRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("history: decode %s: %w", path, err)
		}
		if rec.Version != logVersion {
			return nil, fmt.Errorf("history: decode %s: unsupported log record version %d, want %d",
				path, rec.Version, logVersion)
		}
		s.insertLocked(rec.observation())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("history: read %s: %w", path, err)
	}
	return s, nil
}

// Append records one observation, evicting the oldest for that asset when the
// retention bound is exceeded, and persists the result when the store is
// file-backed.
//
// The returned error is about storage, never about the observation itself: a
// caller recording a scan is not told its scan was rejected because the log
// could not be written.
func (s *Store) Append(o temporal.Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.insertLocked(o)
	if s.path == "" {
		return nil
	}
	return s.persistLocked()
}

// List returns the observations for one asset, oldest first.
//
// The result is a copy. A caller that mutated the returned slice would
// otherwise be editing the store, and a stored observation must not change when
// a later report is produced.
//
// The slice is non-nil even when empty, so an empty history serializes as `[]`
// and not `null`. "There are no observations" is a result and has to render as
// one.
func (s *Store) List(a mechanics.Asset) []temporal.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := s.byAsset[a.String()]
	out := make([]temporal.Observation, len(kept))
	copy(out, kept)
	return out
}

// Len reports how many observations are retained for one asset.
func (s *Store) Len(a mechanics.Asset) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byAsset[a.String()])
}

// RetentionLimit reports the per-asset bound this store keeps, so an API
// response can state the cap a consumer is reading against.
func (s *Store) RetentionLimit() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retention
}

// insertLocked adds one observation and re-applies the retention bound. The
// caller holds s.mu.
func (s *Store) insertLocked(o temporal.Observation) {
	key := o.Asset.String()
	list := append(s.byAsset[key], o)
	// Observations arrive in scan order, which is usually but not always time
	// order, and two observations may share a timestamp. Sorting here keeps the
	// sequence ordered by time regardless of arrival order; the stable sort
	// leaves same-instant observations in the order they arrived.
	sort.SliceStable(list, func(i, j int) bool { return list[i].At.Before(list[j].At) })
	if len(list) > s.retention {
		list = list[len(list)-s.retention:]
	}
	s.byAsset[key] = list
}

// persistLocked rewrites the log from the retained set. The caller holds s.mu.
//
// The log is small and the store is written to at human rates, so a full
// rewrite is simpler and more obviously correct than an append with periodic
// compaction: the file is exactly the retained set at all times, which means a
// restart cannot resurrect observations that retention had already evicted. The
// write is atomic — a temporary file renamed over the target — so a crash
// mid-write cannot leave a half-observation in the log.
func (s *Store) persistLocked() error {
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("history: create %s: %w", dir, err)
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".history-*.tmp")
	if err != nil {
		return fmt.Errorf("history: create temp log: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	w := bufio.NewWriter(tmp)
	for _, key := range sortedKeys(s.byAsset) {
		for _, o := range s.byAsset[key] {
			b, err := json.Marshal(record(o))
			if err != nil {
				_ = tmp.Close()
				return fmt.Errorf("history: encode observation: %w", err)
			}
			if _, err := w.Write(append(b, '\n')); err != nil {
				_ = tmp.Close()
				return fmt.Errorf("history: write temp log: %w", err)
			}
		}
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("history: flush temp log: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("history: close temp log: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("history: replace %s: %w", s.path, err)
	}
	return nil
}

// logVersion is written into every persisted record, so a future change to the
// stored shape cannot be read as if it were this one. It is the same reasoning
// as the evidence preimage's version line: a format a verifier reads has to
// carry the format it is.
const logVersion = 1

// logRecord is the persisted shape of one observation.
//
// It is deliberately not temporal.Observation. That type is the JSON shape the
// API renders, where severity is its level name for a human reader; this is the
// on-disk shape, where severity is stored as the number the model is actually
// built from. Keeping the two apart means a change to how severity is
// displayed cannot silently change what the log contains, and it keeps the log
// independent of mechanics.Severity having a symmetric JSON encoding.
type logRecord struct {
	Version            int                `json:"v"`
	Asset              mechanics.Asset    `json:"asset"`
	At                 time.Time          `json:"at"`
	Mechanics          mechanics.Mechanic `json:"mechanics"`
	BaseSeverity       uint32             `json:"base_severity"`
	Severity           uint32             `json:"severity"`
	Undetermined       bool               `json:"undetermined"`
	UndeterminedChecks []string           `json:"undetermined_checks,omitempty"`
}

func record(o temporal.Observation) logRecord {
	return logRecord{
		Version:            logVersion,
		Asset:              o.Asset,
		At:                 o.At,
		Mechanics:          o.Mechanics,
		BaseSeverity:       uint32(o.Base),
		Severity:           uint32(o.Severity),
		Undetermined:       o.Undetermined,
		UndeterminedChecks: append([]string{}, o.UndeterminedChecks...),
	}
}

func (r logRecord) observation() temporal.Observation {
	return temporal.Observation{
		Asset:              r.Asset,
		At:                 r.At,
		Mechanics:          r.Mechanics,
		Base:               mechanics.Severity(r.BaseSeverity),
		Severity:           mechanics.Severity(r.Severity),
		Undetermined:       r.Undetermined,
		UndeterminedChecks: append([]string{}, r.UndeterminedChecks...),
	}
}

func sortedKeys(m map[string][]temporal.Observation) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
