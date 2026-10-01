package temporal_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/temporal"
)

// A sequence fixture is one directory under testdata: observation snapshots
// plus a PROVENANCE.md saying when each was taken and where it came from.
// They exist so the detectors are exercised on committed data — issue #65 —
// rather than only on values constructed inside a test, and so a captured
// sequence can never drift from the provenance that claims to describe it.
type sequence struct {
	dir        string
	names      []string
	at         []time.Time
	obs        []temporal.Observation
	provenance string
}

// loadSequence reads one fixture directory. Observation files are read in
// name order; temporal.Of orders by time itself, so the file order only has to
// be stable for the provenance checks below.
func loadSequence(t *testing.T, dir string) sequence {
	t.Helper()
	base := filepath.Join("testdata", dir)
	s := sequence{dir: dir}

	paths, err := filepath.Glob(filepath.Join(base, "obs*.json"))
	if err != nil {
		t.Fatalf("glob %s: %v", base, err)
	}
	slices.Sort(paths)
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var o temporal.Observation
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if o.At.IsZero() {
			t.Errorf("%s: observation has no capture time; provenance is meaningless without one", path)
		}
		s.names = append(s.names, filepath.Base(path))
		s.at = append(s.at, o.At)
		s.obs = append(s.obs, o)
	}

	prov, err := os.ReadFile(filepath.Join(base, "PROVENANCE.md"))
	if err != nil {
		t.Fatalf("sequence %s has no PROVENANCE.md: %v", dir, err)
	}
	s.provenance = string(prov)
	return s
}

func sequences(t *testing.T) []sequence {
	t.Helper()
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	var out []sequence
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, loadSequence(t, e.Name()))
		}
	}
	slices.SortFunc(out, func(a, b sequence) int {
		return strings.Compare(a.dir, b.dir)
	})
	return out
}

// TestSequencesAreCompleteFixtures guards the shape issue #65 asked for: at
// least four sequences covering the four cases, each a real multi-observation
// fixture with provenance recorded per observation, at least one captured
// rather than constructed, and every constructed one saying so.
func TestSequencesAreCompleteFixtures(t *testing.T) {
	all := sequences(t)
	if len(all) < 4 {
		t.Errorf("have %d sequences under testdata, want at least 4", len(all))
	}

	real := 0
	for _, s := range all {
		if len(s.obs) < 2 {
			t.Errorf("%s: %d observations, want a sequence of at least 2 to compare", s.dir, len(s.obs))
		}
		if !strings.Contains(s.provenance, "Synthetic:") {
			t.Errorf("%s: PROVENANCE.md does not label the sequence synthetic or captured", s.dir)
		}
		if strings.Contains(s.provenance, "Synthetic: false") {
			real++
		}
		for i, name := range s.names {
			if !strings.Contains(s.provenance, "`"+name+"`") {
				t.Errorf("%s: PROVENANCE.md does not record %s", s.dir, name)
			}
			date := s.at[i].UTC().Format("2006-01-02")
			if !strings.Contains(s.provenance, date) {
				t.Errorf("%s: PROVENANCE.md does not record %s as the capture date of %s", s.dir, date, name)
			}
		}
	}
	if real == 0 {
		t.Error("no sequence is captured from a real source; issue #65 requires at least one real sequence")
	}
}

// TestSequencesProduceExpectedTransitions runs every detector over every
// fixture and compares against the expectation recorded here, so each of the
// four cases issue #65 names is pinned by a committed sequence rather than by
// a value a test made up. Every directory under testdata must appear in this
// table — a fixture nobody asserts about cannot catch a regression.
func TestSequencesProduceExpectedTransitions(t *testing.T) {
	cases := []struct {
		dir   string
		why   string
		state temporal.State

		added, removed mechanics.Mechanic
		attribution    temporal.Attribution // empty on a non-valid transition

		baseBefore, baseAfter         mechanics.Severity
		severityBefore, severityAfter mechanics.Severity

		// mechanicsMoved records whether anything in the full bitset moved, so
		// a sequence in which nothing at all changed cannot be asserted as an
		// evidence-only change, and vice versa.
		mechanicsMoved bool

		// reasonContains, when set, is what a non-valid state must explain.
		reasonContains string
	}{
		{
			dir:   "seq1-capability-addition",
			why:   "a capability was added between two captures; base and final severity move with it",
			state: temporal.Valid,

			added:       mechanics.MechClawbackEnabled,
			attribution: temporal.AttributionCapability,

			baseBefore: mechanics.Medium, baseAfter: mechanics.High,
			severityBefore: mechanics.Medium, severityAfter: mechanics.High,

			mechanicsMoved: true,
		},
		{
			dir:   "seq2-reputation-escalation",
			why:   "a curated listing appeared: final severity moves, base never does",
			state: temporal.Valid,

			added:       0,
			attribution: temporal.AttributionReputation,

			baseBefore: mechanics.Clear, baseAfter: mechanics.Clear,
			severityBefore: mechanics.Clear, severityAfter: mechanics.Critical,

			mechanicsMoved: true,
		},
		{
			dir:   "seq3-evidence-only-change",
			why:   "only reported-only evidence moved: no capability, no severity, but the observations are not identical",
			state: temporal.Valid,

			added:       0,
			attribution: temporal.AttributionNone,

			baseBefore: mechanics.Medium, baseAfter: mechanics.Medium,
			severityBefore: mechanics.Medium, severityAfter: mechanics.Medium,

			mechanicsMoved: true,
		},
		{
			dir:   "seq4-no-change-pair",
			why:   "a real re-attestation reproduced the same hash: a made-and-found-nothing answer, not an absence of one",
			state: temporal.Valid,

			added:       0,
			attribution: temporal.AttributionNone,

			baseBefore: mechanics.Clear, baseAfter: mechanics.Clear,
			severityBefore: mechanics.Critical, severityAfter: mechanics.Critical,

			mechanicsMoved: false,
		},
		{
			dir:   "seq5-undetermined-observation",
			why:   "a source did not answer, so no transition can be derived — this is not a no-change result",
			state: temporal.Unknown,

			added: 0,
			// Attribution is deliberately empty: a comparison that could not
			// be made must not claim which axis moved.
			attribution: "",

			baseBefore: mechanics.High, baseAfter: mechanics.High,
			severityBefore: mechanics.High, severityAfter: mechanics.Critical,

			mechanicsMoved: true,
			reasonContains: "reputation",
		},
	}

	asserted := map[string]bool{}
	for _, tc := range cases {
		asserted[tc.dir] = true
		t.Run(tc.dir, func(t *testing.T) {
			s := loadSequence(t, tc.dir)

			tr := temporal.Of(s.obs)
			if tr.State != tc.state {
				t.Fatalf("state = %q, want %q: %s\nwhy this sequence exists: %s",
					tr.State, tc.state, tr.Reason, tc.why)
			}
			if tc.state == temporal.Valid && tr.Reason != "" {
				t.Errorf("a valid transition must not carry a failure reason: %q", tr.Reason)
			}
			if tc.state != temporal.Valid && tr.Reason == "" {
				t.Error("a non-valid state must say what was missing, or it is indistinguishable from a silent failure")
			}
			if tc.reasonContains != "" && !strings.Contains(tr.Reason, tc.reasonContains) {
				t.Errorf("reason %q does not name %q", tr.Reason, tc.reasonContains)
			}

			// The transition must compare the two most recent observations,
			// whichever order the files are in.
			times := slices.Clone(s.at)
			sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
			if !tr.From.At.Equal(times[len(times)-2]) || !tr.To.At.Equal(times[len(times)-1]) {
				t.Errorf("did not compare the two most recent observations: from=%v to=%v",
					tr.From.At, tr.To.At)
			}
			if moved := tr.From.Mechanics != tr.To.Mechanics; moved != tc.mechanicsMoved {
				t.Errorf("full bitset moved = %t, want %t (from %d to %d)",
					moved, tc.mechanicsMoved, tr.From.Mechanics, tr.To.Mechanics)
			}

			added := temporal.Added(tr.From, tr.To)
			if added.State != tc.state {
				t.Errorf("added state = %q, want %q: %s", added.State, tc.state, added.Reason)
			}
			if added.Bits != tc.added {
				t.Errorf("added = %v, want %v", added.Names, tc.added.Names())
			}
			removed := temporal.Removed(tr.From, tr.To)
			if removed.State != tc.state {
				t.Errorf("removed state = %q, want %q: %s", removed.State, tc.state, removed.Reason)
			}
			if removed.Bits != tc.removed {
				t.Errorf("removed = %v, want %v", removed.Names, tc.removed.Names())
			}

			sev := temporal.SeverityTransition(tr.From, tr.To)
			if sev.State != tc.state {
				t.Errorf("severity state = %q, want %q", sev.State, tc.state)
			}
			if sev.Attribution != tc.attribution {
				t.Errorf("attribution = %q, want %q", sev.Attribution, tc.attribution)
			}
			if tc.state != temporal.Valid {
				// A comparison that could not be made must not report a
				// movement: the fields stay empty rather than guessing.
				if sev.BaseBefore != 0 || sev.BaseAfter != 0 || sev.Before != 0 || sev.After != 0 {
					t.Errorf("a %q transition reported a severity movement: %+v", tc.state, sev)
				}
				return
			}
			if sev.BaseBefore != tc.baseBefore || sev.BaseAfter != tc.baseAfter {
				t.Errorf("base = %v -> %v, want %v -> %v",
					sev.BaseBefore, sev.BaseAfter, tc.baseBefore, tc.baseAfter)
			}
			if sev.Before != tc.severityBefore || sev.After != tc.severityAfter {
				t.Errorf("severity = %v -> %v, want %v -> %v",
					sev.Before, sev.After, tc.severityBefore, tc.severityAfter)
			}
		})
	}

	for _, s := range sequences(t) {
		if !asserted[s.dir] {
			t.Errorf("sequence %s has no expectations in TestSequencesProduceExpectedTransitions; every fixture must be asserted", s.dir)
		}
	}
}
