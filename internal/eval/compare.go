package eval

import (
	"sort"
	"strings"
)

// Movement is one field that changed between two recorded runs.
type Movement struct {
	Dir    string `json:"dir"`
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Diff is what moved between two recorded runs over the same corpus.
type Diff struct {
	// SeverityMovements carries base and final severity changes separately, so
	// a capability change is not confused with an escalation change.
	SeverityMovements []Movement `json:"severity_movements"`
	// MechanicsMovements carries changes to the observed mechanic bitset.
	MechanicsMovements []Movement `json:"mechanics_movements"`
	// EvidenceMovements carries changes to the claims a subject rests on, as
	// digests of the sorted claims.
	EvidenceMovements []Movement `json:"evidence_movements"`
	// Undetermined names subjects undetermined in either run. They are excluded
	// from the movement counts because a partial scan is not comparable to a
	// complete one; they are reported separately rather than as a change.
	Undetermined []string `json:"undetermined"`
	// Added and Removed report corpus membership changes rather than dropping
	// a subject silently.
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// Empty reports whether the diff found no movement at all.
func (d Diff) Empty() bool {
	return len(d.SeverityMovements) == 0 &&
		len(d.MechanicsMovements) == 0 &&
		len(d.EvidenceMovements) == 0 &&
		len(d.Undetermined) == 0 &&
		len(d.Added) == 0 &&
		len(d.Removed) == 0
}

// Compare diffs two recorded runs of the same labelled corpus.
//
// Severity, mechanic and evidence movements are reported separately. A subject
// undetermined in either run is reported as undetermined and excluded from the
// movement counts: an answer that was never reached cannot have "moved". A
// subject present in only one run is reported as added or removed, not
// silently dropped.
func Compare(before, after *Record) Diff {
	var d Diff
	past := index(before)
	current := index(after)

	for dir := range past {
		if _, ok := current[dir]; !ok {
			d.Removed = append(d.Removed, dir)
		}
	}
	for dir := range current {
		if _, ok := past[dir]; !ok {
			d.Added = append(d.Added, dir)
		}
	}

	dirs := make([]string, 0, len(current))
	for dir := range current {
		if _, ok := past[dir]; ok {
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		p, c := past[dir], current[dir]
		if p.Undetermined || c.Undetermined {
			d.Undetermined = append(d.Undetermined, dir)
			continue
		}
		if p.Base != c.Base {
			d.SeverityMovements = append(d.SeverityMovements, Movement{
				Dir: dir, Field: "base_severity", Before: p.Base, After: c.Base,
			})
		}
		if p.Severity != c.Severity {
			d.SeverityMovements = append(d.SeverityMovements, Movement{
				Dir: dir, Field: "severity", Before: p.Severity, After: c.Severity,
			})
		}
		if bm, am := joinList(p.Mechanics), joinList(c.Mechanics); bm != am {
			d.MechanicsMovements = append(d.MechanicsMovements, Movement{
				Dir: dir, Field: "mechanics", Before: bm, After: am,
			})
		}
		if bd, ad := evidenceDigest(p.Evidence), evidenceDigest(c.Evidence); bd != ad {
			d.EvidenceMovements = append(d.EvidenceMovements, Movement{
				Dir: dir, Field: "evidence", Before: bd, After: ad,
			})
		}
	}

	sort.Strings(d.Undetermined)
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	return d
}

func index(r *Record) map[string]SubjectResult {
	m := make(map[string]SubjectResult, len(r.Subjects))
	for _, s := range r.Subjects {
		m[s.Dir] = s
	}
	return m
}

// joinList renders a name list stably so a reordered list is not reported as a
// change. An empty list renders as "-", which is distinct from any real name.
func joinList(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	out := append([]string(nil), v...)
	sort.Strings(out)
	return strings.Join(out, ",")
}
