package eval_test

import (
	"testing"
	"time"

	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/mechanics"
)

func record(subjects ...eval.SubjectResult) *eval.Record {
	return &eval.Record{
		Version:     "test",
		GeneratedAt: time.Unix(0, 0).UTC(),
		Subjects:    subjects,
	}
}

func subject(dir string, mut ...func(*eval.SubjectResult)) eval.SubjectResult {
	s := eval.SubjectResult{
		Dir:            dir,
		Asset:          "CODE-ISSUER",
		Severity:       "clear",
		Base:           "clear",
		Mechanics:      []string{},
		Accountability: "verified",
		Evidence:       []eval.EvidenceResult{{Source: "horizon", URL: "u", Claim: "c"}},
	}
	for _, m := range mut {
		m(&s)
	}
	return s
}

func TestCompareEmptyWhenUnchanged(t *testing.T) {
	s := subject("aqua")
	if d := eval.Compare(record(s), record(s)); !d.Empty() {
		t.Fatalf("two identical runs reported movement: %+v", d)
	}
}

func TestCompareReportsSeverityMovement(t *testing.T) {
	before := record(subject("doge"))
	after := record(subject("doge", func(s *eval.SubjectResult) { s.Severity = "critical" }))

	d := eval.Compare(before, after)
	if len(d.SeverityMovements) != 1 {
		t.Fatalf("severity movements = %+v, want exactly one", d.SeverityMovements)
	}
	m := d.SeverityMovements[0]
	if m.Dir != "doge" || m.Field != "severity" || m.Before != "clear" || m.After != "critical" {
		t.Fatalf("severity movement reported wrongly: %+v", m)
	}
	if len(d.MechanicsMovements) != 0 || len(d.EvidenceMovements) != 0 {
		t.Fatalf("unrelated movements reported alongside severity: %+v", d)
	}
}

func TestCompareReportsMechanicsAndEvidenceSeparately(t *testing.T) {
	before := record(subject("berkshire"))
	after := record(subject("berkshire", func(s *eval.SubjectResult) {
		s.Mechanics = []string{"auth_clawback_enabled"}
		s.Evidence = append(s.Evidence, eval.EvidenceResult{
			Source: "stellar.expert/directory", URL: "u2", Claim: "listed as scam",
		})
	}))

	d := eval.Compare(before, after)
	if len(d.MechanicsMovements) != 1 || d.MechanicsMovements[0].Field != "mechanics" {
		t.Fatalf("mechanics movement not reported: %+v", d.MechanicsMovements)
	}
	if len(d.EvidenceMovements) != 1 || d.EvidenceMovements[0].Field != "evidence" {
		t.Fatalf("evidence movement not reported: %+v", d.EvidenceMovements)
	}
	if len(d.SeverityMovements) != 0 {
		t.Fatalf("severity moved although it did not change: %+v", d.SeverityMovements)
	}
}

// An undetermined subject is not comparable: an answer that was never reached
// cannot have "moved", and counting it would report a change that the evidence
// does not support. It is reported separately instead.
func TestCompareExcludesUndeterminedSubjects(t *testing.T) {
	before := record(subject("doge"))
	after := record(subject("doge",
		func(s *eval.SubjectResult) { s.Severity = "critical" },
		func(s *eval.SubjectResult) { s.Undetermined = true }))

	d := eval.Compare(before, after)
	if len(d.SeverityMovements) != 0 {
		t.Fatalf("an undetermined subject contributed a severity movement: %+v", d.SeverityMovements)
	}
	if len(d.Undetermined) != 1 || d.Undetermined[0] != "doge" {
		t.Fatalf("undetermined subject not reported separately: %+v", d)
	}
}

// A subject present in one run and not the other is reported, not dropped.
func TestCompareReportsMembershipChanges(t *testing.T) {
	before := record(subject("aqua"), subject("retired"))
	after := record(subject("aqua"), subject("added"))

	d := eval.Compare(before, after)
	if len(d.Added) != 1 || d.Added[0] != "added" {
		t.Fatalf("added subjects = %v, want [added]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "retired" {
		t.Fatalf("removed subjects = %v, want [retired]", d.Removed)
	}
	if !d.Empty() && len(d.SeverityMovements) != 0 {
		t.Fatalf("membership changes leaked into severity movements: %+v", d.SeverityMovements)
	}
}

// Run records the actual classifier output for the labelled corpus, including
// a bound check set and a finding per check, so a later run can be diffed
// against it.
func TestRunRecordsPerCheckOutput(t *testing.T) {
	rec, err := eval.Run(mechanics.NewEngine(), "../mechanics/testdata")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.Version == "" {
		t.Fatal("record carries no version identity")
	}
	if len(rec.Subjects) != len(eval.Corpus()) {
		t.Fatalf("recorded %d subjects, corpus has %d", len(rec.Subjects), len(eval.Corpus()))
	}
	for _, s := range rec.Subjects {
		if len(s.CheckSet) == 0 {
			t.Fatalf("subject %s recorded no check set", s.Dir)
		}
		present := make(map[string]bool, len(s.Findings))
		for _, f := range s.Findings {
			present[f.Check] = true
		}
		for _, id := range s.CheckSet {
			if !present[id] {
				t.Errorf("subject %s binds check %s but recorded no finding for it", s.Dir, id)
			}
		}
	}
}
