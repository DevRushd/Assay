package eval

import (
	"fmt"
	"sort"

	"github.com/use-assay/assay/internal/mechanics"
)

// CheckMismatch is one per-check expectation a report violates.
type CheckMismatch struct {
	Check string
	Want  string
	Got   string
}

// CheckEvaluation is the per-check result for one subject.
type CheckEvaluation struct {
	Dir string
	// Partial is true when the subject's findings and its labels do not line
	// up: the subject carries no per-check labels, some findings are
	// unlabelled, or some labels have no finding. A partial subject is
	// reported, never silently passed.
	Partial bool
	// Missing names labelled checks with no finding in the report.
	Missing []string
	// Unlabelled names findings the label set does not cover.
	Unlabelled []string
	// Agreed names checks whose finding matched its label.
	Agreed []string
	// Mismatches names checks whose finding disagreed with its label.
	Mismatches []CheckMismatch
}

// OK reports whether the subject was fully labelled and every check agreed.
func (e CheckEvaluation) OK() bool {
	return !e.Partial && len(e.Mismatches) == 0
}

// EvaluateChecks compares a report's findings against the per-check labels of
// one subject. It reports agreement per check rather than only the aggregate
// verdict, so a wrong check cannot be masked by a correct aggregate (#115).
func EvaluateChecks(rep *mechanics.Report, label Label) CheckEvaluation {
	res := CheckEvaluation{Dir: label.Dir}
	if len(label.Checks) == 0 {
		res.Partial = true
	}

	findings := make(map[string]mechanics.Finding, len(rep.Findings))
	for _, f := range rep.Findings {
		findings[f.Check] = f
	}

	for id, want := range label.Checks {
		f, ok := findings[id]
		if !ok {
			res.Missing = append(res.Missing, id)
			res.Partial = true
			continue
		}
		if detail := compareFinding(f, want); detail != "" {
			res.Mismatches = append(res.Mismatches, CheckMismatch{
				Check: id,
				Want:  describeWant(want),
				Got:   detail,
			})
		} else {
			res.Agreed = append(res.Agreed, id)
		}
	}
	for _, f := range rep.Findings {
		if _, ok := label.Checks[f.Check]; !ok {
			res.Unlabelled = append(res.Unlabelled, f.Check)
			res.Partial = true
		}
	}

	sort.Strings(res.Missing)
	sort.Strings(res.Unlabelled)
	sort.Strings(res.Agreed)
	sort.Slice(res.Mismatches, func(i, j int) bool {
		return res.Mismatches[i].Check < res.Mismatches[j].Check
	})
	return res
}

// compareFinding returns "" when the finding matches the label, or a
// human-readable description of the first disagreement.
func compareFinding(f mechanics.Finding, want CheckLabel) string {
	if f.Undetermined != want.Undetermined {
		return fmt.Sprintf("undetermined=%t, want %t", f.Undetermined, want.Undetermined)
	}
	if want.Undetermined {
		// An undetermined check makes no severity or mechanics claim, so there
		// is nothing else to compare.
		return ""
	}
	if f.Severity != want.Severity {
		return fmt.Sprintf("severity %s, want %s", f.Severity, want.Severity)
	}
	if f.Escalation != want.Escalation {
		return fmt.Sprintf("escalation=%t, want %t", f.Escalation, want.Escalation)
	}
	// Compare raw bits rather than names so an accidental renumbering is caught
	// too. Both an unset expected bit and an extra observed bit are failures.
	if f.Mechanics&want.Mechanics != want.Mechanics || f.Mechanics&^want.Mechanics != 0 {
		return fmt.Sprintf("mechanics %v, want %v", f.Mechanics.Names(), want.Mechanics.Names())
	}
	return ""
}

// describeWant renders the expected label for a mismatch message.
func describeWant(w CheckLabel) string {
	if w.Undetermined {
		return "undetermined"
	}
	return fmt.Sprintf("severity %s, mechanics %v, escalation=%t",
		w.Severity, w.Mechanics.Names(), w.Escalation)
}
