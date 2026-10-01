package eval

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/version"
)

// SeverityEntry is one row of the confusion matrix for a severity level.
type SeverityEntry struct {
	Severity     string `json:"severity"`
	Agreed       int    `json:"agreed"`
	Disagreed    int    `json:"disagreed"`
	Undetermined int    `json:"undetermined"`
	SampleSize   int    `json:"sample_size"`
}

// CheckEntry is one row of the confusion matrix for a check.
type CheckEntry struct {
	Check        string `json:"check"`
	Agreed       int    `json:"agreed"`
	Disagreed    int    `json:"disagreed"`
	Undetermined int    `json:"undetermined"`
	SampleSize   int    `json:"sample_size"`
}

// ConfusionMatrix is the full classification agreement matrix over the corpus.
type ConfusionMatrix struct {
	Version      string          `json:"version"`
	SampleSize   int             `json:"sample_size"`
	CorpusSize   int             `json:"corpus_size"`
	SeverityRows []SeverityEntry `json:"severity_rows"`
	CheckRows    []CheckEntry    `json:"check_rows"`
}

// severityValues returns all defined severity levels in order.
func severityValues() []mechanics.Severity {
	return []mechanics.Severity{
		mechanics.Clear, mechanics.Low, mechanics.Medium,
		mechanics.High, mechanics.Critical, mechanics.Unevaluated,
	}
}

// BuildConfusionMatrix classifies every subject in the corpus against its
// label, producing a confusion matrix over severity levels and checks.
// Undetermined scans are counted as their own outcome class and are never
// folded into agreement or disagreement.
func BuildConfusionMatrix(engine *mechanics.Engine, fixturesDir string) (*ConfusionMatrix, error) {
	labels := Corpus()
	corpusSize := len(labels)

	matrix := &ConfusionMatrix{
		Version:    version.Version,
		SampleSize: corpusSize,
		CorpusSize: corpusSize,
	}

	// Initialise severity rows for every severity level that appears in the corpus.
	severityLabels := make(map[mechanics.Severity]bool)
	for _, l := range labels {
		severityLabels[l.Base] = true
	}
	for sev := range severityLabels {
		matrix.SeverityRows = append(matrix.SeverityRows, SeverityEntry{
			Severity: sev.String(),
		})
	}
	sort.Slice(matrix.SeverityRows, func(i, j int) bool {
		return matrix.SeverityRows[i].Severity < matrix.SeverityRows[j].Severity
	})

	// Initialise check rows for every check in the corpus.
	checkIDs := make(map[string]bool)
	for _, l := range labels {
		for id := range l.Checks {
			checkIDs[id] = true
		}
	}
	for id := range checkIDs {
		matrix.CheckRows = append(matrix.CheckRows, CheckEntry{
			Check: id,
		})
	}
	sort.Slice(matrix.CheckRows, func(i, j int) bool {
		return matrix.CheckRows[i].Check < matrix.CheckRows[j].Check
	})

	// Run every subject and classify.
	for _, label := range labels {
		s, err := LoadSubject(fixturesDir, label.Dir)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", label.Dir, err)
		}
		rep, err := engine.Run(context.Background(), s)
		if err != nil {
			return nil, fmt.Errorf("run %s: %w", label.Dir, err)
		}
		classifySubject(rep, label, matrix)
	}

	// Compute sample sizes for each row.
	computeSampleSizes(labels, matrix)

	return matrix, nil
}

func classifySubject(rep *mechanics.Report, label Label, matrix *ConfusionMatrix) {
	if rep.Undetermined {
		// An undetermined scan is its own outcome class.
		for i := range matrix.SeverityRows {
			if matrix.SeverityRows[i].Severity == label.Base.String() {
				matrix.SeverityRows[i].Undetermined++
			}
		}
		for i := range matrix.CheckRows {
			if _, hasCheck := label.Checks[matrix.CheckRows[i].Check]; hasCheck {
				matrix.CheckRows[i].Undetermined++
			}
		}
		return
	}

	// Classify by severity level: does the classifier's final severity
	// match the label's base severity?
	for i := range matrix.SeverityRows {
		if matrix.SeverityRows[i].Severity == label.Base.String() {
			if rep.Severity == label.Base {
				matrix.SeverityRows[i].Agreed++
			} else {
				matrix.SeverityRows[i].Disagreed++
			}
		}
	}

	// Classify by check.
	for checkID, want := range label.Checks {
		finding, ok := findFinding(rep, checkID)
		for i := range matrix.CheckRows {
			if matrix.CheckRows[i].Check != checkID {
				continue
			}
			if !ok || finding.Undetermined {
				matrix.CheckRows[i].Undetermined++
				continue
			}
			if findingsMatch(finding, want) {
				matrix.CheckRows[i].Agreed++
			} else {
				matrix.CheckRows[i].Disagreed++
			}
		}
	}
}

func findFinding(rep *mechanics.Report, checkID string) (mechanics.Finding, bool) {
	for _, f := range rep.Findings {
		if f.Check == checkID {
			return f, true
		}
	}
	return mechanics.Finding{}, false
}

func findingsMatch(finding mechanics.Finding, want CheckLabel) bool {
	if finding.Undetermined != want.Undetermined {
		return false
	}
	if want.Undetermined {
		return true
	}
	if finding.Severity != want.Severity {
		return false
	}
	if finding.Escalation != want.Escalation {
		return false
	}
	if finding.Mechanics&want.Mechanics != want.Mechanics || finding.Mechanics&^want.Mechanics != 0 {
		return false
	}
	return true
}

func computeSampleSizes(labels []Label, matrix *ConfusionMatrix) {
	for i := range matrix.SeverityRows {
		sev := mechanics.Severity(0)
		for _, s := range severityValues() {
			if s.String() == matrix.SeverityRows[i].Severity {
				sev = s
				break
			}
		}
		for _, l := range labels {
			if l.Base == sev {
				matrix.SeverityRows[i].SampleSize++
			}
		}
	}
	for i := range matrix.CheckRows {
		for _, l := range labels {
			if _, ok := l.Checks[matrix.CheckRows[i].Check]; ok {
				matrix.CheckRows[i].SampleSize++
			}
		}
	}
}

// Print prints the confusion matrix to stdout with sample size on every row.
// If precision-recall is requested, it also emits those metrics with a caveat
// about the small sample size.
func (m *ConfusionMatrix) Print(precisionRecall bool) {
	fmt.Printf("confusion matrix (sample size: %d subjects, corpus %s)\n", m.SampleSize, m.Version)
	fmt.Println()

	fmt.Println("=== severity level agreement ===")
	fmt.Printf("%-12s %-10s %-12s %-14s %s\n", "severity", "agreed", "disagreed", "undetermined", "sample_size")
	for _, row := range m.SeverityRows {
		fmt.Printf("%-12s %-10d %-12d %-14d %d\n", row.Severity, row.Agreed, row.Disagreed, row.Undetermined, row.SampleSize)
	}
	fmt.Println()

	fmt.Println("=== check agreement ===")
	fmt.Printf("%-18s %-10s %-12s %-14s %s\n", "check", "agreed", "disagreed", "undetermined", "sample_size")
	for _, row := range m.CheckRows {
		fmt.Printf("%-18s %-10d %-12d %-14d %d\n", row.Check, row.Agreed, row.Disagreed, row.Undetermined, row.SampleSize)
	}
	fmt.Println()

	if precisionRecall {
		m.printPrecisionRecallCaveat()
	}
}

func (m *ConfusionMatrix) printPrecisionRecallCaveat() {
	fmt.Println("=== precision / recall ===")
	fmt.Println("WARNING: precision and recall are computed from a sample of only")
	fmt.Printf("%d subjects. This sample size cannot support statistically\n", m.SampleSize)
	fmt.Println("meaningful rates. These figures are illustrative only and must not")
	fmt.Println("be cited as evidence of classifier accuracy.")
	fmt.Println()

	totalAgreed := 0
	totalDisagreed := 0
	totalUndetermined := 0
	for _, row := range m.SeverityRows {
		totalAgreed += row.Agreed
		totalDisagreed += row.Disagreed
		totalUndetermined += row.Undetermined
	}
	totalClassified := totalAgreed + totalDisagreed

	if totalClassified > 0 {
		precision := float64(totalAgreed) / float64(totalClassified)
		fmt.Printf("precision (severity): %.4f  (=%d/%d)\n", precision, totalAgreed, totalClassified)
	}
	if totalAgreed+totalUndetermined > 0 {
		recall := float64(totalAgreed) / float64(totalAgreed+totalUndetermined)
		fmt.Printf("recall (severity): %.4f  (=%d/%d)\n", recall, totalAgreed, totalAgreed+totalUndetermined)
	}
}

// String returns a compact string representation of the confusion matrix.
func (m *ConfusionMatrix) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "confusion matrix: %d subjects, v%s\n", m.SampleSize, m.Version)
	for _, row := range m.SeverityRows {
		fmt.Fprintf(&b, "  %s: agreed=%d disagreed=%d undetermined=%d sample=%d\n",
			row.Severity, row.Agreed, row.Disagreed, row.Undetermined, row.SampleSize)
	}
	for _, row := range m.CheckRows {
		fmt.Fprintf(&b, "  %s: agreed=%d disagreed=%d undetermined=%d sample=%d\n",
			row.Check, row.Agreed, row.Disagreed, row.Undetermined, row.SampleSize)
	}
	return b.String()
}

// EmptyReports whether the matrix has no subjects.
func (m *ConfusionMatrix) EmptyReports() bool {
	return m.SampleSize == 0
}

// ValidateSampleSize returns an error if the sample is too small to
// support the requested statistical operation. It never produces a
// precision or recall number without an explicit flag and a stated caveat.
func (m *ConfusionMatrix) ValidateSampleSize() error {
	if m.SampleSize < 20 {
		return fmt.Errorf("sample size %d is too small to support statistical claims; precision and recall require an explicit flag and a stated caveat", m.SampleSize)
	}
	return nil
}
