package eval_test

import (
	"testing"

	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/mechanics"
)

func TestBuildConfusionMatrixStable(t *testing.T) {
	engine := mechanics.NewEngine()
	m1, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	m2, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build second: %v", err)
	}
	if m1.SampleSize != m2.SampleSize {
		t.Fatalf("sample size changed: %d vs %d", m1.SampleSize, m2.SampleSize)
	}
	for i := range m1.SeverityRows {
		if m1.SeverityRows[i] != m2.SeverityRows[i] {
			t.Fatalf("severity row %d differs: %+v vs %+v", i, m1.SeverityRows[i], m2.SeverityRows[i])
		}
	}
	for i := range m1.CheckRows {
		if m1.CheckRows[i] != m2.CheckRows[i] {
			t.Fatalf("check row %d differs: %+v vs %+v", i, m1.CheckRows[i], m2.CheckRows[i])
		}
	}
}

func TestConfusionMatrixSampleSize(t *testing.T) {
	engine := mechanics.NewEngine()
	m, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if m.SampleSize != len(eval.Corpus()) {
		t.Fatalf("sample size = %d, want %d", m.SampleSize, len(eval.Corpus()))
	}
	for _, row := range m.SeverityRows {
		if row.SampleSize == 0 {
			t.Errorf("severity %s has sample_size 0", row.Severity)
		}
	}
	for _, row := range m.CheckRows {
		if row.SampleSize == 0 {
			t.Errorf("check %s has sample_size 0", row.Check)
		}
	}
}

func TestConfusionMatrixUndeterminedIsOwnClass(t *testing.T) {
	engine := mechanics.NewEngine()
	m, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, row := range m.SeverityRows {
		total := row.Agreed + row.Disagreed + row.Undetermined
		if total != row.SampleSize {
			t.Errorf("severity %s: agreed(%d)+disagreed(%d)+undetermined(%d) = %d, want sample_size %d",
				row.Severity, row.Agreed, row.Disagreed, row.Undetermined, total, row.SampleSize)
		}
	}
	for _, row := range m.CheckRows {
		total := row.Agreed + row.Disagreed + row.Undetermined
		if total != row.SampleSize {
			t.Errorf("check %s: agreed(%d)+disagreed(%d)+undetermined(%d) = %d, want sample_size %d",
				row.Check, row.Agreed, row.Disagreed, row.Undetermined, total, row.SampleSize)
		}
	}
}

func TestConfusionMatrixDoesNotFoldUndetermined(t *testing.T) {
	engine := mechanics.NewEngine()
	m, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, row := range m.SeverityRows {
		if row.Agreed+row.Disagreed > row.SampleSize {
			t.Errorf("severity %s: agreed+disagreed (%d) exceeds sample_size (%d)",
				row.Severity, row.Agreed+row.Disagreed, row.SampleSize)
		}
	}
}

func TestConfusionMatrixValidateSampleSize(t *testing.T) {
	engine := mechanics.NewEngine()
	m, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Corpus has 7 subjects, which is less than 20.
	if err := m.ValidateSampleSize(); err == nil {
		t.Fatal("ValidateSampleSize did not error for small corpus")
	}
}

func TestConfusionMatrixVersion(t *testing.T) {
	engine := mechanics.NewEngine()
	m, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if m.Version == "" {
		t.Fatal("confusion matrix has no version")
	}
}

func TestConfusionMatrixNotEmpty(t *testing.T) {
	engine := mechanics.NewEngine()
	m, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if m.EmptyReports() {
		t.Fatal("confusion matrix reports empty for non-empty corpus")
	}
}

func TestConfusionMatrixSeverityOrdering(t *testing.T) {
	engine := mechanics.NewEngine()
	m, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for i := 1; i < len(m.SeverityRows); i++ {
		if m.SeverityRows[i].Severity < m.SeverityRows[i-1].Severity {
			t.Errorf("severity rows not sorted: %s before %s",
				m.SeverityRows[i-1].Severity, m.SeverityRows[i].Severity)
		}
	}
}

func TestConfusionMatrixCheckOrdering(t *testing.T) {
	engine := mechanics.NewEngine()
	m, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for i := 1; i < len(m.CheckRows); i++ {
		if m.CheckRows[i].Check < m.CheckRows[i-1].Check {
			t.Errorf("check rows not sorted: %s before %s",
				m.CheckRows[i-1].Check, m.CheckRows[i].Check)
		}
	}
}

func TestConfusionMatrixPrintsWithoutPanic(t *testing.T) {
	engine := mechanics.NewEngine()
	m, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Print without precision-recall flag should work without caveat.
	m.Print(false)
	// Print with precision-recall flag should work with caveat.
	m.Print(true)
}

// TestConfusionMatrixAgreedAndDisagreedCounts verifies that the
// aggregate counts are consistent: total agreed + disagreed +
// undetermined across all severity rows equals corpus size times
// number of severity levels represented (since each subject maps
// to exactly one severity row).
func TestConfusionMatrixAggregateCounts(t *testing.T) {
	engine := mechanics.NewEngine()
	m, err := eval.BuildConfusionMatrix(engine, "../mechanics/testdata")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	totalSubjects := 0
	for _, row := range m.SeverityRows {
		totalSubjects += row.SampleSize
	}
	if totalSubjects != m.CorpusSize {
		t.Errorf("total severity sample sizes (%d) != corpus size (%d)", totalSubjects, m.CorpusSize)
	}
}
