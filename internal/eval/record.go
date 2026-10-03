package eval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/version"
)

// FindingResult is one check's output in a recorded run.
type FindingResult struct {
	Check        string   `json:"check"`
	Severity     string   `json:"severity"`
	Escalation   bool     `json:"escalation"`
	Undetermined bool     `json:"undetermined"`
	Mechanics    []string `json:"mechanics"`
	UndeterminedBySource map[string]int `json:"undetermined_by_source,omitempty"`
	UndeterminedRate string `json:"undetermined_rate,omitempty"`
}

// EvidenceResult is one attributed claim in a recorded run. Retrieval times are
// excluded: they are outside evidence_hash and would make every run differ even
// when nothing changed.
type EvidenceResult struct {
	Source string `json:"source"`
	URL    string `json:"url"`
	Claim  string `json:"claim"`
}

// SubjectResult is one subject's classification in a recorded run.
type SubjectResult struct {
	Dir                     string                   `json:"dir"`
	Asset                   string                   `json:"asset"`
	Severity                string                   `json:"severity"`
	Base                    string                   `json:"base_severity"`
	Escalated               bool                     `json:"escalated"`
	Undetermined            bool                     `json:"undetermined"`
	UndeterminedChecks      []string                 `json:"undetermined_checks,omitempty"`
	UndeterminedBySource    map[string]int           `json:"undetermined_by_source,omitempty"`
	UndeterminedRate        string                   `json:"undetermined_rate,omitempty"`
	Mechanics               []string                 `json:"mechanics"`
	Accountability          string                   `json:"accountability"`
	CheckSet                []string                 `json:"checks,omitempty"`
	Findings                []FindingResult          `json:"findings"`
	Evidence                []EvidenceResult         `json:"evidence"`
	ObservationWindowStart  time.Time                `json:"observation_window_start,omitempty"`
	ObservationWindowEnd    time.Time                `json:"observation_window_end,omitempty"`
}

// Record is the classifier output for the whole corpus under one version.
type Record struct {
	Version     string          `json:"version"`
	GeneratedAt time.Time       `json:"generated_at"`
	Subjects    []SubjectResult `json:"subjects"`
}

// Run classifies every subject in the corpus and records the output.
func Run(engine *mechanics.Engine, fixturesDir string) (*Record, error) {
	rec := &Record{Version: version.Version, GeneratedAt: time.Now().UTC()}
	for _, label := range Corpus() {
		s, err := LoadSubject(fixturesDir, label.Dir)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", label.Dir, err)
		}
		rep, err := engine.Run(context.Background(), s)
		if err != nil {
			return nil, fmt.Errorf("run %s: %w", label.Dir, err)
		}
		rec.Subjects = append(rec.Subjects, recordSubject(label.Dir, rep))
	}
	return rec, nil
}

func recordSubject(dir string, rep *mechanics.Report) SubjectResult {
	sr := SubjectResult{
		Dir:                    dir,
		Asset:                  rep.Asset.String(),
		Severity:               rep.Severity.String(),
		Base:                   rep.Base.String(),
		Escalated:              rep.Escalated,
		Undetermined:           rep.Undetermined,
		UndeterminedChecks:     append([]string(nil), rep.UndeterminedChecks...),
		UndeterminedBySource:   rep.UndeterminedBySource,
		UndeterminedRate:       rep.UndeterminedRate,
		Mechanics:              append([]string(nil), rep.MechanicNames...),
		Accountability:         string(rep.Accountability),
		CheckSet:               append([]string(nil), rep.CheckSet...),
		Findings:               make([]FindingResult, 0, len(rep.Findings)),
		Evidence:               make([]EvidenceResult, 0, len(rep.Evidence)),
		ObservationWindowStart: rep.ObservationWindowStart,
		ObservationWindowEnd:   rep.ObservationWindowEnd,
	}
	for _, f := range rep.Findings {
		sr.Findings = append(sr.Findings, FindingResult{
			Check:                    f.Check,
			Severity:                 f.Severity.String(),
			Escalation:               f.Escalation,
			Undetermined:             f.Undetermined,
			UndeterminedBySource:     f.UndeterminedBySource,
			UndeterminedRate:         f.UndeterminedRate,
			Mechanics:                append([]string(nil), f.MechanicNames...),
		})
	}
	for _, e := range rep.Evidence {
		sr.Evidence = append(sr.Evidence, EvidenceResult{Source: e.Source, URL: e.URL, Claim: e.Claim})
	}
	return sr
}

// evidenceDigest is a stable digest over one subject's claims, used to report
// an evidence movement compactly. Retrieval times are excluded so a re-run of
// unchanged evidence digests the same.
func evidenceDigest(ev []EvidenceResult) string {
	lines := make([]string, 0, len(ev))
	for _, e := range ev {
		lines = append(lines, e.Source+"\t"+e.URL+"\t"+e.Claim)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}
