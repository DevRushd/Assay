package eval

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
)

// CheckLabel is the expected output of one check on one subject.
//
// Undetermined and Severity are separate labels on purpose: a check that could
// not conclude is compared against an undetermined label, not against a
// severity, because an undetermined finding makes no severity claim and
// comparing it to one would measure a value the check never produced.
type CheckLabel struct {
	// Undetermined asserts whether the check could not conclude.
	Undetermined bool
	// Severity is the expected level for a determined check.
	Severity mechanics.Severity
	// Escalation pins the finding's escalation flag.
	Escalation bool
	// Mechanics pins the finding's mechanic bitset exactly.
	Mechanics mechanics.Mechanic
}

// Label is the expected classification of one corpus subject. It carries the
// aggregate expectation (Base/Severity/Escalated/Accountability) and the
// per-check expectations (Checks) that #115 requires, so a wrong check cannot
// hide behind a right total. Labels are parsed from the subject's
// metadata.json beside its fixtures; Corpus never constructs one from
// anything else.
type Label struct {
	// Dir is the fixture directory under the corpus root.
	Dir string
	// Why states what the subject proves. It is printed on failure so a
	// maintainer learns what they broke rather than only seeing a number move.
	Why string

	// Unknown marks a subject whose metadata deliberately states no verdict
	// (state "unknown"): the verdict is genuinely uncertain and recording one
	// would be a guess. Tests that compare verdicts skip an unknown subject
	// instead of inventing an expectation for it, while the subject stays in
	// the corpus so its fixtures are still loaded and its provenance still
	// enforced (#112).
	Unknown bool

	Base      mechanics.Severity
	Severity  mechanics.Severity
	Escalated bool
	// Undetermined asserts whether the whole report is a partial answer: at
	// least one check could not conclude because a source it depends on was
	// unreachable. It is separate from the per-check Undetermined label so the
	// aggregate state is pinned too, and so a report that is partial for an
	// unexpected reason fails the eval rather than passing on a per-check
	// coincidence.
	Undetermined   bool
	Accountability mechanics.Accountability

	// Checks carries per-check expectations keyed by check ID. A subject with
	// an empty map is reported as partially evaluated rather than silently
	// passing.
	Checks map[string]CheckLabel
}

// subjectDirs is the labelled set's membership: every entry must carry a
// metadata.json under the corpus root or Corpus fails. Membership is the only
// thing about the set that lives in Go code; the verdicts, capture dates,
// source URLs and rationale live in each subject's metadata.json beside its
// fixtures, so they are edited next to the files they describe (#112).
var subjectDirs = []string{
	"aqua-clear-verified",
	"shx-clear-flagslocked",
	"xrp-clear-unlocked",
	"usdz-clawback-regulated",
	"usdc-revocable-regulated",
	"berkshire-clawback-scam",
	"doge-noflags-scam",
	"doge-reputation-outage",
	"velo-no-home-domain",
	"synthetic-redirect-off-host",
}

// metadataSchemaVersion is the schema_version Corpus accepts. It is pinned
// rather than defaulted so a future layout change is a loud load failure in
// every subject at once, not a silent misparse of the fields it kept.
const metadataSchemaVersion = 1

// nonFixtureFiles are the files a subject directory may hold without being
// listed in metadata.json: the metadata itself, and the optional README that
// documents a synthetic fixture's construction. Everything else in the
// directory is a fixture file and must be listed with its source URL and
// capture date, so a file cannot sit beside the corpus unprovenanced.
var nonFixtureFiles = map[string]bool{
	"metadata.json": true,
	"README.md":     true,
}

// metadata is the on-disk form of one subject's labels, stored as
// <fixturesDir>/<dir>/metadata.json. Field names and the valid/unknown states
// are documented in docs/eval.md.
type metadata struct {
	SchemaVersion int         `json:"schema_version"`
	Subject       string      `json:"subject"`
	Why           string      `json:"why"`
	Files         []fileEntry `json:"files"`
	Expected      expected    `json:"expected"`
}

// fileEntry is one fixture file, the URL it was captured from, and the UTC
// date of that capture. Note carries an optional qualifier (an abridged
// payload, a constructed error marker, a derived synthetic file).
type fileEntry struct {
	File     string `json:"file"`
	URL      string `json:"url"`
	Captured string `json:"captured"`
	Note     string `json:"note,omitempty"`
}

// expected is the labelled verdict. State selects between the two states:
// "valid" carries a full verdict, "unknown" refuses to state one.
//
// The verdict fields are pointers so presence can be enforced: a "valid"
// subject that omits, say, accountability fails to load rather than silently
// reading as the empty value, because a label the file never stated must not
// become an expectation the eval enforces.
type expected struct {
	State          string                    `json:"state"`
	Base           *mechanics.Severity       `json:"base,omitempty"`
	Severity       *mechanics.Severity       `json:"severity,omitempty"`
	Escalated      *bool                     `json:"escalated,omitempty"`
	Undetermined   *bool                     `json:"undetermined,omitempty"`
	Accountability *mechanics.Accountability `json:"accountability,omitempty"`
	Checks         map[string]expectedCheck  `json:"checks,omitempty"`
}

// expectedCheck is one per-check expectation. Severity is a pointer for the
// same reason as in expected: a determined check must state one, and an
// undetermined check must state none.
type expectedCheck struct {
	Undetermined bool                `json:"undetermined,omitempty"`
	Severity     *mechanics.Severity `json:"severity,omitempty"`
	Escalation   bool                `json:"escalation,omitempty"`
	Mechanics    []string            `json:"mechanics,omitempty"`
}

// Corpus is the labelled set, loaded from the subjects' metadata.json files
// under fixturesDir.
//
// Every entry of subjectDirs must carry a well-formed metadata.json, or
// Corpus fails: a subject without metadata, or with metadata that does not
// parse, has no expectation to eval against, and the eval refuses to proceed
// on a guessed one (#112). The per-check labels come from the same file as
// the aggregate labels, so the two cannot describe different runs: TestEval
// and TestEvalPerCheck both iterate this corpus.
//
// Fixtures and provenance are under internal/mechanics/testdata; the schema
// and the labelling rationale are in docs/eval.md.
func Corpus(fixturesDir string) ([]Label, error) {
	labels := make([]Label, 0, len(subjectDirs))
	for _, dir := range subjectDirs {
		l, err := loadLabel(fixturesDir, dir)
		if err != nil {
			return nil, err
		}
		labels = append(labels, l)
	}
	return labels, nil
}

// loadLabel reads and validates one subject's metadata.json.
//
// The parse is strict in both directions: fields a "valid" verdict must state
// are required rather than defaulted, and fields an "unknown" verdict must
// not state are rejected rather than ignored, so a half-written subject fails
// to load instead of quietly becoming a weaker label.
func loadLabel(fixturesDir, dir string) (Label, error) {
	base := filepath.Join(fixturesDir, dir)
	b, err := os.ReadFile(filepath.Join(base, "metadata.json"))
	if err != nil {
		return Label{}, fmt.Errorf("corpus subject %s: read metadata.json: %w", dir, err)
	}
	var m metadata
	if err := json.Unmarshal(b, &m); err != nil {
		return Label{}, fmt.Errorf("corpus subject %s: decode metadata.json: %w", dir, err)
	}
	if m.SchemaVersion != metadataSchemaVersion {
		return Label{}, fmt.Errorf("corpus subject %s: metadata schema_version = %d, want %d",
			dir, m.SchemaVersion, metadataSchemaVersion)
	}
	if m.Subject != dir {
		return Label{}, fmt.Errorf("corpus subject %s: metadata names subject %q, want the directory name",
			dir, m.Subject)
	}
	if strings.TrimSpace(m.Why) == "" {
		return Label{}, fmt.Errorf("corpus subject %s: metadata carries no why", dir)
	}
	if err := checkFiles(base, m.Files); err != nil {
		return Label{}, fmt.Errorf("corpus subject %s: %w", dir, err)
	}

	label := Label{Dir: dir, Why: m.Why}
	switch m.Expected.State {
	case "valid":
		v := m.Expected
		if v.Base == nil || v.Severity == nil || v.Escalated == nil ||
			v.Undetermined == nil || v.Accountability == nil {
			return Label{}, fmt.Errorf("corpus subject %s: valid verdict must state base, severity, "+
				"escalated, undetermined and accountability", dir)
		}
		switch *v.Accountability {
		case mechanics.AccountabilityUnknown, mechanics.AccountabilityUnverified,
			mechanics.AccountabilityVerified:
		default:
			return Label{}, fmt.Errorf("corpus subject %s: unknown accountability %q",
				dir, *v.Accountability)
		}
		if len(v.Checks) == 0 {
			return Label{}, fmt.Errorf("corpus subject %s: valid verdict must state per-check expectations", dir)
		}
		checks, err := loadChecks(v.Checks)
		if err != nil {
			return Label{}, fmt.Errorf("corpus subject %s: %w", dir, err)
		}
		label.Base = *v.Base
		label.Severity = *v.Severity
		label.Escalated = *v.Escalated
		label.Undetermined = *v.Undetermined
		label.Accountability = *v.Accountability
		label.Checks = checks
	case "unknown":
		v := m.Expected
		if v.Base != nil || v.Severity != nil || v.Escalated != nil ||
			v.Undetermined != nil || v.Accountability != nil || len(v.Checks) > 0 {
			return Label{}, fmt.Errorf("corpus subject %s: unknown verdict must not carry a "+
				"verdict alongside its state", dir)
		}
		label.Unknown = true
	default:
		return Label{}, fmt.Errorf("corpus subject %s: expected.state = %q, want %q or %q",
			dir, m.Expected.State, "valid", "unknown")
	}
	return label, nil
}

// loadChecks converts one subject's per-check expectations.
func loadChecks(in map[string]expectedCheck) (map[string]CheckLabel, error) {
	out := make(map[string]CheckLabel, len(in))
	for id, c := range in {
		if c.Undetermined {
			if c.Severity != nil || c.Escalation || len(c.Mechanics) > 0 {
				return nil, fmt.Errorf("check %s: undetermined label must not carry a severity, "+
					"escalation or mechanics — an undetermined finding makes no claim", id)
			}
			out[id] = CheckLabel{Undetermined: true}
			continue
		}
		if c.Severity == nil {
			return nil, fmt.Errorf("check %s: determined label must state a severity", id)
		}
		mechanicsBits, err := mechanics.ParseMechanicNames(c.Mechanics)
		if err != nil {
			return nil, fmt.Errorf("check %s: %w", id, err)
		}
		out[id] = CheckLabel{
			Severity:   *c.Severity,
			Escalation: c.Escalation,
			Mechanics:  mechanicsBits,
		}
	}
	return out, nil
}

// checkFiles pins a subject's file list to its directory contents in both
// directions: every listed file must exist, and every fixture file present
// must be listed. Either direction failing means the fixtures and their
// provenance have drifted apart — a re-capture that renamed a payload, or a
// new file with no URL and no date — and the eval must not proceed on
// provenance it cannot state (#112).
func checkFiles(base string, files []fileEntry) error {
	if len(files) == 0 {
		return fmt.Errorf("metadata records no files")
	}
	listed := make(map[string]bool, len(files))
	for _, f := range files {
		if f.File == "" {
			return fmt.Errorf("metadata lists a file with no name")
		}
		if f.File != filepath.Base(f.File) {
			return fmt.Errorf("metadata lists %q, want a bare file name", f.File)
		}
		if listed[f.File] {
			return fmt.Errorf("metadata lists file %q twice", f.File)
		}
		listed[f.File] = true
		if f.Captured == "" {
			return fmt.Errorf("file %s: no capture date", f.File)
		}
		if _, err := time.Parse("2006-01-02", f.Captured); err != nil {
			return fmt.Errorf("file %s: capture date %q, want YYYY-MM-DD", f.File, f.Captured)
		}
		u, err := url.Parse(f.URL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("file %s: url %q is not an absolute URL", f.File, f.URL)
		}
		if _, err := os.Stat(filepath.Join(base, f.File)); err != nil {
			return fmt.Errorf("metadata lists file %s which is not in the fixture directory: %w",
				f.File, err)
		}
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return fmt.Errorf("read fixture directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || nonFixtureFiles[e.Name()] {
			continue
		}
		if !listed[e.Name()] {
			return fmt.Errorf("fixture file %q is not listed in metadata.json with its source "+
				"URL and capture date", e.Name())
		}
	}
	return nil
}
