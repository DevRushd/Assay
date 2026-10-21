package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/temporal"
)

// This file implements `assay diff A.json B.json` (issue #464): run the
// internal/temporal detectors over two saved scan reports and print what moved.
//
// The detectors are pure functions over observations. A saved report is not an
// observation yet: Report.Mechanics is deliberately not serialized, because the
// preimage binds the numeric bitset and the JSON document carries the same
// information as mechanic names. The decode step therefore rebuilds the bitset
// from those names before comparing. An unknown name is an error rather than a
// dropped bit — a reader that guessed would make a power this build does not
// understand look absent, which is the same failure the detectors exist to
// prevent.
//
// Nothing here re-derives a verdict. The two documents carry the severities and
// mechanics their scanners produced; this command only subtracts one from the
// other.

// diffResult is the full comparison, for both the text renderer and -json.
type diffResult struct {
	From            string   `json:"from"`
	To              string   `json:"to"`
	Asset           string   `json:"asset"`
	SchemaVersion   int      `json:"schema_version"`
	FromObservation diffSide `json:"from_observation"`
	ToObservation   diffSide `json:"to_observation"`

	Capability     capabilityDiff                  `json:"capability"`
	Severity       temporal.SeverityMovement       `json:"severity"`
	Accountability temporal.AccountabilityMovement `json:"accountability"`
	Evidence       temporal.EvidenceResult         `json:"evidence"`

	// Changed is true only when the comparison was valid and at least one
	// reported axis moved. An unknown or missing comparison is not "unchanged":
	// State carries that distinction per detector.
	Changed bool `json:"changed"`
}

// capabilityDiff reports both directions of the capability comparison. Added is
// the alarming direction; Removed is the reassuring one. Each carries its own
// State, so a caller cannot read an empty list as "no change" when the
// comparison could not be made.
type capabilityDiff struct {
	Added   temporal.CapabilityDelta `json:"added"`
	Removed temporal.CapabilityDelta `json:"removed"`
}

// diffSide is what one saved report said, reduced to the fields a reader needs
// to interpret the comparison. The full report stays in the file; this is the
// context a diff would otherwise make the reader look up.
type diffSide struct {
	At                 time.Time                `json:"at"`
	Severity           mechanics.Severity       `json:"severity"`
	Base               mechanics.Severity       `json:"base_severity"`
	Accountability     mechanics.Accountability `json:"accountability"`
	Mechanics          []string                 `json:"mechanics"`
	Undetermined       bool                     `json:"undetermined"`
	UndeterminedChecks []string                 `json:"undetermined_checks,omitempty"`
}

// runDiff decodes both reports, validates their schema versions, and prints the
// comparison. It refuses two reports for different assets: a transition is
// defined for one asset over time, and subtracting one asset's powers from
// another's is not a change.
func runDiff(args []string, d commandDeps) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the comparison as JSON for scripting")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("diff: %w", err)
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("diff takes exactly two saved reports (A.json B.json)")
	}

	fromRep, err := readReport(fs.Arg(0))
	if err != nil {
		return err
	}
	toRep, err := readReport(fs.Arg(1))
	if err != nil {
		return err
	}
	if fromRep.Asset != toRep.Asset {
		return fmt.Errorf("diff: reports are for different assets (%s and %s); a transition compares one asset over time",
			fromRep.Asset.String(), toRep.Asset.String())
	}

	res, err := diffReports(fs.Arg(0), fs.Arg(1), fromRep, toRep)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(d.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return fmt.Errorf("diff: encode comparison: %w", err)
		}
		return nil
	}
	printDiff(d.stdout, res)
	return nil
}

// readReport reads one saved report and validates the shape version. An absent
// or future schema_version is refused rather than guessed: the command reads
// fields this build knows, and a document written to a different contract may
// mean something else by them.
func readReport(path string) (*mechanics.Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("diff: read %s: %w", path, err)
	}
	var rep mechanics.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("diff: decode %s: %w", path, err)
	}
	if rep.SchemaVersion != mechanics.ReportSchemaVersion {
		return nil, fmt.Errorf("diff: %s has schema_version %d, this build reads %d",
			path, rep.SchemaVersion, mechanics.ReportSchemaVersion)
	}
	return &rep, nil
}

// diffReports builds the comparison. It is separate from the file reads so the
// decode and detector wiring can be tested with reports constructed in memory.
func diffReports(fromPath, toPath string, fromRep, toRep *mechanics.Report) (*diffResult, error) {
	from, err := observationFromSavedReport(fromRep)
	if err != nil {
		return nil, fmt.Errorf("diff: %s: %w", fromPath, err)
	}
	to, err := observationFromSavedReport(toRep)
	if err != nil {
		return nil, fmt.Errorf("diff: %s: %w", toPath, err)
	}

	t := temporal.Between(from, to)
	res := &diffResult{
		From:            fromPath,
		To:              toPath,
		Asset:           t.Asset.String(),
		SchemaVersion:   mechanics.ReportSchemaVersion,
		FromObservation: sideOfObservation(t.From),
		ToObservation:   sideOfObservation(t.To),
		Capability: capabilityDiff{
			Added:   temporal.Added(from, to),
			Removed: temporal.Removed(from, to),
		},
		Severity:       temporal.SeverityTransition(from, to),
		Accountability: temporal.AccountabilityTransition(from, to),
		Evidence:       temporal.EvidenceTransition(from, to),
	}

	if t.State == temporal.Valid {
		res.Changed = res.Capability.Added.Bits != 0 ||
			res.Capability.Removed.Bits != 0 ||
			res.Severity.Before != res.Severity.After ||
			res.Severity.BaseBefore != res.Severity.BaseAfter ||
			res.Accountability.Changed ||
			len(res.Evidence.Events) > 0
	}
	return res, nil
}

// observationFromSavedReport rebuilds the bitset a document omits.
func observationFromSavedReport(rep *mechanics.Report) (temporal.Observation, error) {
	m, err := mechanics.ParseMechanicNames(rep.MechanicNames)
	if err != nil {
		return temporal.Observation{}, fmt.Errorf("diff: %w", err)
	}
	return temporal.Observation{
		Asset:              rep.Asset,
		At:                 rep.ScannedAt.Time(),
		Mechanics:          m,
		Base:               rep.Base,
		Severity:           rep.Severity,
		Accountability:     rep.Accountability,
		Undetermined:       rep.Undetermined,
		UndeterminedChecks: append([]string(nil), rep.UndeterminedChecks...),
		Evidence:           append([]mechanics.Evidence(nil), rep.Evidence...),
	}, nil
}

func sideOfObservation(o temporal.Observation) diffSide {
	return diffSide{
		At:                 o.At,
		Severity:           o.Severity,
		Base:               o.Base,
		Accountability:     o.Accountability,
		Mechanics:          o.Mechanics.Names(),
		Undetermined:       o.Undetermined,
		UndeterminedChecks: append([]string(nil), o.UndeterminedChecks...),
	}
}

// printDiff renders the comparison. Every non-valid detector prints its reason
// rather than an empty movement, so "could not compare" never reads as "no
// change".
func printDiff(w io.Writer, r *diffResult) {
	_, _ = fmt.Fprintf(w, "%s -> %s\n", r.From, r.To)
	_, _ = fmt.Fprintf(w, "asset: %s\n", r.Asset)
	_, _ = fmt.Fprintf(w, "from:  %s\n", sideLine(r.FromObservation))
	_, _ = fmt.Fprintf(w, "to:    %s\n", sideLine(r.ToObservation))

	printCapability(w, "added", r.Capability.Added)
	printCapability(w, "removed", r.Capability.Removed)

	_, _ = fmt.Fprintln(w, "severity:")
	if r.Severity.State != temporal.Valid {
		_, _ = fmt.Fprintf(w, "  %s\n", nonValid(r.Severity.State, r.Severity.Reason))
	} else if r.Severity.BaseBefore == r.Severity.BaseAfter && r.Severity.Before == r.Severity.After {
		_, _ = fmt.Fprintf(w, "  unchanged (base %s, final %s)\n", r.Severity.BaseAfter, r.Severity.After)
	} else {
		_, _ = fmt.Fprintf(w, "  base:\t%s -> %s\n", r.Severity.BaseBefore, r.Severity.BaseAfter)
		_, _ = fmt.Fprintf(w, "  final:\t%s -> %s\n", r.Severity.Before, r.Severity.After)
		_, _ = fmt.Fprintf(w, "  attribution: %s\n", r.Severity.Attribution)
	}

	_, _ = fmt.Fprintln(w, "accountability:")
	if r.Accountability.State != temporal.Valid {
		_, _ = fmt.Fprintf(w, "  %s\n", nonValid(r.Accountability.State, r.Accountability.Reason))
	} else if !r.Accountability.Changed {
		_, _ = fmt.Fprintf(w, "  unchanged (%s)\n", r.Accountability.After)
	} else {
		_, _ = fmt.Fprintf(w, "  %s -> %s\n", r.Accountability.Before, r.Accountability.After)
	}

	_, _ = fmt.Fprintln(w, "evidence:")
	switch {
	case r.Evidence.State != temporal.Valid:
		_, _ = fmt.Fprintf(w, "  %s\n", nonValid(r.Evidence.State, r.Evidence.Reason))
	case r.Evidence.VerdictChanged:
		_, _ = fmt.Fprintf(w, "  verdict changed; no evidence-only comparison\n  %s\n", r.Evidence.Reason)
	case r.Evidence.Unchanged:
		_, _ = fmt.Fprintln(w, "  unchanged")
	default:
		for _, e := range r.Evidence.Events {
			_, _ = fmt.Fprintf(w, "  %s\n", temporal.DescribeEvidenceEvent(e))
		}
	}

	if !r.Changed {
		_, _ = fmt.Fprintln(w, "result: no change (or no comparison, as stated above)")
	} else {
		_, _ = fmt.Fprintln(w, "result: changed")
	}
}

func printCapability(w io.Writer, label string, d temporal.CapabilityDelta) {
	_, _ = fmt.Fprintf(w, "capability %s:\n", label)
	if d.State != temporal.Valid {
		_, _ = fmt.Fprintf(w, "  %s\n", nonValid(d.State, d.Reason))
		return
	}
	if len(d.Names) == 0 {
		_, _ = fmt.Fprintln(w, "  none")
		return
	}
	_, _ = fmt.Fprintf(w, "  %s\n", strings.Join(d.Names, ", "))
}

func sideLine(s diffSide) string {
	line := fmt.Sprintf("%s (severity %s, base %s, accountability %s, mechanics [%s])",
		s.At.UTC().Format(time.RFC3339), s.Severity, s.Base, s.Accountability, strings.Join(s.Mechanics, ", "))
	if s.Undetermined {
		checks := "unnamed check"
		if len(s.UndeterminedChecks) > 0 {
			checks = strings.Join(s.UndeterminedChecks, ", ")
		}
		line += fmt.Sprintf(" -- UNDETERMINED (%s did not complete)", checks)
	}
	return line
}

func nonValid(state temporal.State, reason string) string {
	if reason == "" {
		return string(state)
	}
	return string(state) + ": " + reason
}
