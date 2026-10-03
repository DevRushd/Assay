// Command eval records the labelled corpus's classification, compares
// two recorded runs, and produces a confusion matrix over the corpus.
//
// It exists so a check change that moves verdicts is visible before it
// merges. Recording writes the per-subject, per-check output under a
// version identity; comparing diffs two records and reports severity,
// mechanic and evidence movements separately, so a change that alters
// many subjects while keeping the aggregate expectations stable cannot
// pass unremarked. The confusion matrix reports agreements and
// disagreements per severity level and per check, with undetermined as
// its own outcome class.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/mechanics"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "eval:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fixtures := fs.String("fixtures", "internal/mechanics/testdata", "corpus fixture root")
	out := fs.String("out", "", "write a run record to this file")
	compare := fs.String("compare", "", "compare the current run against a recorded baseline file")
	strict := fs.Bool("strict", false, "with -compare, exit non-zero when anything moved")
	confusion := fs.Bool("confusion", false, "print the confusion matrix over the labelled corpus")
	precisionRecall := fs.Bool("precision-recall", false, "with -confusion, emit precision and recall with a sample-size caveat")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" && *compare == "" && !*confusion {
		return fmt.Errorf("nothing to do: pass -out to record a run, -compare to diff one, or -confusion to print the matrix")
	}

	rec, err := eval.Run(mechanics.NewEngine(), *fixtures)
	if err != nil {
		return err
	}

	if *out != "" {
		if err := writeRecord(*out, rec); err != nil {
			return err
		}
		fmt.Printf("recorded %d subjects under %s -> %s\n", len(rec.Subjects), rec.Version, *out)
	}

	if *compare != "" {
		base, err := readRecord(*compare)
		if err != nil {
			return err
		}
		diff := eval.Compare(base, rec)
		printDiff(base, rec, diff, *compare)
		if *strict && !diff.Empty() {
			return fmt.Errorf("classifier output moved since %s", *compare)
		}
	}

	if *confusion {
		matrix, err := eval.BuildConfusionMatrix(mechanics.NewEngine(), *fixtures)
		if err != nil {
			return err
		}
		matrix.Print(*precisionRecall)
	}

	return nil
}

func writeRecord(path string, rec *eval.Record) error {
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func readRecord(path string) (*eval.Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec eval.Record
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &rec, nil
}

func printDiff(base, current *eval.Record, diff eval.Diff, baselinePath string) {
	fmt.Printf("eval compare: %s (%s) -> %s\n", base.Version, baselinePath, current.Version)
	if diff.Empty() {
		fmt.Println("no movement: severity, mechanics and evidence are unchanged")
		return
	}

	printMovements("severity", diff.SeverityMovements)
	printMovements("mechanics", diff.MechanicsMovements)
	printMovements("evidence", diff.EvidenceMovements)

	if len(diff.Undetermined) > 0 {
		fmt.Printf("\nundetermined (excluded from movement counts, reported separately):\n")
		for _, dir := range diff.Undetermined {
			fmt.Printf("  %s\n", dir)
		}
	}
	if len(diff.Added) > 0 {
		fmt.Printf("\nadded to the corpus:\n")
		for _, dir := range diff.Added {
			fmt.Printf("  %s\n", dir)
		}
	}
	if len(diff.Removed) > 0 {
		fmt.Printf("\nremoved from the corpus:\n")
		for _, dir := range diff.Removed {
			fmt.Printf("  %s\n", dir)
		}
	}
}

func printMovements(name string, moves []eval.Movement) {
	if len(moves) == 0 {
		return
	}
	fmt.Printf("\n%s movements (%d):\n", name, len(moves))
	for _, m := range moves {
		fmt.Printf("  %s\t%s: %s -> %s\n", m.Dir, m.Field, m.Before, m.After)
	}
}
