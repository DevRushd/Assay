// Command refreshfixture re-captures one corpus fixture from the URLs recorded
// in PROVENANCE.md and prints what changed, so a maintainer can judge whether a
// moved verdict reflects a real change or a regression.
//
// It requires network access and is therefore not run by CI. Invoke it through
// the make target:
//
//	make refresh-fixture SUBJECT=aqua-clear-verified
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/use-assay/assay/internal/fixtures"
)

func main() {
	subject := flag.String("subject", "", "fixture directory to re-capture, e.g. aqua-clear-verified")
	root := flag.String("root", "internal/mechanics/testdata", "fixture root holding PROVENANCE.md and manifest.json")
	dryRun := flag.Bool("dry-run", false, "show the diff without writing")
	flag.Parse()

	if *subject == "" {
		fmt.Fprintln(os.Stderr, "usage: refresh-fixture -subject <dir> [-root <dir>] [-dry-run]")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	r := &fixtures.Refresher{}
	res, err := r.Refresh(ctx, *root, *subject, !*dryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "refresh %s: %v\n", *subject, err)
		os.Exit(1)
	}

	if len(res.Changed) == 0 {
		fmt.Printf("%s: no change; the fixtures match the live sources\n", *subject)
		return
	}
	for _, c := range res.Changed {
		fmt.Print(fixtures.Unified(c.File, c.Old, c.New))
	}
	if *dryRun {
		fmt.Printf("\n%s: %d file(s) would change (dry run; nothing written)\n", *subject, len(res.Changed))
		return
	}
	fmt.Printf("\n%s: %d file(s) updated and capture date refreshed\n", *subject, len(res.Changed))
}
