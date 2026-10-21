// Command attestfixture prints the attest() arguments for one labelled fixture
// subject, without touching the network.
//
// It exists for the standalone end-to-end test (issue #463): the test must
// submit exactly the values the scanner derives, but must never depend on
// Horizon, StellarExpert or an issuer domain. LoadSubject replays the committed
// fixture with the same decoders a live scan uses, so the values here are the
// values the evidence in internal/mechanics/testdata supports.
//
// The report is bound to the local network and to the scanner identity before
// Params are derived. That is what a real scan does (scan.Scanner sets both),
// and it keeps the e2e preimage under the v4 encoding rather than a fixture-only
// v2 that no live scanner can produce.
//
// Output is the same three-field contract `assay attestation -raw` uses, plus
// the asset first so a shell can bind each line to the address it attests:
//
//	CODE-ISSUER<TAB>SEVERITY<TAB>FLAGS<TAB>EVIDENCE_HASH
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
)

// DefaultNetwork is the passphrase stellar/quickstart's local mode uses. The
// e2e test never points at testnet or pubnet, so the default is the network it
// actually runs against; -network exists so a different local setup can be
// named explicitly.
const DefaultNetwork = "Standalone Network ; February 2017"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "attestfixture:", err)
		os.Exit(1)
	}
}

func run(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("attestfixture", flag.ContinueOnError)
	subject := fs.String("subject", "", "fixture directory under -fixtures (for example aqua-clear-verified)")
	fixtures := fs.String("fixtures", "internal/mechanics/testdata", "corpus fixture root")
	network := fs.String("network", DefaultNetwork, "network passphrase the report is bound to")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("attestfixture: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("attestfixture takes no positional arguments")
	}
	if *subject == "" {
		return fmt.Errorf("-subject is required")
	}

	params, asset, err := paramsForFixture(*fixtures, *subject, *network)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s\t%d\t%d\t%s\n",
		asset, params.Severity, params.Flags, params.EvidenceHash); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// paramsForFixture is separated from flag handling so the three e2e subjects
// can be pinned by a unit test against the committed fixtures.
func paramsForFixture(fixturesDir, subject, network string) (attest.Params, mechanics.Asset, error) {
	s, err := eval.LoadSubject(fixturesDir, subject)
	if err != nil {
		return attest.Params{}, mechanics.Asset{}, fmt.Errorf("load %s: %w", subject, err)
	}
	rep, err := mechanics.NewEngine().Run(context.Background(), s)
	if err != nil {
		return attest.Params{}, mechanics.Asset{}, fmt.Errorf("classify %s: %w", subject, err)
	}
	// Match what a production scan binds. A fixture replay otherwise carries
	// only a check set (v2), which would test a preimage encoding no live
	// attestation uses.
	rep.Network = horizon.Network(network)
	rep.ScannerBound = true

	params, err := attest.FromReport(rep)
	if err != nil {
		return attest.Params{}, mechanics.Asset{}, fmt.Errorf("derive attest() arguments for %s: %w", subject, err)
	}
	return params, rep.Asset, nil
}
