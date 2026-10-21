package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
)

// TestNativeAssetIsRefusedBeforeAnyScan pins the CLI's whole answer to the
// network's native asset ("native" or "XLM", any case): an explicit
// explanation naming the ledger fact, a non-zero exit, no scanner call, and
// nothing on stdout a pipeline could mistake for a report or an attestation.
// The message and exit code are a documented contract — docs/cli.md.
func TestNativeAssetIsRefusedBeforeAnyScan(t *testing.T) {
	for _, cmd := range []string{"scan", "attestation", "history", "verify"} {
		for _, arg := range []string{"native", "XLM"} {
			t.Run(cmd+"/"+arg, func(t *testing.T) {
				called := false
				out := &bytes.Buffer{}
				d := commandDeps{
					stdout: out,
					stderr: &bytes.Buffer{},
					scan: func(context.Context, mechanics.Asset) (*mechanics.Report, error) {
						called = true
						return testReport(), nil
					},
					serve: func([]string, *slog.Logger) error { return nil },
				}

				err := runWith([]string{cmd, arg}, d)
				if !errors.Is(err, scan.ErrNativeAsset) {
					t.Fatalf("%s %q: error = %v, want ErrNativeAsset", cmd, arg, err)
				}
				if called {
					t.Errorf("%s %q reached the scanner; the native asset must be refused before any fetch", cmd, arg)
				}
				if out.Len() != 0 {
					t.Errorf("%s %q printed %q to stdout; nothing may read as a report or attestation", cmd, arg, out.String())
				}
				if got := exitCodeForError(err); got != exitUsage {
					t.Errorf("%s %q: exit code = %d, want %d", cmd, arg, got, exitUsage)
				}
				for _, want := range []string{"no issuer", "no authorization flags", "cannot be scanned or attested"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("%s %q: error = %q, want it to say %q", cmd, arg, err, want)
					}
				}
			})
		}
	}
}
