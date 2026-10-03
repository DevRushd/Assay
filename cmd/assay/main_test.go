package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

const cliIssuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

// testReport is a complete, attestable report with a deterministic shape. From
// it, attest.FromReport derives severity, flags and evidence_hash, so the -raw
// golden can be pinned against the exact bytes a pipeline consumes.
func testReport() *mechanics.Report {
	return &mechanics.Report{
		Asset:              mechanics.Asset{Code: "USDC", Issuer: cliIssuer},
		Severity:           mechanics.Medium,
		Base:               mechanics.Medium,
		Accountability:     mechanics.AccountabilityVerified,
		CheckSet:           []string{"capability", "mutability", "reputation", "sep1-domain"},
		Findings:           []mechanics.Finding{},
		Evidence:           []mechanics.Evidence{},
		UndeterminedChecks: []string{},
		ScannedAt:          time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC),
	}
}

// deps builds a commandDeps whose scan returns the given report, with captured
// output. It records calls to the injected serve so dispatch can be asserted.
func deps(rep *mechanics.Report, scanErr error) (commandDeps, *bytes.Buffer, *bytes.Buffer, *[]string) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	serveArgs := &[]string{}
	return commandDeps{
		stdout: out,
		stderr: errOut,
		scan: func(context.Context, mechanics.Asset) (*mechanics.Report, error) {
			return rep, scanErr
		},
		serve: func(args []string, _ *slog.Logger) error {
			*serveArgs = args
			return nil
		},
	}, out, errOut, serveArgs
}

// TestDispatch covers every subcommand and an unknown one. A dispatch
// regression is the kind that silently runs the wrong command.
func TestDispatch(t *testing.T) {
	asset := "USDC-" + cliIssuer

	t.Run("scan", func(t *testing.T) {
		d, out, _, _ := deps(testReport(), nil)
		if err := runWith([]string{"scan", asset}, d); err != nil {
			t.Fatalf("scan: %v", err)
		}
		var got mechanics.Report
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatalf("scan output is not JSON: %v", err)
		}
		if got.Asset.Code != "USDC" {
			t.Errorf("scan output asset = %v", got.Asset)
		}
	})

	t.Run("attestation", func(t *testing.T) {
		d, out, _, _ := deps(testReport(), nil)
		if err := runWith([]string{"attestation", asset}, d); err != nil {
			t.Fatalf("attestation: %v", err)
		}
		if !strings.Contains(out.String(), "evidence_hash") {
			t.Errorf("attestation output missing evidence_hash: %s", out.String())
		}
	})

	t.Run("history", func(t *testing.T) {
		d, out, _, _ := deps(testReport(), nil)
		if err := runWith([]string{"history", asset}, d); err != nil {
			t.Fatalf("history: %v", err)
		}
		if !strings.Contains(out.String(), "no observations") {
			t.Errorf("history output = %q", out.String())
		}
	})

	t.Run("serve", func(t *testing.T) {
		d, _, _, serveArgs := deps(testReport(), nil)
		if err := runWith([]string{"serve", "-addr", ":9999"}, d); err != nil {
			t.Fatalf("serve: %v", err)
		}
		if len(*serveArgs) != 2 || (*serveArgs)[0] != "-addr" {
			t.Errorf("serve received args %v, want [-addr :9999]", *serveArgs)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		d, _, errOut, _ := deps(testReport(), nil)
		err := runWith([]string{"frobnicate"}, d)
		if err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Fatalf("unknown command error = %v", err)
		}
		if !strings.Contains(errOut.String(), "usage:") {
			t.Error("unknown command did not print usage")
		}
	})

	t.Run("none", func(t *testing.T) {
		d, _, errOut, _ := deps(testReport(), nil)
		err := runWith(nil, d)
		if err == nil || !strings.Contains(err.Error(), "no command given") {
			t.Fatalf("no-args error = %v", err)
		}
		if !strings.Contains(errOut.String(), "usage:") {
			t.Error("no-args did not print usage")
		}
	})
}

// TestAttestationRawGolden pins the -raw format. The Makefile parses it
// positionally with `cut -f1 -f2 -f3`, so the separators, the field order and
// the trailing newline are a contract.
func TestAttestationRawGolden(t *testing.T) {
	d, out, _, _ := deps(testReport(), nil)
	if err := runWith([]string{"attestation", "-raw", "USDC-" + cliIssuer}, d); err != nil {
		t.Fatalf("attestation -raw: %v", err)
	}

	params, err := attest.FromReport(testReport())
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	want := fmt.Sprintf("%d\t%d\t%s\n", params.Severity, params.Flags, params.EvidenceHash)
	if got := out.String(); got != want {
		t.Fatalf("-raw output = %q, want %q", got, want)
	}

	fields := strings.Split(strings.TrimRight(out.String(), "\n"), "\t")
	if len(fields) != 3 {
		t.Fatalf("-raw has %d tab-separated fields, want 3: %q", len(fields), out.String())
	}
	if fields[0] != "2" {
		t.Errorf("-raw severity field = %q, want 2", fields[0])
	}
	if fields[1] != "0" {
		t.Errorf("-raw flags field = %q, want 0", fields[1])
	}
	if len(fields[2]) != 64 {
		t.Errorf("-raw hash field is not a 64-char hex digest: %q", fields[2])
	}
}

// TestAttestationUndeterminedPrintsNothing is the honesty case: an undetermined
// scan has nothing to attest, so the command fails and writes no values a shell
// pipeline could mistake for a severity, flags or hash.
func TestAttestationUndeterminedPrintsNothing(t *testing.T) {
	rep := testReport()
	rep.Undetermined = true
	rep.UndeterminedChecks = []string{"reputation"}

	for _, raw := range []bool{false, true} {
		args := []string{"attestation", "USDC-" + cliIssuer}
		if raw {
			args = []string{"attestation", "-raw", "USDC-" + cliIssuer}
		}
		d, out, _, _ := deps(rep, nil)
		err := runWith(args, d)
		if err == nil {
			t.Fatalf("raw=%v: undetermined scan did not fail", raw)
		}
		if !errors.Is(err, attest.ErrUndetermined) {
			t.Fatalf("raw=%v: error = %v, want ErrUndetermined", raw, err)
		}
		if out.Len() != 0 {
			t.Fatalf("raw=%v: undetermined scan printed %q; a pipeline could read it as values", raw, out.String())
		}
	}
}

// TestWrongArgumentCount covers the invalid-argument state for every command
// that takes a positional asset.
func TestWrongArgumentCount(t *testing.T) {
	d, _, _, _ := deps(testReport(), nil)
	for _, args := range [][]string{
		{"scan"},
		{"scan", "USDC-" + cliIssuer, "extra"},
		{"attestation"},
		{"attestation", "USDC-" + cliIssuer, "extra"},
		{"history"},
		{"history", "USDC-" + cliIssuer, "extra"},
	} {
		if err := runWith(args, d); err == nil {
			t.Errorf("runWith(%v) = nil, want an argument-count error", args)
		}
	}
}

// TestScanErrorPropagates ensures a failing scan is not rendered as a report.
func TestScanErrorPropagates(t *testing.T) {
	boom := errors.New("horizon down")
	d, out, _, _ := deps(nil, boom)
	err := runWith([]string{"scan", "USDC-" + cliIssuer}, d)
	if !errors.Is(err, boom) {
		t.Fatalf("scan error = %v, want %v", err, boom)
	}
	if out.Len() != 0 {
		t.Errorf("a failed scan wrote output: %q", out.String())
	}
}

// TestHistoryRawWithEvidence pins the history raw format and the -guarantee
// exit behavior.
func TestHistoryRawWithEvidence(t *testing.T) {
	rep := testReport()
	rep.Evidence = []mechanics.Evidence{
		{
			Source:      "stellar.expert/directory",
			URL:         "https://api.stellar.expert/explorer/directory/" + cliIssuer,
			Claim:       `listed as "Example" (domain "example.com", tags: )`,
			RetrievedAt: time.Date(2026, 9, 27, 11, 0, 0, 0, time.UTC),
		},
	}

	d, out, _, _ := deps(rep, nil)
	if err := runWith([]string{"history", "-raw", "USDC-" + cliIssuer}, d); err != nil {
		t.Fatalf("history -raw: %v", err)
	}
	got := strings.TrimRight(out.String(), "\n")
	fields := strings.Split(got, "\t")
	if len(fields) != 4 {
		t.Fatalf("history -raw line has %d fields, want 4: %q", len(fields), got)
	}
	if fields[0] != "USDC-"+cliIssuer {
		t.Errorf("field 1 = %q, want the asset", fields[0])
	}
	if fields[2] != "listed as" {
		t.Errorf("field 3 (transition) = %q, want %q", fields[2], "listed as")
	}

	// -guarantee on a report with no history must exit non-zero.
	emptyDeps, _, _, _ := deps(testReport(), nil)
	if err := runWith([]string{"history", "-guarantee", "USDC-" + cliIssuer}, emptyDeps); err == nil {
		t.Error("history -guarantee with no observations returned nil error")
	}
}

// TestDefaultDepsWired checks the production wiring is present. It performs no
// I/O: the closures are not called.
func TestDefaultDepsWired(t *testing.T) {
	d := defaultDeps()
	if d.stdout == nil || d.stderr == nil {
		t.Fatal("defaultDeps left an output writer nil")
	}
	if d.scan == nil {
		t.Error("defaultDeps left scan nil")
	}
	if d.serve == nil {
		t.Error("defaultDeps left serve nil")
	}
}

// TestRunServeRejectsBadAddr covers runServe's own body without binding a real
// port: an address that cannot be listened on returns an error.
func TestRunServeRejectsBadAddr(t *testing.T) {
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	if err := runServe([]string{"-addr", "bad::addr"}, log); err == nil {
		t.Fatal("runServe accepted an unbindable address")
	}
}
