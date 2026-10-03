// Command assay scans Stellar assets for issuer trap mechanics.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/use-assay/assay/internal/api"
	"github.com/use-assay/assay/internal/attest"
	// Aliased because this file already has a local history() for the CLI's
	// evidence view; this package is the persisted observation store behind the
	// HTTP endpoint, a different thing.
	historystore "github.com/use-assay/assay/internal/history"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
)

const (
	exitSuccess     = 0
	exitGeneric     = 1
	exitUsage       = 2
	exitMissing     = 3
	exitUnavailable = 4
	exitUnknown     = 5
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "assay:", err)
		os.Exit(exitCodeForError(err))
	}
}

func exitCodeForError(err error) int {
	if err == nil {
		return exitSuccess
	}
	s := err.Error()
	if strings.Contains(s, "unknown command") ||
		strings.Contains(s, "no command given") ||
		strings.Contains(s, "takes exactly one asset") ||
		strings.Contains(s, "invalid asset") ||
		strings.Contains(s, "expected asset") ||
		strings.Contains(s, "bad request") ||
		strings.Contains(s, "parse") ||
		strings.Contains(s, "flag provided but not defined") ||
		strings.Contains(s, "invalid value") {
		return exitUsage
	}
	if strings.Contains(s, "not found") ||
		strings.Contains(s, "no such asset") ||
		strings.Contains(s, "does not exist") {
		return exitMissing
	}
	if strings.Contains(s, "timeout") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "no route to host") ||
		strings.Contains(s, "upstream") ||
		strings.Contains(s, "network") ||
		strings.Contains(s, "http") ||
		strings.Contains(s, "exhausted") {
		return exitUnavailable
	}
	if strings.Contains(s, "undetermined") ||
		strings.Contains(s, "unevaluated") ||
		strings.Contains(s, "inconsistent") {
		return exitUnknown
	}
	return exitGeneric
}

// commandDeps are the process-level dependencies the subcommands use. They are
// grouped so dispatch, flag handling and output formatting can be tested
// without a network or a real server. The CLI is how the attestation pipeline
// is driven — `make attest` shells out to `assay attestation -raw` and pipes
// the output into a transaction — so its parsing and formatting is a contract
// worth pinning.
type commandDeps struct {
	stdout io.Writer
	stderr io.Writer
	// scan fetches and classifies one asset. It is injected so tests never
	// touch the network.
	scan func(context.Context, mechanics.Asset) (*mechanics.Report, error)
	// serve starts the HTTP API. It is injected so dispatch can be tested
	// without binding a port.
	serve func([]string, *slog.Logger) error
}

// defaultDeps wires the real production sources.
func defaultDeps() commandDeps {
	return commandDeps{
		stdout: os.Stdout,
		stderr: os.Stderr,
		scan: func(ctx context.Context, a mechanics.Asset) (*mechanics.Report, error) {
			return scan.New().Scan(ctx, a)
		},
		serve: runServe,
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage:
  assay scan CODE-ISSUER          classify one asset and print the report as JSON
  assay attestation CODE-ISSUER   print the on-chain attest() arguments for one asset
  assay verify [-hash HEX] [-raw] [PREIMAGE]
                                  check a canonical preimage against an evidence_hash
  assay history [-guarantee] [-raw] CODE-ISSUER
                                  print the asset's observation history
  assay serve [-addr]             serve the HTTP API and UI

Every command that scans accepts:
  -cache-directory-ttl D   reuse a curated directory answer for D (0 disables)
  -cache-blocklist-ttl D   reuse a blocklist answer for D (0 disables)
  -no-cache                re-fetch curated sources on every scan
  assay serve [-addr] [-history PATH]
                                  serve the HTTP API and UI

Commands that scan also accept:
  -asset-lists URL[,URL...]       SEP-0042 Stellar Asset Lists to consume
                                  (repeatable). No list is used by default.
`)
}

func run(args []string) error { return runWith(args, defaultDeps()) }

// runWith is the testable entry point: it performs dispatch only, consuming
// output writers and a scan function from d.
func runWith(args []string, d commandDeps) error {
	if len(args) == 0 {
		usage(d.stderr)
		return fmt.Errorf("no command given")
	}

	log := slog.New(slog.NewTextHandler(d.stderr, nil))

	switch args[0] {
	case "scan":
		return runScan(args[1:], d)
	case "attestation":
		return runAttestation(args[1:], d)
	case "history":
		return runHistory(args[1:], d)
	case "serve":
		return d.serve(args[1:], log)
	default:
		usage(d.stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	assetLists := assetListFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("scan takes exactly one asset (CODE-ISSUER)")
	}
	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := newScanner(assetLists()).Scan(ctx, asset)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(d.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// assetListFlags registers the -asset-lists flag shared by every command that
// scans, and returns a constructor for the URLs it names.
//
// No list is a default, and that is deliberate: shipping one would hard-code a
// provider's curation as authoritative for every scan, and would add evidence
// to every report — which changes every evidence_hash, including for assets
// already attested. A caller opts in, and each list it names is attributed
// separately by name and URL. See docs/asset-lists.md.
func assetListFlags(fs *flag.FlagSet) func() []string {
	var urls listFlag
	fs.Var(&urls, "asset-lists",
		"SEP-0042 Stellar Asset List URLs to consume, comma-separated or repeated; none by default")
	return func() []string {
		return append([]string(nil), urls...)
	}
}

// newScanner returns a production Scanner configured to consult the given
// SEP-0042 asset lists.
func newScanner(lists []string) *scan.Scanner {
	sc := scan.New()
	sc.AssetListURLs = lists
	return sc
}

// listFlag collects repeated -asset-lists values as well as comma-separated
// ones, so both forms work:
//
//	-asset-lists=a,b -asset-lists=c
//	-asset-lists a -asset-lists b
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

// runAttestation prints the arguments of an on-chain attest() call for one
// asset, derived from a live scan.
//
// It deliberately does not submit anything. Signing belongs to whoever holds
// the attester key, and keeping derivation separate from submission means the
// numbers going on-chain can be inspected — and the evidence hash independently
// recomputed from -preimage — before a key ever touches them.
func runAttestation(args []string, d commandDeps) error {
	fs := flag.NewFlagSet("attestation", flag.ContinueOnError)
	assetLists := assetListFlags(fs)
	preimage := fs.Bool("preimage", false, "include the canonical bytes evidence_hash commits to")
	raw := fs.Bool("raw", false, "print only the attest() arguments, tab-separated, for scripting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("attestation takes exactly one asset (CODE-ISSUER)")
	}
	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := newScanner(assetLists()).Scan(ctx, asset)
	if err != nil {
		return err
	}
	// Derivation happens before any output. An undetermined scan has no
	// attestation to print, and nothing may reach stdout that a pipeline could
	// mistake for values.
	params, err := attest.FromReport(report)
	if err != nil {
		return err
	}

	if *raw {
		_, err := fmt.Fprintf(d.stdout, "%d\t%d\t%s\n", params.Severity, params.Flags, params.EvidenceHash)
		return err
	}
	if !*preimage {
		params.Preimage = ""
	}

	enc := json.NewEncoder(d.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(params)
}

func runHistory(args []string, d commandDeps) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	assetLists := assetListFlags(fs)
	guarantee := fs.Bool("guarantee", false, "exit non-zero when there is no history")
	raw := fs.Bool("raw", false, "print only the history, tab-separated, for scripting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("history takes exactly one asset (CODE-ISSUER)")
	}

	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := newScanner(assetLists()).Scan(ctx, asset)
	if err != nil {
		return err
	}

	hist := history(report)

	if len(hist) == 0 {
		msg := "assay history: no observations for " + asset.String()
		fmt.Fprintln(d.stdout, msg)
		if *guarantee {
			return fmt.Errorf("no history")
		}
		return nil
	}

	if *raw {
		for _, h := range hist {
			fmt.Fprintf(d.stdout, "%s\t%s\t%s\t%s\n", h.Asset, h.Severity, h.Transition, h.Reason)
		}
		return nil
	}

	enc := json.NewEncoder(d.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(hist)
}

// history extracts the observation history from a report. The observations are
// the evidence entries, in time order. When there are none, it returns an empty
// slice so the caller can print the clear message.
func history(rep *mechanics.Report) []historyEntry {
	if rep == nil {
		return nil
	}
	hist := make([]historyEntry, 0, len(rep.Evidence))
	for _, e := range rep.Evidence {
		hist = append(hist, historyEntry{
			Asset:      rep.Asset.String(),
			Severity:   rep.Severity.String(),
			Transition: transition(e.Claim),
			Reason:     e.Claim,
			Time:       e.RetrievedAt.Time(),
		})
	}
	return hist
}

// transition reduces a plain-language evidence claim to the term the
// consumer prints: whatever the issuer was observed doing, or unknown when a
// source did not answer.
func transition(claim string) string {
	if claim == "" {
		return "unknown"
	}
	low := strings.ToLower(claim)
	for _, s := range candidateTransitions {
		if strings.Contains(low, s) {
			return s
		}
	}
	return "unknown"
}

// candidateTransitions is the set of ways an observation can read in this
// project. It is deliberately small: the history view does not re-derive the
// verdict, it only reports what each observation says.
var candidateTransitions = []string{
	"malicious",
	"listed as",
	"blocked",
	"unverified",
	"not retrievable",
	"not present",
	"credits",
	"claims",
	"borrow",
	"pay",
}

type historyEntry struct {
	Asset      string    `json:"asset"`
	Severity   string    `json:"severity"`
	Transition string    `json:"transition"`
	Reason     string    `json:"reason"`
	Time       time.Time `json:"time"`
}

func runServe(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	assetLists := assetListFlags(fs)
	addr := fs.String("addr", ":8080", "listen address")
	historyPath := fs.String("history", "",
		"path to the observation history log (JSON Lines); empty keeps history in memory only")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// The cache lives as long as the server process, which is where it earns
	// its keep: repeated scans of the same issuer reuse an answer instead of
	// re-reading a free service on every request.
	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.NewServerWithScanner(scan.NewWithOptions(cache()), log).Handler(),
	srv := api.NewServer(log)
	// The server is where a list configuration matters most: every scan it
	// serves consults the same configured lists, attributed the same way, and
	// records them in the observation history like any other evidence.
	srv.Scanner = newScanner(assetLists())
	if *historyPath != "" {
		store, err := historystore.Open(*historyPath)
		if err != nil {
			return err
		}
		srv.History = store
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errChan := make(chan error, 1)
	go func() {
		log.Info("assay listening", "addr", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Info("shutting down server gracefully")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
errChan := make(chan error, 1)
	go func() {
		log.Info("assay listening", "addr", *addr, "history", *historyPath)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Info("shutting down server gracefully")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}
