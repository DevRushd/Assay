// Command assay scans Stellar assets for issuer trap mechanics.
package main

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/use-assay/assay/internal/bundle"
	// Aliased because this file already has a local history() for the CLI's
	// evidence view; this package is the persisted observation store behind the
	// HTTP endpoint, a different thing.
	historystore "github.com/use-assay/assay/internal/history"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/replay"
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
	// The native asset ("native" or "XLM", any case) is an input Assay
	// understands and deliberately refuses, not one it fails to parse: the
	// ledger gives it no issuer account, so there are no authorization flags
	// to read and nothing to scan or attest. It is grouped with the other
	// arguments these commands refuse (exit 2) so a script can tell "this
	// identifier will never scan" from a transient failure without parsing
	// stderr. Matched with errors.Is rather than the message text below, so
	// wrapping or rewording cannot silently move it to another code.
	// Documented in docs/cli.md.
	if errors.Is(err, scan.ErrNativeAsset) {
		return exitUsage
	}
	s := err.Error()
	if strings.Contains(s, "unknown command") ||
		strings.Contains(s, "no command given") ||
		strings.Contains(s, "takes exactly one asset") ||
		strings.Contains(s, "invalid asset") ||
		strings.Contains(s, "expected asset") ||
		strings.Contains(s, "bad request") ||
		strings.Contains(s, "parse") ||
		strings.Contains(s, "unknown preimage version") ||
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
	_, _ = fmt.Fprint(w, `usage:
  assay scan CODE-ISSUER          classify one asset and print the report as JSON
  assay attestation CODE-ISSUER   print the on-chain attest() arguments for one asset
  assay verify [-json] [-max-age SECS] CODE-ISSUER
                                  compare a live scan with the on-chain attestation
  assay verify -bundle IN [-json]
                                  verify an offline bundle without a network
  assay diff [-json] A.json B.json
                                  compare two saved reports and print what changed
  assay history [-guarantee] [-raw] CODE-ISSUER
                                  print the asset's observation history
  assay registry-history [-rpc URL] [-contract C...] [-json] ASSET
                                  print the registry's attest/revoke events for an asset
                                  (CODE-ISSUER or SAC address), bounded by RPC event retention
  assay serve [-addr] [-history PATH]
                                  serve the HTTP API and UI

Commands that scan also accept:
  -cache-directory-ttl D   reuse a curated directory answer for D (0 disables)
  -cache-blocklist-ttl D   reuse a blocklist answer for D (0 disables)
  -no-cache                re-fetch curated sources on every scan
  -asset-lists URL[,URL...]
                           SEP-0042 Stellar Asset Lists to consume
                           (repeatable). No list is used by default.

The scan command additionally accepts:
  -record DIR             save every upstream response into DIR with a
                          manifest, for later -replay
  -replay DIR             serve every upstream response from a recording;
                          an unrecorded request fails loudly instead of
                          reaching the network

The attestation command additionally accepts:
  -preimage-version V     render the preimage under encoding V (v1, v2, v3,
                          v4 or assay-evidence-vN) instead of the one the
                          report binds, so an already-recorded hash can be
                          reproduced from a fresh scan
  -bundle OUT             also write an offline verification bundle (raw
                          source bytes, report, preimage, digest) to OUT
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
	case "verify":
		return runVerify(args[1:])
	case "diff":
		return runDiff(args[1:], d)
	case "registry-history":
		return runRegistryHistory(args[1:], d)
	case "serve":
		return d.serve(args[1:], log)
	default:
		usage(d.stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runScan(args []string, d commandDeps) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	assetLists := assetListFlags(fs)
	recordDir := fs.String("record", "",
		"save every upstream response into DIR for later -replay")
	replayDir := fs.String("replay", "",
		"serve every upstream response from a recording made with -record")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("scan takes exactly one asset (CODE-ISSUER)")
	}
	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	if *recordDir != "" && *replayDir != "" {
		return fmt.Errorf("-record and -replay are mutually exclusive")
	}

	scanFn, finish, err := scanFuncForRecording(assetLists(), d, *recordDir, *replayDir)
	if err != nil {
		return err
	}
	// A recording is closed even when the scan fails: a failed live scan is
	// exactly the case worth reproducing, so everything it did fetch is kept.
	defer finish()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := scanFn(ctx, asset)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(d.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("scan: write report: %w", err)
	}
	return nil
}

// scanFuncForRecording returns the scan function for the scanning subcommands
// plus a finish hook that must run after the scan, whatever its outcome.
//
// With neither flag it returns the injected dependency unchanged, so dispatch
// tests never construct a scanner or touch a transport. -record wraps the
// fetchers' transport in a recorder; -replay replaces it with the recording.
// Nothing else about the scan changes — same fetches, same engine — which is
// what makes a replayed report comparable to the recorded one.
func scanFuncForRecording(lists []string, d commandDeps, recordDir, replayDir string) (func(context.Context, mechanics.Asset) (*mechanics.Report, error), func(), error) {
	if recordDir == "" && replayDir == "" {
		return scanFuncFor(lists, d), func() {}, nil
	}
	scanner := newScanner(lists)

	if recordDir != "" {
		rec, err := replay.NewRecorder(recordDir, scanner.Horizon.HTTP.Transport)
		if err != nil {
			return nil, func() {}, fmt.Errorf("record: %w", err)
		}
		wireTransport(scanner, rec)
		return scanner.Scan, func() {
			if err := rec.Close(); err != nil {
				// The scan's report is already on stdout or already failed;
				// the recording failing must not mask either, but it must be
				// said out loud — a silently missing recording turns the
				// next -replay into a confusing "unrecorded request".
				_, _ = fmt.Fprintln(d.stderr, "assay: recording not written:", err)
			}
		}, nil
	}

	rp, err := replay.NewReplayer(replayDir)
	if err != nil {
		return nil, func() {}, fmt.Errorf("replay: %w", err)
	}
	wireTransport(scanner, rp)
	return scanner.Scan, func() {}, nil
}

// wireTransport points every fetcher's client at the same transport. The
// fetchers build their http.Clients with the default transport and a timeout;
// replacing the transport is the one seam every source shares.
func wireTransport(s *scan.Scanner, rt http.RoundTripper) {
	for _, c := range []*http.Client{
		s.Horizon.HTTP, s.Toml.HTTP, s.Expert.HTTP, s.Lists.HTTP,
	} {
		c.Transport = rt
	}
}

// scanFuncFor returns the scan function the scanning subcommands use. When no
// SEP-0042 list is configured it returns the injected dependency, so dispatch
// tests never touch the network; when lists are named it wires a production
// scanner configured to consult them.
func scanFuncFor(lists []string, d commandDeps) func(context.Context, mechanics.Asset) (*mechanics.Report, error) {
	if len(lists) == 0 {
		return d.scan
	}
	return newScanner(lists).Scan
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
//
// -preimage-version renders the report under a historical encoding instead of
// the newest one it binds: reproducing an attestation already on chain means
// re-deriving the bytes it was actually hashed over. The flag takes v1 … v4
// or the full assay-evidence-vN line; an empty value keeps the default
// (newest binding wins). A verifier compares like with like because of it.
func runAttestation(args []string, d commandDeps) error {
	fs := flag.NewFlagSet("attestation", flag.ContinueOnError)
	assetLists := assetListFlags(fs)
	preimage := fs.Bool("preimage", false, "include the canonical bytes evidence_hash commits to")
	raw := fs.Bool("raw", false, "print only the attest() arguments, tab-separated, for scripting")
	preimageVersion := fs.String("preimage-version", "",
		"render the preimage under this encoding: v1, v2, v3, v4 or a full assay-evidence-vN line (default: the one the report binds)")
	bundleOut := fs.String("bundle", "",
		"also write an offline verification bundle (raw source bytes, report, preimage, digest) to this path")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("attestation: %w", err)
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("attestation takes exactly one asset (CODE-ISSUER)")
	}
	// The encoding is validated before the live scan: a mistyped version is a
	// usage error, and discovering it after a 30-second fetch would waste the
	// fetch and muddy the error.
	if *preimageVersion != "" {
		if _, err := attest.NormalizePreimageVersion(*preimageVersion); err != nil {
			return fmt.Errorf("attestation: %w", err)
		}
	}
	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("attestation: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanFn := scanFuncFor(assetLists(), d)
	finish := func() {}
	recordingDir := ""
	if *bundleOut != "" {
		dir, err := os.MkdirTemp("", "assay-bundle-*")
		if err != nil {
			return fmt.Errorf("create bundle recording directory: %w", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()
		recordingDir = dir
		// Record into a private directory first; the archive is written only
		// after the report is derived, so a failed scan leaves no half bundle.
		scanFn, finish, err = scanFuncForRecording(assetLists(), d, recordingDir, "")
		if err != nil {
			return err
		}
	}

	report, err := scanFn(ctx, asset)
	if err != nil {
		return err
	}
	// Derivation happens before any output. An undetermined scan has no
	// attestation to print, and nothing may reach stdout that a pipeline could
	// mistake for values.
	params, err := attest.FromReportAs(report, *preimageVersion)
	if err != nil {
		return fmt.Errorf("attestation: %w", err)
	}

	if *bundleOut != "" {
		// Close the recording before packaging: the manifest and bodies are
		// written by Close, and a bundle built from a still-open recorder would
		// be missing every response.
		finish()
		if err := bundle.Write(*bundleOut, report, params, recordingDir); err != nil {
			return fmt.Errorf("write verification bundle %s: %w", *bundleOut, err)
		}
		_, _ = fmt.Fprintf(d.stderr, "assay: wrote verification bundle %s\n", *bundleOut)
	}

	if *raw {
		// Without a requested version the format is unchanged: SEVERITY,
		// FLAGS, HASH. With one, a fourth field carries the hash the report
		// renders under the version the current binary would pick, so a
		// caller can tell "the evidence changed" (neither matches the
		// recorded hash) apart from "the recorded hash belongs to another
		// encoding" (only the current rendering matches it).
		if *preimageVersion == "" {
			if _, err := fmt.Fprintf(d.stdout, "%d\t%d\t%s\n", params.Severity, params.Flags, params.EvidenceHash); err != nil {
				return fmt.Errorf("attestation: write: %w", err)
			}
			return nil
		}
		current, err := attest.FromReport(report)
		if err != nil {
			return fmt.Errorf("attestation: %w", err)
		}
		if _, err := fmt.Fprintf(d.stdout, "%d\t%d\t%s\t%s\n",
			params.Severity, params.Flags, params.EvidenceHash, current.EvidenceHash); err != nil {
			return fmt.Errorf("attestation: write: %w", err)
		}
		return nil
	}
	if !*preimage {
		params.Preimage = ""
	}

	enc := json.NewEncoder(d.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(params); err != nil {
		return fmt.Errorf("attestation: write: %w", err)
	}
	return nil
}

func runHistory(args []string, d commandDeps) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	assetLists := assetListFlags(fs)
	guarantee := fs.Bool("guarantee", false, "exit non-zero when there is no history")
	raw := fs.Bool("raw", false, "print only the history, tab-separated, for scripting")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("history: %w", err)
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("history takes exactly one asset (CODE-ISSUER)")
	}

	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := scanFuncFor(assetLists(), d)(ctx, asset)
	if err != nil {
		return err
	}

	hist := history(report)

	if len(hist) == 0 {
		msg := "assay history: no observations for " + asset.String()
		_, _ = fmt.Fprintln(d.stdout, msg)
		if *guarantee {
			return fmt.Errorf("no history")
		}
		return nil
	}

	if *raw {
		for _, h := range hist {
			_, _ = fmt.Fprintf(d.stdout, "%s\t%s\t%s\t%s\n", h.Asset, h.Severity, h.Transition, h.Reason)
		}
		return nil
	}

	enc := json.NewEncoder(d.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(hist); err != nil {
		return fmt.Errorf("history: write: %w", err)
	}
	return nil
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
		return fmt.Errorf("serve: %w", err)
	}

	// The server is where a list configuration matters most: every scan it
	// serves consults the same configured lists, attributed the same way, and
	// records them in the observation history like any other evidence.
	srv := api.NewServer(log)
	srv.Scanner = newScanner(assetLists())
	if *historyPath != "" {
		store, err := historystore.Open(*historyPath)
		if err != nil {
			return fmt.Errorf("serve: history: %w", err)
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
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("serve: shutdown: %w", err)
		}
		return nil
	}
}
