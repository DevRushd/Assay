package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
)

// This file implements `assay verify` (issue #39): re-scan the asset,
// recompute the evidence hash, read the on-chain attestation, and report
// whether they agree — with one command, instead of two commands and a human
// comparing hex by eye.
//
// The outcome classes are distinct, because collapsing them is exactly the
// dishonesty the command exists to prevent:
//
//	agree        the scan, the recomputed hash and the chain all match (exit 0)
//	stale        they match, but the attestation is older than -max-age (exit 2)
//	mismatch     one or more of severity/flags/evidence_hash differ (exit 1),
//	             with the differing fields named
//	absent       no attestation on chain for this asset (exit 3)
//	unverifiable the scan is undetermined, so no verdict is possible (exit 4);
//	             an undetermined scan NEVER reports agreement
//
// Staleness is only a failure when the caller supplies -max-age: without it
// the command has no age to judge against and reports agreement regardless of
// age, because freshness is a policy of the caller, not of the tool.

// verifyOutcome is one of the five terminal states of a verification.
type verifyOutcome string

const (
	outcomeAgree        verifyOutcome = "agree"
	outcomeStale        verifyOutcome = "stale"
	outcomeMismatch     verifyOutcome = "mismatch"
	outcomeAbsent       verifyOutcome = "absent"
	outcomeUnverifiable verifyOutcome = "unverifiable"
)

// exit codes, one per outcome class, so a script can branch on $?.
const (
	exitMismatch     = 1
	exitStale        = 2
	exitAbsent       = 3
	exitUnverifiable = 4
)

// OnChainSafety mirrors the registry's get_safety return: the stored
// attestation for one asset.
type OnChainSafety struct {
	Severity     uint32 `json:"severity"`
	Flags        uint32 `json:"flags"`
	EvidenceHash string `json:"evidence_hash"`
	AttestedAt   int64  `json:"attested_at"`
}

// registryReader reads the on-chain attestation for one asset. It is an
// interface boundary rather than a concrete call so the outcome table test can
// stub the chain; the production implementation is stellarRegistryReader.
type registryReader func(asset mechanics.Asset) (*OnChainSafety, error)

// scanFunc performs the live re-scan. Stubbed in tests, scan.New().Scan in
// production.
type scanFunc func(ctx context.Context, asset mechanics.Asset) (*mechanics.Report, error)

// VerifyResult is the full verdict, for both the human line and -json.
type VerifyResult struct {
	Asset   string         `json:"asset"`
	Outcome verifyOutcome  `json:"outcome"`
	Fields  []string       `json:"fields,omitempty"`   // which fields mismatched
	AgeSecs int64          `json:"age_secs,omitempty"` // attestation age, for stale
	MaxAge  int64          `json:"max_age_secs,omitempty"`
	Local   *LocalSide     `json:"local,omitempty"`
	Chain   *OnChainSafety `json:"chain,omitempty"`
	Detail  string         `json:"detail,omitempty"`
}

// LocalSide is the freshly scanned side of the comparison.
type LocalSide struct {
	Severity     uint32   `json:"severity"`
	SeverityName string   `json:"severity_name"`
	Flags        uint32   `json:"flags"`
	EvidenceHash string   `json:"evidence_hash"`
	Checks       []string `json:"checks,omitempty"`
}

// verifyAsset is the whole comparison. It never reports agreement for an
// undetermined scan: the undetermined check runs before anything else, and
// FromReport would refuse the scan anyway.
//
// The error return is for infrastructure failures (scan errored, chain read
// errored) — situations where no verdict exists at all. Every *verdict* —
// agree, stale, mismatch, absent, unverifiable — is a VerifyResult, not an
// error, because "the attestation disagrees" is a successful verification of
// a bad attestation and a script must be able to distinguish the exit codes.
func verifyAsset(ctx context.Context, asset mechanics.Asset, maxAge int64, now time.Time, doScan scanFunc, read registryReader) (*VerifyResult, error) {
	res := &VerifyResult{Asset: asset.String()}

	report, err := doScan(ctx, asset)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	if report.Undetermined {
		res.Outcome = outcomeUnverifiable
		res.Detail = fmt.Sprintf("scan is undetermined (%s); no verdict is possible",
			strings.Join(report.UndeterminedChecks, ", "))
		return res, nil
	}

	params, err := attest.FromReport(report)
	if err != nil {
		res.Outcome = outcomeUnverifiable
		res.Detail = fmt.Sprintf("scan produced nothing attestable: %v", err)
		return res, nil
	}
	res.Local = &LocalSide{
		Severity:     params.Severity,
		SeverityName: params.SeverityName,
		Flags:        params.Flags,
		EvidenceHash: params.EvidenceHash,
		Checks:       params.Checks,
	}

	chain, err := read(asset)
	if err != nil {
		return nil, fmt.Errorf("read on-chain attestation: %w", err)
	}
	if chain == nil {
		res.Outcome = outcomeAbsent
		res.Detail = "no attestation on chain for this asset"
		return res, nil
	}
	res.Chain = chain

	// Compare the three attested fields by name, so a mismatch says which
	// field moved instead of a generic "not equal".
	var diff []string
	if params.Severity != chain.Severity {
		diff = append(diff, "severity")
	}
	if params.Flags != chain.Flags {
		diff = append(diff, "flags")
	}
	if !strings.EqualFold(params.EvidenceHash, chain.EvidenceHash) {
		diff = append(diff, "evidence_hash")
	}
	if len(diff) > 0 {
		res.Outcome = outcomeMismatch
		res.Fields = diff
		res.Detail = "on-chain attestation does not match the live scan"
		return res, nil
	}

	age := now.Unix() - chain.AttestedAt
	if age < 0 {
		age = 0
	}
	res.AgeSecs = age

	// Staleness is judged only when the caller supplied an age. Otherwise a
	// matching attestation agrees no matter how old it is.
	if maxAge > 0 && age > maxAge {
		res.Outcome = outcomeStale
		res.MaxAge = maxAge
		res.Detail = fmt.Sprintf("attestation matches but is %d seconds old (max %d)", age, maxAge)
		return res, nil
	}

	res.Outcome = outcomeAgree
	res.Detail = "on-chain attestation matches the live scan"
	return res, nil
}

// stellarRegistryReader is the production registryReader: it derives the
// asset's SAC id and simulates get_safety through the stellar CLI, exactly as
// `make read` does. Simulation rather than submission means reading costs
// nothing and needs no signature. CONTRACT_ID / NETWORK come from the
// environment with the same defaults as the Makefile.
func stellarRegistryReader(asset mechanics.Asset) (*OnChainSafety, error) {
	contract := os.Getenv("ASSAY_CONTRACT_ID")
	if contract == "" {
		contract = "CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73"
	}
	network := os.Getenv("ASSAY_NETWORK")
	if network == "" {
		network = "testnet"
	}

	sac, err := exec.Command("stellar", "contract", "id", "asset",
		"--asset", asset.Code+":"+asset.Issuer, "--network", network).Output()
	if err != nil {
		return nil, fmt.Errorf("derive SAC id: %w", err)
	}
	out, err := exec.Command("stellar", "contract", "invoke",
		"--id", contract,
		"--source-account", "assay-attester",
		"--network", network,
		"--send=no",
		"--", "get_safety", "--asset", strings.TrimSpace(string(sac)),
	).Output()
	if err != nil {
		return nil, fmt.Errorf("invoke get_safety: %w", err)
	}

	// The CLI prints the Option as either `null` (absent) or the Safety JSON.
	var raw *OnChainSafety
	if err := json.Unmarshal(bytesOr(out), &raw); err != nil {
		return nil, fmt.Errorf("parse get_safety output: %w", err)
	}
	return raw, nil
}

func bytesOr(b []byte) []byte {
	if len(strings.TrimSpace(string(b))) == 0 {
		return []byte("null")
	}
	return b
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	maxAge := fs.Int64("max-age", 0, "treat an attestation older than this many seconds as stale (0 disables the age check)")
	asJSON := fs.Bool("json", false, "print the verdict as JSON for scripting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("verify takes exactly one asset (CODE-ISSUER)")
	}
	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, verdict := verifyAsset(ctx, asset, *maxAge, time.Now(),
		func(ctx context.Context, a mechanics.Asset) (*mechanics.Report, error) {
			return scan.New().Scan(ctx, a)
		},
		stellarRegistryReader)
	if verdict != nil {
		return verdict
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return err
		}
	} else {
		fmt.Printf("%s: %s\n", strings.ToUpper(string(res.Outcome)), res.Asset)
		if res.Detail != "" {
			fmt.Println(res.Detail)
		}
		if len(res.Fields) > 0 {
			fmt.Println("differing fields:", strings.Join(res.Fields, ", "))
			if res.Local != nil {
				fmt.Printf("local: severity=%d flags=%d evidence_hash=%s\n",
					res.Local.Severity, res.Local.Flags, res.Local.EvidenceHash)
			}
			if res.Chain != nil {
				fmt.Printf("chain: severity=%d flags=%d evidence_hash=%s attested_at=%d\n",
					res.Chain.Severity, res.Chain.Flags, res.Chain.EvidenceHash, res.Chain.AttestedAt)
			}
		}
	}

	switch res.Outcome {
	case outcomeAgree:
		return nil
	case outcomeStale:
		os.Exit(exitStale)
	case outcomeMismatch:
		os.Exit(exitMismatch)
	case outcomeAbsent:
		os.Exit(exitAbsent)
	case outcomeUnverifiable:
		os.Exit(exitUnverifiable)
	}
	return nil
}
