// Package attest turns a scan report into the exact arguments of an on-chain
// attest() call, and specifies the bytes that evidence_hash commits to.
//
// The registry contract stores a severity number that a caller has to trust.
// evidence_hash is what makes that trust checkable: it is a SHA-256 over a
// canonical encoding of the report, so anyone can re-run the scanner and prove
// an on-chain attestation corresponds to specific evidence rather than to a
// number someone typed. The encoding therefore has to be specified precisely
// enough to reimplement, which is what this package is for.
package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/use-assay/assay/internal/mechanics"
)

// PreimageVersion is the first line of every canonical preimage. It is part of
// what gets hashed, so a future encoding change cannot silently produce a hash
// that a verifier would compare against v1 bytes.
const PreimageVersion = "assay-evidence-v1"

// PreimageVersionCheckSet is the encoding used once a report binds its check
// set. It adds a `checks` line naming the checks the engine actually ran, so a
// report produced by an engine with a check removed cannot hash the same as one
// produced by the full engine.
//
// It is a v2 rather than an edit to v1 for the same reason the version line
// exists: every attestation already on-chain was hashed under v1, and must
// keep reproducing. A report carrying no bound check set is still written as
// v1; only reports that ran through an engine with a check set use v2.
const PreimageVersionCheckSet = "assay-evidence-v2"

// PreimageVersionNetwork is the encoding used once a report binds the network
// its facts were read from. It adds a `network` line carrying the full network
// passphrase, so a pubnet scan and a testnet scan of the same CODE-ISSUER can
// no longer produce indistinguishable preimages (#41): the same identifier can
// exist on both networks with different flags, and Assay's attestations are
// currently written to testnet while scanning pubnet, which made the ambiguity
// concrete.
//
// Like the v2 bump, it is a new version rather than an edit: attestations on
// chain under v1 and v2 must keep reproducing, so a report carrying no bound
// network is still written under its earlier encoding, and only scans that
// name their network hash as v3.
const PreimageVersionNetwork = "assay-evidence-v3"

// ScannerIdentity identifies the code that produced a report, for the v3
// preimage's `scanner` line (issue #40).
//
// The choice of WHAT identifies a scanner was the decision this issue asked
// to be made. A build-stamped commit hash was rejected: it makes every local
// dev build produce a different hash for the same evidence, which would make
// the hash useless for exactly the cross-machine and cross-version comparison
// the field exists for. The module version (Go's `runtime/debug.BuildInfo`,
// the same string `go install github.com/use-assay/assay@v1.2.3` records) was
// chosen instead: it is stable across machines for a given release, changes
// exactly when the code changes, and is verifiable by anyone who can run the
// module. Development builds (no version stamped by the build system) report
// as "devel", the same sentinel `go version -m` prints, so a hash produced by
// an unstamped build is distinguishable from any tagged release rather than
// silently pretending to be one.
//
// The variable is a var rather than computed at call time so tests can pin a
// known identity and so a future build-stamping scheme can override it
// deliberately — with a PreimageVersion review, as any identity change is a
// hash change.
var ScannerIdentity = moduleVersion()

// moduleVersion reads the main module's version from the build info embedded
// by the Go toolchain. "devel" for unstamped builds mirrors what
// `go version -m` prints for a binary built from source without a version
// flag.
func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "devel"
	}
	return info.Main.Version
}

// Params is one attest() call: the arguments, and nothing else.
//
// Asset is the classic identifier the scanner read. The contract keys on the
// asset's Stellar Asset Contract address, which is network-scoped and derived
// separately (see docs/deployment.md) — deriving it is not this package's job,
// because it needs a network passphrase and this package needs no I/O at all.
type Params struct {
	Asset        mechanics.Asset `json:"asset"`
	Severity     uint32          `json:"severity"`
	SeverityName string          `json:"severity_name"`
	Flags        uint32          `json:"flags"`
	Mechanics    []string        `json:"mechanics"`
	// Checks is the sorted check set the scan ran, and is the set the preimage
	// binds under v2. It is reported here so an attestation can be checked
	// against the set a verifier expects without re-reading the report; empty
	// means pre-binding, which is reported as unknown rather than complete.
	Checks []string `json:"checks,omitempty"`
	// Network is the full network passphrase of the ledger the facts were read
	// from, bound into the preimage under v3. Empty means the scan predates
	// network binding, which is reported as such rather than guessed.
	Network      string `json:"network,omitempty"`
	EvidenceHash string `json:"evidence_hash"`
	ScannedAt    string `json:"scanned_at"`
	Preimage     string `json:"preimage,omitempty"`
}

// ErrInconsistent reports a report whose severity the contract would reject.
var ErrInconsistent = errors.New("attest: attestation violates the confiscation invariant")

// ErrUndetermined reports a scan that could not complete, and so must not be
// written on-chain at all.
var ErrUndetermined = errors.New("attest: scan is undetermined, so there is nothing to attest")

// ErrUnevaluated reports a report whose capability axis was never evaluated:
// it carries mechanics.Unevaluated, not a severity level. This is the specific
// case behind most undetermined reports — the flags were never read — and it
// is refused with its own error so a caller can tell "no capability statement
// exists" apart from "a source was down". Like ErrUndetermined, it means there
// is nothing to attest.
var ErrUnevaluated = errors.New("attest: capability axis was never evaluated, so there is no severity to attest")

// ProvenanceStatus represents the result of evaluating scanner version binding.
type ProvenanceStatus string

// ProvenanceValid, ProvenanceInvalid and ProvenanceUnknown are the three
// outcomes of evaluating a report's bound scanner version against the caller's
// minimum.
const (
	ProvenanceValid   ProvenanceStatus = "valid"   // ProvenanceValid means the scanner version meets the caller's minimum.
	ProvenanceInvalid ProvenanceStatus = "invalid" // Version below caller's minimum
	ProvenanceUnknown ProvenanceStatus = "unknown" // No version recorded (pre-v2 attestation)
)

// ErrUnknownProvenance reports an attestation produced without version binding (pre-v2).
var ErrUnknownProvenance = errors.New("attest: unknown provenance, attestation has no recorded scanner version")

// ErrScannerDowngrade reports an attestation carrying a scanner version below the caller's minimum acceptable version.
var ErrScannerDowngrade = errors.New("attest: scanner version is below caller's minimum acceptable version")

// VerifyVersion checks whether a recorded scanner version meets a caller's minimum version requirement.
// An absent (empty) recorded version is reported as unknown provenance rather than silently accepted or invalidated.
func VerifyVersion(recordedVersion string, minVersion string) (ProvenanceStatus, error) {
	recorded := strings.TrimSpace(recordedVersion)
	if recorded == "" {
		return ProvenanceUnknown, ErrUnknownProvenance
	}
	if CompareVersions(recorded, minVersion) < 0 {
		return ProvenanceInvalid, fmt.Errorf("%w: recorded %q < minimum %q", ErrScannerDowngrade, recorded, minVersion)
	}
	return ProvenanceValid, nil
}

// CompareVersions compares two semver version strings (e.g. "v1.0.0", "1.0.0", "v0.1.0").
// It returns -1 if v1 < v2, 0 if v1 == v2, and 1 if v1 > v2.
func CompareVersions(v1, v2 string) int {
	clean1 := strings.TrimPrefix(strings.TrimSpace(v1), "v")
	clean2 := strings.TrimPrefix(strings.TrimSpace(v2), "v")

	parts1 := strings.Split(clean1, ".")
	parts2 := strings.Split(clean2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var num1, num2 int
		if i < len(parts1) {
			if n, err := strconv.Atoi(parts1[i]); err == nil {
				num1 = n
			}
		}
		if i < len(parts2) {
			if n, err := strconv.Atoi(parts2[i]); err == nil {
				num2 = n
			}
		}
		if num1 < num2 {
			return -1
		}
		if num1 > num2 {
			return 1
		}
	}
	return 0
}

// ErrStale reports that the report is stale and cannot be attested as fresh.
// Contract precedent: AttestationStale is error #2 in the example gate.
var ErrStale = errors.New("attest: report is stale, so it cannot be attested as fresh")

// FromReport derives the attest() arguments for a scan report.
//
// It re-checks the confiscation invariant that the contract enforces at write
// time. Catching it here is not redundant: a submitter should find out that an
// attestation is inconsistent before spending a transaction on it, and a report
// that trips this is a bug in the engine rather than a fee to pay.
func FromReport(rep *mechanics.Report) (Params, error) {
	flags := uint32(rep.Mechanics)
	sev := uint32(rep.Severity)

	// An unevaluated capability axis is refused before the generic undetermined
	// refusal so the canonical case (a Subject whose Stat was never loaded)
	// reports the specific error. The sentinel is deliberately outside the
	// ABI's 0..4 range: the contract would reject it as InvalidSeverity, but
	// catching it here names the actual problem and keeps it out of the
	// preimage entirely.
	if rep.Severity == mechanics.Unevaluated || rep.Base == mechanics.Unevaluated {
		return Params{}, fmt.Errorf("%w: capability was never derived from issuer flags", ErrUnevaluated)
	}

	// A stale report was complete when made, but is older than the freshness
	// policy window. On-chain gates refuse stale attestations (AttestationStale
	// is error #2 in the example gate), and FromReport refuses it with a distinct
	// error so an expired verdict cannot be attested as fresh.
	if rep.Stale || rep.State == mechanics.StateStale {
		msg := "verdict is older than freshness policy window"
		if rep.StaleReason != "" {
			msg = rep.StaleReason
		}
		return Params{}, fmt.Errorf("%w: %s", ErrStale, msg)
	}

	// A partial scan is refused outright rather than attested with the severity
	// it managed to reach. On-chain there is nowhere to put the caveat: a
	// consumer calling get_safety sees a severity and a timestamp, and has no
	// way to discover that the reputation axis was never read. Writing a level
	// derived from half the evidence would be indistinguishable, to every
	// downstream gate, from one derived from all of it.
	//
	// So the honest options are to attest a complete scan or to attest nothing,
	// and the contract already treats "nothing" correctly — get_safety returns
	// None and every gate fails closed on it.
	if rep.Undetermined {
		return Params{}, fmt.Errorf("%w: %s could not complete",
			ErrUndetermined, strings.Join(rep.UndeterminedChecks, ", "))
	}

	if flags&uint32(mechanics.ConfiscationMask) != 0 && sev < uint32(mechanics.High) {
		return Params{}, fmt.Errorf("%w: clawback bit set at severity %d", ErrInconsistent, sev)
	}

	pre := Preimage(rep)
	sum := sha256.Sum256([]byte(pre))

	checks := append([]string(nil), rep.CheckSet...)
	sort.Strings(checks)

	return Params{
		Asset:        rep.Asset,
		Severity:     sev,
		SeverityName: rep.Severity.String(),
		Flags:        flags,
		Mechanics:    rep.MechanicNames,
		Checks:       checks,
		Network:      string(rep.Network),
		EvidenceHash: hex.EncodeToString(sum[:]),
		ScannedAt:    rep.ScannedAt.String(), // canonical whole-second UTC (issue #52)
		Preimage:     pre,
	}, nil
}

// Preimage renders the canonical bytes that evidence_hash commits to.
//
// The format is line-oriented, tab-separated, LF-terminated, UTF-8:
//
//	assay-evidence-v1                    (no check set, no scanner identity)
//	asset	CODE-ISSUER
//	severity	N
//	base_severity	N
//	escalated	true|false
//	mechanics	N
//	accountability	NAME
//	checks	ID,ID,...                (v2 only: checks the engine ran, sorted)
//	network	PASSPHRASE               (v3 only: ledger the facts were read from)
//	evidence	SOURCE	URL	CLAIM      (one per claim, sorted)
//
// A report that binds its check set adds one line after `accountability`
// and is written as:
//
//	assay-evidence-v2
//	checks	ID,ID,...                (checks the engine ran, sorted)
//
// A report that also carries a scanner identity adds the identity line
// immediately after the version line and is written as:
//
//	assay-evidence-v3
//	scanner	VERSION                  (module version, or "devel")
//	checks	ID,ID,...
//
// Two decisions in here are worth stating outright.
//
// Retrieval timestamps are excluded. If they were hashed, the same unchanged
// evidence would produce a different hash on every scan, and the field would be
// unverifiable by anyone who was not present for the original fetch. Excluding
// them means the hash commits to what the sources claimed, not to when they
// were asked; the on-chain attested_at carries the time dimension, and a
// verifier re-scans and compares hashes. The cost is that the hash cannot
// distinguish a fresh confirmation from a stale one, which is exactly why
// is_safe takes max_age_secs against attested_at rather than trusting this.
//
// Evidence lines are sorted bytewise rather than left in check order, so
// reordering checks does not change the hash for evidence that did not change.
// Adding or removing a check does change it, by design: the v2 `checks` line
// binds the check set, so a check removed from the engine cannot hide behind an
// otherwise identical report. From v3 on the `network` line names the ledger
// the facts were read from, so the same identifier scanned on two networks
// hashes differently.
func Preimage(rep *mechanics.Report) string {
	var b strings.Builder

	b.WriteString(preimageVersion(rep))
	b.WriteByte('\n')
	// The scanner identity line is the v3 addition (issue #40): the hashed
	// bytes name the code that produced the report, so two versions that
	// classify differently can never hash identically. It comes right after
	// the version line — identity before content.
	if preimageHasScanner(rep) {
		line(&b, "scanner", escape(ScannerIdentity))
	}
	line(&b, "asset", rep.Asset.String())
	line(&b, "severity", strconv.FormatUint(uint64(rep.Severity), 10))
	line(&b, "base_severity", strconv.FormatUint(uint64(rep.Base), 10))
	line(&b, "escalated", strconv.FormatBool(rep.Escalated))
	line(&b, "mechanics", strconv.FormatUint(uint64(rep.Mechanics), 10))
	line(&b, "accountability", string(rep.Accountability))

	// The checks line is written for every report, v1 included: it is empty
	// when the report binds no check set, which is the exact v1 byte shape,
	// and carries the sorted bound set under v2/v3 so a verifier can name the
	// checks a report is missing.
	checks := append([]string(nil), rep.CheckSet...)
	sort.Strings(checks)
	line(&b, "checks", strings.Join(checks, ","))

	// A bound network is written after the check set and before the evidence:
	// the encoding is line-oriented, so a new field takes a fixed position and
	// every earlier encoding must keep rendering byte-identically without it.
	// Reports with no network omit the line entirely, keeping the exact v1/v2
	// bytes an on-chain attestation was hashed under.
	if rep.Network != "" {
		line(&b, "network", string(rep.Network))
	}

	ev := make([]string, 0, len(rep.Evidence))
	for _, e := range rep.Evidence {
		ev = append(ev, "evidence\t"+escape(e.Source)+"\t"+escape(e.URL)+"\t"+escape(e.Claim))
	}
	sort.Strings(ev)
	for _, l := range ev {
		b.WriteString(l)
		b.WriteByte('\n')
	}

	return b.String()
}

// preimageVersion returns the encoding version a report is written under.
//
// The version names the newest binding the report carries: a report that names
// its network is v3; one that binds only a check set is v2; one with neither
// keeps the exact v1 bytes, so an attestation written before check-set or
// network binding still reproduces its hash. Each version's rendering rules
// are cumulative — a v3 report with no bound check set carries the network
// line but not the checks line — so the version line always determines the
// byte format completely.
func preimageVersion(rep *mechanics.Report) string {
	switch {
	case preimageHasScanner(rep) || rep.Network != "":
		return PreimageVersionNetwork
	case len(rep.CheckSet) > 0:
		return PreimageVersionCheckSet
	default:
		return PreimageVersion
	}
}

// preimageHasScanner reports whether a report is written under the v3
// encoding. Gating on ScannerBound rather than on the identity value keeps
// the encoding decision a property of the REPORT: an operator who wants v1
// bytes can produce a report without the binding, and a reader can tell from
// the version line alone whether the bytes name their producer.
func preimageHasScanner(rep *mechanics.Report) bool {
	return rep.ScannerBound
}

// CheckSetStatus describes whether a report's bound check set can be compared
// against what a verifier expects.
type CheckSetStatus string

const (
	// CheckSetUnknown means the report carries no bound check set: it was
	// produced before check-set binding. It is reported as unknown rather than
	// failed, because there is nothing to compare — and never as complete.
	CheckSetUnknown CheckSetStatus = "unknown"
	// CheckSetComplete means every expected check is present in the report.
	CheckSetComplete CheckSetStatus = "complete"
	// CheckSetIncomplete means at least one expected check is absent.
	CheckSetIncomplete CheckSetStatus = "incomplete"
)

// CheckSetVerification is the result of comparing a report's bound check set
// against the set a verifier requires.
type CheckSetVerification struct {
	Status CheckSetStatus
	// Present is the report's bound check set, sorted, or nil when unknown.
	Present []string
	// Missing names the expected checks the report does not carry. It is
	// populated only for an incomplete set, so a verifier can say which check
	// is absent rather than only that something is.
	Missing []string
}

// VerifyCheckSet checks that a report was produced by an engine running at
// least the expected checks.
//
// A report with no bound check set is CheckSetUnknown: it predates check-set
// binding, so there is nothing to compare, and failing it would reject every
// historical attestation. A report with a bound set that is missing an
// expected check is CheckSetIncomplete, with the absent checks named.
func VerifyCheckSet(rep *mechanics.Report, expected []string) CheckSetVerification {
	return verifyChecks(rep.CheckSet, expected)
}

// VerifyParams checks an attestation's bound check set against the set a
// verifier expects. It is the same check as VerifyCheckSet applied to the
// derived attest() arguments, so a verifier holding only the params can flag an
// attestation whose check set is smaller than expected.
func VerifyParams(p Params, expected []string) CheckSetVerification {
	return verifyChecks(p.Checks, expected)
}

// HashStatus describes the result of comparing a report's evidence hash with a
// claimed digest.
type HashStatus string

const (
	// HashUnknown means there is no authoritative digest to compare, such as an
	// undetermined or unevaluated report.
	HashUnknown HashStatus = "unknown"
	// HashMatched means the report reproduces the claimed digest exactly.
	HashMatched HashStatus = "matched"
	// HashMismatch means the report differs in a way that constitutes tampering or
	// drift from the claimed evidence bundle.
	HashMismatch HashStatus = "mismatch"
)

// HashVerification is the result of comparing a report's recomputed evidence
// hash against a claimed digest.
type HashVerification struct {
	Status  HashStatus
	Got     string
	Want    string
	Reason  string
	Present []string
}

// VerifyHash checks whether a report reproduces the claimed evidence hash.
//
// An undetermined report never has a valid digest to compare and is reported as
// unknown rather than as tampered. Any material difference in the canonical
// preimage returns a mismatch status with the recomputed digest, so callers can
// distinguish an attestation whose evidence changed from one whose auth state is
// merely unresolved.
func VerifyHash(rep *mechanics.Report, expected string) HashVerification {
	if rep == nil || rep.Undetermined || rep.Severity == mechanics.Unevaluated || rep.Base == mechanics.Unevaluated {
		return HashVerification{Status: HashUnknown, Want: expected, Reason: "report is undetermined or unevaluated"}
	}
	if expected == "" {
		return HashVerification{Status: HashUnknown, Want: expected, Reason: "no evidence hash was supplied"}
	}
	p, err := FromReport(rep)
	if err != nil {
		return HashVerification{Status: HashUnknown, Want: expected, Reason: err.Error()}
	}
	if p.EvidenceHash == expected {
		return HashVerification{Status: HashMatched, Got: p.EvidenceHash, Want: expected, Reason: "evidence hash matches the canonical preimage"}
	}
	return HashVerification{Status: HashMismatch, Got: p.EvidenceHash, Want: expected, Reason: "recomputed evidence hash differs from the claimed digest"}
}

func verifyChecks(present, expected []string) CheckSetVerification {
	if len(present) == 0 {
		return CheckSetVerification{Status: CheckSetUnknown}
	}
	have := make(map[string]bool, len(present))
	for _, id := range present {
		have[id] = true
	}
	v := CheckSetVerification{
		Status:  CheckSetComplete,
		Present: append([]string(nil), present...),
	}
	sort.Strings(v.Present)
	for _, id := range expected {
		if !have[id] {
			v.Missing = append(v.Missing, id)
		}
	}
	if len(v.Missing) > 0 {
		v.Status = CheckSetIncomplete
		sort.Strings(v.Missing)
	}
	return v
}

// line writes one key/value record.
func line(b *strings.Builder, key, val string) {
	b.WriteString(key)
	b.WriteByte('\t')
	b.WriteString(escape(val))
	b.WriteByte('\n')
}

// escape makes a field unambiguous inside a tab-separated line.
//
// Claims embed third-party text — a directory name, a domain, a toml error —
// so a field can contain anything an issuer chose to publish. Without escaping,
// an issuer could put a tab or a newline in its directory name and forge the
// preimage of a different report. The replacement order matters: backslash
// first, or the escapes introduced below would themselves be escaped.
func escape(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		"\t", `\t`,
		"\n", `\n`,
		"\r", `\r`,
	)
	return r.Replace(s)
}
