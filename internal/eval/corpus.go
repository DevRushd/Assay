package eval

import "github.com/use-assay/assay/internal/mechanics"

// CheckLabel is the expected output of one check on one subject.
//
// Undetermined and Severity are separate labels on purpose: a check that could
// not conclude is compared against an undetermined label, not against a
// severity, because an undetermined finding makes no severity claim and
// comparing it to one would measure a value the check never produced.
type CheckLabel struct {
	// Undetermined asserts whether the check could not conclude.
	Undetermined bool
	// Severity is the expected level for a determined check.
	Severity mechanics.Severity
	// Escalation pins the finding's escalation flag.
	Escalation bool
	// Mechanics pins the finding's mechanic bitset exactly.
	Mechanics mechanics.Mechanic
}

// Label is the expected classification of one corpus subject. It carries the
// aggregate expectation (Base/Severity/Escalated/Accountability) and the
// per-check expectations (Checks) that #115 requires, so a wrong check cannot
// hide behind a right total.
type Label struct {
	// Dir is the fixture directory under the corpus root.
	Dir string
	// Why states what the subject proves. It is printed on failure so a
	// maintainer learns what they broke rather than only seeing a number move.
	Why string

	Base           mechanics.Severity
	Severity       mechanics.Severity
	Escalated      bool
	Accountability mechanics.Accountability

	// Checks carries per-check expectations keyed by check ID. A subject with
	// an empty map is reported as partially evaluated rather than silently
	// passing.
	Checks map[string]CheckLabel
}

// Corpus is the labelled set. Every subject is a real pubnet asset; fixtures
// and provenance are under internal/mechanics/testdata, and the rationale for
// each label is in docs/eval.md.
//
// The per-check labels are derived from the same fixtures the aggregate labels
// are, so the two cannot describe different runs: TestEval and TestEvalPerCheck
// both iterate this corpus.
func Corpus() []Label {
	return []Label{
		{
			Dir: "aqua-clear-verified",
			Why: "no auth flags at all: the issuer has no power over holders, and a " +
				"reciprocal domain confirms who it is",
			Base:           mechanics.Clear,
			Severity:       mechanics.Clear,
			Accountability: mechanics.AccountabilityVerified,
			Checks: map[string]CheckLabel{
				"capability":  {Severity: mechanics.Clear},
				"mutability":  {Severity: mechanics.Clear},
				"sep1-domain": {Severity: mechanics.Clear},
				"reputation":  {Severity: mechanics.Clear, Escalation: true},
			},
		},
		{
			Dir: "shx-clear-flagslocked",
			Why: "no auth flags AND auth_immutable: the issuer can never add freeze " +
				"or clawback later",
			Base:           mechanics.Clear,
			Severity:       mechanics.Clear,
			Accountability: mechanics.AccountabilityVerified,
			Checks: map[string]CheckLabel{
				"capability":  {Severity: mechanics.Clear},
				"mutability":  {Severity: mechanics.Clear, Mechanics: mechanics.MechFlagsLocked},
				"sep1-domain": {Severity: mechanics.Clear},
				"reputation":  {Severity: mechanics.Clear, Escalation: true},
			},
		},
		{
			Dir: "xrp-clear-unlocked",
			Why: "the unlocked counterpart to SHX: no auth flags, but auth_immutable " +
				"is UNSET. The mutability finding must report that without moving " +
				"base severity off clear.",
			Base:           mechanics.Clear,
			Severity:       mechanics.Clear,
			Accountability: mechanics.AccountabilityVerified,
			Checks: map[string]CheckLabel{
				"capability":  {Severity: mechanics.Clear},
				"mutability":  {Severity: mechanics.Clear},
				"sep1-domain": {Severity: mechanics.Clear},
				"reputation":  {Severity: mechanics.Clear, Escalation: true},
			},
		},
		{
			Dir: "usdz-clawback-regulated",
			Why: "the confirmed-legitimate clawback control asset (docs/eval.md " +
				"coverage-gaps). USDZ (Zeam Money, zeam.money) carries both " +
				"auth_revocable and auth_clawback_enabled, so capability alone " +
				"puts it at high — and it must NOT be escalated: the domain " +
				"publishes a reciprocal stellar.toml that names the exact issuer, " +
				"the directory tag is 'issuer' (not 'malicious'), and no " +
				"blocklist entry exists. The severity model's central claim is " +
				"that it treats legitimate clawback fairly; this subject is the " +
				"only one in the set that measures that claim.",
			Base:           mechanics.High,
			Severity:       mechanics.High,
			Escalated:      false,
			Accountability: mechanics.AccountabilityVerified,
			Checks: map[string]CheckLabel{
				"capability": {
					Severity:  mechanics.High,
					Mechanics: mechanics.MechAuthRevocable | mechanics.MechClawbackEnabled,
				},
				"mutability":  {Severity: mechanics.Clear},
				"sep1-domain": {Severity: mechanics.Clear},
				"reputation":  {Severity: mechanics.Clear, Escalation: true},
			},
		},
		{
			Dir: "usdc-revocable-regulated",
			Why: "a real regulated stablecoin that legitimately uses auth_revocable. It " +
				"must report freeze-capable (medium) on the strength of the flag alone.",
			Base:           mechanics.Medium,
			Severity:       mechanics.Medium,
			Accountability: mechanics.AccountabilityUnverified,
			Checks: map[string]CheckLabel{
				"capability": {Severity: mechanics.Medium, Mechanics: mechanics.MechAuthRevocable},
				"mutability": {Severity: mechanics.Clear},
				// circle.com does not serve a stellar.toml, so the reciprocal
				// claim genuinely fails and the unverified bit is set.
				"sep1-domain": {Severity: mechanics.Clear, Mechanics: mechanics.MechDomainUnverified},
				"reputation":  {Severity: mechanics.Clear, Escalation: true},
			},
		},
		{
			Dir: "berkshire-clawback-scam",
			Why: "impersonation asset with clawback: capability alone puts it at high, " +
				"and the curated malicious tag escalates it to critical",
			Base:           mechanics.High,
			Severity:       mechanics.Critical,
			Escalated:      true,
			Accountability: mechanics.AccountabilityUnverified,
			Checks: map[string]CheckLabel{
				"capability": {
					Severity:  mechanics.High,
					Mechanics: mechanics.MechAuthRevocable | mechanics.MechClawbackEnabled,
				},
				"mutability":  {Severity: mechanics.Clear},
				"sep1-domain": {Severity: mechanics.Clear, Mechanics: mechanics.MechDomainUnverified},
				"reputation": {
					Severity:   mechanics.Critical,
					Escalation: true,
					Mechanics:  mechanics.MechBlocklisted,
				},
			},
		},
		{
			Dir: "doge-noflags-scam",
			Why: "the case that justifies keeping reputation as a separate upward-only " +
				"axis: a known scam asset carrying NO auth flags. Capability is honestly " +
				"clear, and escalation is the only thing that catches it. This is also " +
				"the fixture the check-suppression test uses, because it is the case " +
				"with the largest consequence.",
			Base:           mechanics.Clear,
			Severity:       mechanics.Critical,
			Escalated:      true,
			Accountability: mechanics.AccountabilityUnverified,
			Checks: map[string]CheckLabel{
				"capability":  {Severity: mechanics.Clear},
				"mutability":  {Severity: mechanics.Clear},
				"sep1-domain": {Severity: mechanics.Clear, Mechanics: mechanics.MechDomainUnverified},
				"reputation": {
					Severity:   mechanics.Critical,
					Escalation: true,
					Mechanics:  mechanics.MechBlocklisted,
				},
			},
		},
		{
			Dir: "velo-no-home-domain",
			Why: "an issuer account that carries no home_domain at all: the domain " +
				"claim is absent rather than wrong, so accountability must be unknown " +
				"not unverified, and severity must stay clear (#3)",
			Base:           mechanics.Clear,
			Severity:       mechanics.Clear,
			Accountability: mechanics.AccountabilityUnknown,
			Checks: map[string]CheckLabel{
				"capability": {Severity: mechanics.Clear},
				"mutability": {Severity: mechanics.Clear},
				// No domain was ever advertised, so the finding is unknown, not
				// a failed verification — and still carries the unverified bit,
				// because no identity was published to verify against.
				"sep1-domain": {Severity: mechanics.Clear, Mechanics: mechanics.MechDomainUnverified},
				"reputation":  {Severity: mechanics.Clear, Escalation: true},
			},
		},
	}
}
