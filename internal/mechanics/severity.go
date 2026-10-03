package mechanics

import "fmt"

// Severity is Assay's risk level for an asset.
//
// Severity is CAPABILITY-ONLY. It answers exactly one question: what is the
// issuer able to do to a holder's balance? It is derived from the issuer's
// authorization flags, which are consensus-enforced facts, and from nothing
// else.
//
// Reputation, attribution, age, popularity, and trustline count do not lower
// severity. Ever. Two assets with identical issuer capability return identical
// severity even if one is issued by a household-name regulated institution and
// the other by an anonymous account created an hour ago. This is not an
// oversight — it is the property that makes the on-chain gate sound. A gate
// that reads `severity <= Medium` must be relying on a statement about
// mechanics, not on a statement about anyone's opinion of the issuer.
//
// Reputation is monotonic upward only: confirmed-bad reputation escalates to
// Critical, because evidence of abuse is decisive. Absence of bad reputation is
// never evidence of good, so it moves nothing.
//
// Whether anyone stands behind the capability is reported separately, as
// Accountability. See docs/severity-model.md.
type Severity uint32

// Severity levels are pinned to a specific issuer capability so that the
// numeric value is self-documenting on-chain. These values are part of the
// contract ABI: do not renumber them.
const (
	// Clear means the issuer holds no authorization flags and has no special
	// power over holders of this asset.
	Clear Severity = 0

	// Low means auth_required: the issuer gates who may open a trustline. It
	// controls entry, but cannot act against a holder who is already in.
	Low Severity = 1

	// Medium means auth_revocable: the issuer can freeze an existing holder's
	// balance, making it unusable while leaving it in place.
	Medium Severity = 2

	// High means auth_clawback_enabled: the issuer can confiscate an existing
	// holder's balance outright and burn it, without that holder's signature.
	High Severity = 3

	// Critical is reserved for reputation escalation. It is never produced by
	// reading flags; it means a curated source has affirmatively identified
	// this issuer or its domain as malicious.
	Critical Severity = 4

	// Unevaluated means the issuer's authorization flags were never read, so
	// no capability statement exists. It is deliberately not zero: a nil
	// Subject.Stat must not render as Clear, because Clear is the safest value
	// in the ABI and "could not assess" would then be indistinguishable from
	// "assessed and found no powers". Unevaluated is not a severity level and
	// is not part of the on-chain ABI: attest.FromReport refuses any report
	// carrying it (ErrUnevaluated), and the safety-registry contract rejects
	// severity > SEVERITY_CRITICAL at write time as a second backstop. It
	// exists so that an unread flag can never be serialized as a permissive
	// answer. See docs/severity-model.md, "What unevaluated means".
	//
	// The value 5 is chosen to sit outside the ABI's 0..4 range so that
	// accidental serialization is detectable rather than silently meaningful.
	Unevaluated Severity = 5
)

// String returns the lowercase level name used in the API and UI.
func (s Severity) String() string {
	switch s {
	case Clear:
		return "clear"
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	case Unevaluated:
		return "unevaluated"
	default:
		return "unknown"
	}
}

// MarshalJSON renders severity as its level name.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// UnmarshalJSON parses the level name MarshalJSON emits.
//
// Marshal and unmarshal have to be symmetric, or a stored report document is
// a one-way format: it could be written but never read back. The parse is
// strict — anything that is not one of the five level names is an error
// rather than a zero value, because a report whose severity cannot be parsed
// must fail loudly, not silently read as clear. "unknown" is likewise
// rejected: MarshalJSON only emits it for an out-of-range severity, which is
// a bug state no report should be re-read into existence.
func (s *Severity) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case `"clear"`:
		*s = Clear
	case `"low"`:
		*s = Low
	case `"medium"`:
		*s = Medium
	case `"high"`:
		*s = High
	case `"critical"`:
		*s = Critical
	default:
		return fmt.Errorf("mechanics: unknown severity %s", b)
	}
	return nil
}

// Mechanic is a bit in the mechanics bitset. The bit positions are part of the
// contract ABI: do not renumber them.
type Mechanic uint32

const (
	// MechAuthRequired is the issuer's auth_required flag.
	MechAuthRequired Mechanic = 1 << 0
	// MechAuthRevocable is the issuer's auth_revocable flag.
	MechAuthRevocable Mechanic = 1 << 1
	// MechClawbackEnabled is the issuer's auth_clawback_enabled flag.
	MechClawbackEnabled Mechanic = 1 << 2
	// MechFlagsLocked is the issuer's auth_immutable flag. It is not a power
	// over holders; it means the flag set above can never change again.
	MechFlagsLocked Mechanic = 1 << 3
	// MechDomainUnverified means reciprocal SEP-1 domain verification failed.
	MechDomainUnverified Mechanic = 1 << 4
	// MechBlocklisted means a curated source flagged the issuer or its domain.
	MechBlocklisted Mechanic = 1 << 5
	// MechTrustlineClawbackEnabled means the specific holder's trustline has
	// is_clawback_enabled set. Distinct from MechClawbackEnabled, which is
	// the issuer-level flag applicable to new trustlines.
	MechTrustlineClawbackEnabled Mechanic = 1 << 6
	// MechTrustlineDeauthorized means the specific holder's trustline has
	// is_authorized unset: the holder cannot currently transact.
	MechTrustlineDeauthorized Mechanic = 1 << 7
)

// CapabilityMask covers the mechanics that are issuer powers over holders:
// the bits a consumer masks out of the report bitset to read the capability
// the issuer holds on the ledger. It exists to state the escalation invariant
// in code rather than as convention — a finding marked Escalation must carry
// none of these bits, because reputation raising a level must never read as
// the ledger granting a power. Engine.Run enforces this at runtime, and the
// escalation tests enforce it across the eval fixtures. See
// docs/severity-model.md.
//
// It is also the public answer to "which bits are powers": everything outside
// this mask (auth_immutable, domain_unverified, blocklisted) is a reported
// fact, not a power (issue #34). The Rust contract exports the same value as
// CAPABILITY_MASK; the ABI drift test fails the build if the two ever
// disagree. Bit positions are unchanged — existing attestations commit to
// them.
const CapabilityMask = MechAuthRequired | MechAuthRevocable | MechClawbackEnabled

// ConfiscationMask covers the mechanics that let an issuer take a balance.
// Any asset matching this mask has severity >= High by construction.
const ConfiscationMask = MechClawbackEnabled

// names is ordered by bit position for stable output.
var names = []struct {
	bit  Mechanic
	name string
}{
	{MechAuthRequired, "auth_required"},
	{MechAuthRevocable, "auth_revocable"},
	{MechClawbackEnabled, "auth_clawback_enabled"},
	{MechFlagsLocked, "auth_immutable"},
	{MechDomainUnverified, "domain_unverified"},
	{MechBlocklisted, "blocklisted"},
	{MechTrustlineClawbackEnabled, "trustline_clawback_enabled"},
	{MechTrustlineDeauthorized, "trustline_deauthorized"},
}

// Names returns the set bits as their ledger flag names, in bit order.
func (m Mechanic) Names() []string {
	out := []string{}
	for _, n := range names {
		if m&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

// Accountability reports whether an identifiable party stands behind the
// issuer's capability. It is reported alongside severity and never folded into
// it: a verified domain does not make confiscation power safer, it only makes
// the party holding that power identifiable.
type Accountability string

const (
	// AccountabilityUnknown means the issuer advertises no home_domain, so
	// there is no claim to verify.
	AccountabilityUnknown Accountability = "unknown"
	// AccountabilityUnverified means a home_domain is advertised but reciprocal
	// verification failed: the stellar.toml did not resolve, or it resolved and
	// did not claim this asset.
	AccountabilityUnverified Accountability = "unverified"
	// AccountabilityVerified means the issuer's advertised domain published a
	// stellar.toml that names this exact code and issuer.
	AccountabilityVerified Accountability = "verified"
)
