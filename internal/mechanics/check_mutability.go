package mechanics

import (
	"context"
	"fmt"
	"strings"

	"github.com/use-assay/assay/internal/horizon"
)

// MutabilityCheck reports whether the issuer's authorization flag set can still
// change. It is modelled on DomainCheck: it reports a first-class finding and
// never sets a severity.
//
// auth_immutable is deliberately not a severity level. It is not a power over
// holders; it fixes whether the power set can change, and which direction that
// cuts depends entirely on what is already set. So it cannot be carried by a
// number, and it is reported here instead:
//
//   - Locked with no dangerous flags — a durable safety property. Clawback and
//     freeze can never be added.
//   - Locked with freeze or clawback — permanence. The power can never be given
//     up.
//   - Not locked — the issuer may add freeze or confiscation later. Under
//     CAP-0035 that would not reach trustlines that already exist, but it would
//     apply to any trustline opened after the change.
//
// The third case is the one a prospective holder wants surfaced, because it is
// the one where today's clear is not a durable answer. It is stated rather than
// scored, because a single severity number cannot carry a conditional.
//
// Flag source: this check reads the reconciled flag set the capability check
// derives severity from — reconcileFlags resolves Horizon's two copies of the
// issuer flags (the /assets record and the /accounts record), counting a power
// held when either copy reports it and auth_immutable as set only when both
// copies agree. Reading that same set here keeps this finding consistent with
// the severity next to it, and means a lock is never claimed while a source
// contradicts it: asserting a lock one copy disputes would hand the reader a
// reassurance the evidence does not support.
//
// It emits no Evidence. The flag read is already attributed by the capability
// finding, and the evidence_hash preimage is a sorted multiset: emitting a
// second copy of the same claim — or a new claim about the same read — would
// change the hash of every attestation whose underlying evidence did not
// change, which the encoding is explicitly designed to prevent.
type MutabilityCheck struct{}

// ID implements Check.
func (MutabilityCheck) ID() string { return "mutability" }

// Describe implements Check.
func (MutabilityCheck) Describe() string {
	return "Reports whether the issuer's flag set can still change: locked with " +
		"no dangerous flags (a durable safety property), locked with freeze or " +
		"clawback (the power is permanent), or unlocked (the issuer may add freeze " +
		"or confiscation later, which under CAP-0035 would not reach existing " +
		"trustlines but would apply to ones opened after the change). Never sets " +
		"severity: auth_immutable is not a power over holders."
}

// Run implements Check.
func (c MutabilityCheck) Run(_ context.Context, s *Subject) (Finding, error) {
	f := Finding{
		Check:    c.ID(),
		Title:    "Issuer flag mutability",
		Severity: Clear, // mutability is never severity
		Evidence: []Evidence{},
	}

	if s.Stat == nil {
		f.Undetermined = true
		f.Reasoning = "The asset was not found on the ledger, so no issuer flags " +
			"could be read. Whether the flag set can still change is unknown, " +
			"which is not the same as unlocked and not the same as safe."
		return f, nil
	}

	flags, _ := reconcileFlags(s)
	if flags.AuthImmutable {
		f.Mechanics = MechFlagsLocked
	}

	powers := holderPowers(flags)
	switch {
	case flags.AuthImmutable && len(powers) == 0:
		f.Reasoning = "The issuer's flag set is locked (auth_immutable is set) and " +
			"the issuer holds no freeze or confiscation power. That is a durable " +
			"safety property: because the flag set can never change again, " +
			"auth_revocable and auth_clawback_enabled can never be added later, so " +
			"this asset is clear for a trustline opened now and stays clear for one " +
			"opened later. This does not move severity; it reports the durability of " +
			"the verdict the capability check already reached."
	case flags.AuthImmutable:
		f.Reasoning = fmt.Sprintf(
			"The issuer's flag set is locked (auth_immutable is set) while the issuer "+
				"can %s. The lock makes the power permanent: no flag in this set can be "+
				"given up, because auth_immutable itself cannot be cleared once set. "+
				"Locking does not make the power safer — it removes any future in which "+
				"the issuer relinquishes it. Severity is unchanged; this is a report "+
				"about durability, not a new capability.",
			joinPowers(powers))
	default:
		var b strings.Builder
		b.WriteString("The issuer's flag set is not locked (auth_immutable is unset), " +
			"so it can still change. ")
		if len(powers) == 0 {
			b.WriteString("The issuer holds no freeze or confiscation power today, " +
				"but it may add auth_revocable or auth_clawback_enabled later. ")
		} else {
			fmt.Fprintf(&b,
				"The issuer can %s today, and it may give that power up, or add "+
					"another, later. ", joinPowers(powers))
		}
		b.WriteString("Under CAP-0035 a flag added later applies only to trustlines " +
			"opened after the change — it does not reach a trustline that already " +
			"exists — so this verdict is correct for a trustline opened now but is " +
			"not guaranteed to stay correct for one opened later. Severity is " +
			"unchanged; mutability is reported, not scored.")
		f.Reasoning = b.String()
	}

	return f, nil
}

// holderPowers names the flags that act against a holder who already holds the
// asset, using the severity model's language. auth_required is excluded: it
// gates entry and cannot touch an existing holder (severity Low).
func holderPowers(f horizon.Flags) []string {
	var powers []string
	if f.AuthRevocable {
		powers = append(powers, "freeze an existing holder's balance (auth_revocable)")
	}
	if f.AuthClawbackEnabled {
		powers = append(powers, "confiscate your balance outright and burn it (auth_clawback_enabled)")
	}
	return powers
}
