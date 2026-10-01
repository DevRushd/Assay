package mechanics

import (
	"context"
	"fmt"
	"strings"

	"github.com/use-assay/assay/internal/horizon"
)

// CapabilityCheck derives severity from the issuer's authorization flags.
//
// It is the only check that can set the capability base severity. It reports
// what the issuer is able to do, never who the issuer is.
type CapabilityCheck struct{}

// ID implements Check.
func (CapabilityCheck) ID() string { return "capability" }

// Describe implements Check.
func (CapabilityCheck) Describe() string {
	return "Maps the issuer's authorization flags to a capability severity: " +
		"what the issuer can do to a holder's balance. Says nothing about who " +
		"the issuer is or whether they are likely to use the power."
}

// Run implements Check.
//
// Severity is the highest single capability present, not a sum. auth_revocable
// is a protocol precondition for auth_clawback_enabled (CAP-0035: setting
// clawback without revocable fails with SET_OPTIONS_AUTH_REVOCABLE_REQUIRED),
// so a clawback-capable issuer necessarily also carries revocable. Scoring
// those as two independent signals would double-count a rule the protocol
// enforces, and would make every clawback asset look worse than it is by a
// margin that has nothing to do with its behaviour.
func (c CapabilityCheck) Run(_ context.Context, s *Subject) (Finding, error) {
	f := Finding{
		Check:    c.ID(),
		Title:    "Issuer capability",
		Severity: Clear,
		Evidence: []Evidence{},
	}

	if s.Stat == nil {
		// The flags were never read, so no capability statement exists — not
		// even the statement that there is nothing to state. Reporting Clear
		// here would put the ABI's safest value on a subject nobody assessed
		// (see #23, #25 for that failure shape), so the finding carries the
		// Unevaluated sentinel and marks the report undetermined, which makes
		// it non-attestable at attest.FromReport.
		f.Severity = Unevaluated
		f.Undetermined = true
		f.Reasoning = "Asset not found on the ledger, so no issuer capability could be read: the capability axis is unevaluated, not clear."
		return f, nil
	}

	// Horizon publishes the issuer's authorization flags twice: on the asset
	// record and on the issuer account. Reading one of two available copies and
	// never comparing them is an unforced gap in a tool whose entire output is a
	// claim about issuer power, so they are reconciled here.
	flags, disagreement := reconcileFlags(s)

	var mech Mechanic
	var powers []string

	if flags.AuthRequired {
		mech |= MechAuthRequired
		powers = append(powers, "decide who is allowed to hold it (auth_required)")
		f.Severity = Low
	}
	if flags.AuthRevocable {
		mech |= MechAuthRevocable
		powers = append(powers, "freeze your balance so you cannot move it (auth_revocable)")
		f.Severity = Medium
	}
	if flags.AuthClawbackEnabled {
		mech |= MechClawbackEnabled
		powers = append(powers, "confiscate your balance outright and burn it, "+
			"without your signature (auth_clawback_enabled)")
		f.Severity = High
	}
	f.Mechanics = mech

	f.Evidence = append(f.Evidence, Evidence{
		Source:      "horizon",
		URL:         horizonAssetURL(s.Asset),
		Claim:       "issuer flags: " + flagSummary(flags),
		RetrievedAt: NewCanonicalTime(s.StatFetchedAt),
	})

	// The second source is cited only when it disagrees. Attaching it to every
	// report would restate a fact already in evidence, and would change the
	// evidence_hash of every attestation already written for an asset whose two
	// copies agree — which is all of them.
	if disagreement != "" {
		f.Evidence = append(f.Evidence, Evidence{
			Source:      "horizon/account",
			URL:         horizonAccountURL(s.Asset.Issuer),
			Claim:       "issuer account flags: " + flagSummary(s.Issuer.Flags),
			RetrievedAt: NewCanonicalTime(s.IssuerFetchedAt),
		})
	}

	var b strings.Builder
	if disagreement != "" {
		b.WriteString(disagreement)
		b.WriteString(" ")
	}
	if len(powers) == 0 {
		b.WriteString("The issuer holds no authorization flags. It cannot freeze, " +
			"confiscate, or gate this asset. ")
	} else {
		b.WriteString("The issuer can ")
		b.WriteString(joinPowers(powers))
		b.WriteString(". ")
	}

	// auth_immutable is not a power over holders; it fixes whether the power
	// set can change. It is not scored here and it is not described here:
	// MutabilityCheck reports it as its own finding, so that a reader gets the
	// durability of this verdict without this reasoning having to carry a
	// conditional it cannot score.
	f.Reasoning = b.String()

	return f, nil
}

// reconcileFlags resolves the two copies of the issuer's authorization flags
// Horizon publishes, and reports in plain language when they differ.
//
// The resolution rule is deterministic and always resolves against the holder,
// never in their favour: a power is taken as held when either source says it is
// held. The two sources are separate ingestion paths, so a disagreement means
// one of them is wrong or stale, and there is no way to tell which from inside
// a single scan. Choosing the safer-looking copy would let indexer lag lower a
// severity, which is the one direction this project never resolves silently.
//
// auth_immutable is handled the other way, and deliberately. It is not a power
// over a holder: it fixes whether the power set can change, and the reasoning
// cites it protectively ("the issuer can never add confiscation later") as well
// as as an aggravator. Asserting the lock on a disagreement would hand the
// reader a reassurance one source contradicts, so the lock is claimed only when
// both copies agree it is set. On disagreement the report keeps the cautious
// reading: the flags may still change.
//
// Verified live on 2026-09-25 against six assets spanning the severity range:
// both endpoints carry identical field names and agreed in every case. This
// path is therefore expected to be cold, which is why a disagreement is
// surfaced loudly rather than quietly repaired.
func reconcileFlags(s *Subject) (horizon.Flags, string) {
	asset := s.Stat.Flags
	if s.Issuer == nil {
		return asset, ""
	}
	account := s.Issuer.Flags
	if asset == account {
		return asset, ""
	}

	resolved := horizon.Flags{
		AuthRequired:        asset.AuthRequired || account.AuthRequired,
		AuthRevocable:       asset.AuthRevocable || account.AuthRevocable,
		AuthClawbackEnabled: asset.AuthClawbackEnabled || account.AuthClawbackEnabled,
		AuthImmutable:       asset.AuthImmutable && account.AuthImmutable,
	}

	var differing []string
	for _, d := range []struct {
		name        string
		asset, acct bool
	}{
		{"auth_required", asset.AuthRequired, account.AuthRequired},
		{"auth_revocable", asset.AuthRevocable, account.AuthRevocable},
		{"auth_clawback_enabled", asset.AuthClawbackEnabled, account.AuthClawbackEnabled},
		{"auth_immutable", asset.AuthImmutable, account.AuthImmutable},
	} {
		if d.asset != d.acct {
			differing = append(differing, fmt.Sprintf("%s (asset record %t, issuer account %t)",
				d.name, d.asset, d.acct))
		}
	}

	return resolved, "Horizon's two copies of the issuer's authorization flags disagree on " +
		joinPowers(differing) + ". Both are cited below with their own URL so the " +
		"disagreement can be checked rather than taken on trust. Assay does not know " +
		"which copy is correct, so it resolves against you: a power counted as held " +
		"if either copy reports it, and auth_immutable treated as unset unless both " +
		"copies agree it is set. The severity below is therefore the more dangerous " +
		"of the two readings, not an average of them."
}

func joinPowers(p []string) string {
	switch len(p) {
	case 1:
		return p[0]
	case 2:
		return p[0] + ", and " + p[1]
	default:
		return strings.Join(p[:len(p)-1], ", ") + ", and " + p[len(p)-1]
	}
}
