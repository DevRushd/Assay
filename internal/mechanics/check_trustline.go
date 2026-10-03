package mechanics

import (
	"context"
	"fmt"
	"net/url"

	"github.com/use-assay/assay/internal/horizon"
)

// TrustlineCheck reports the actual flags on a specific holder's trustline.
//
// CapabilityCheck answers the prospective question: what can the issuer do to a
// new holder? TrustlineCheck answers the retrospective question: what can the
// issuer do to this holder right now?
//
// Under CAP-0035, is_clawback_enabled is set on a trustline when it is created.
// A holder who opened their trustline before the issuer enabled clawback is not
// exposed — the flag was not set at creation time and SetTrustLineFlagsOp cannot
// add it retroactively. Current issuer flags cannot express this distinction.
//
// Severity decision: trustline findings are informational and do not affect
// report severity. Severity answers what the issuer can do in general (to a
// new holder); it is holder-independent by design so that on-chain gates reading
// severity receive a stable, deterministic number regardless of who is asking.
// Whether a specific holder is currently exposed is a different question and is
// answered here, separately.
type TrustlineCheck struct{}

// ID implements Check.
func (TrustlineCheck) ID() string { return "trustline" }

// Describe implements Check.
func (TrustlineCheck) Describe() string {
	return "Reports the actual clawback and authorization flags on a specific " +
		"holder's trustline. Under CAP-0035, is_clawback_enabled is fixed at " +
		"trustline creation time and does not track later changes to the issuer's " +
		"auth_clawback_enabled flag. Does not affect severity."
}

// Run implements Check.
func (c TrustlineCheck) Run(_ context.Context, s *Subject) (Finding, error) {
	f := Finding{
		Check:    c.ID(),
		Title:    "Holder trustline flags",
		Severity: Clear,
		Evidence: []Evidence{},
	}

	if s.Holder == "" {
		return f, nil
	}

	holderURL := horizon.DefaultURL + "/accounts/" + url.PathEscape(s.Holder)

	if s.HolderTrustlineErr != "" {
		f.Undetermined = true
		f.Reasoning = fmt.Sprintf(
			"Could not fetch trustline flags for holder %s: %s. "+
				"This does not mean the holder is safe — it means the "+
				"holder-specific answer is unknown.",
			s.Holder, s.HolderTrustlineErr,
		)
		f.Evidence = append(f.Evidence, Evidence{
			Source: "horizon",
			URL:    holderURL,
			Claim:  "not retrievable: " + s.HolderTrustlineErr,
			// Fetch failed: attempt time, marked as an attempt.
			RetrievedAt: NewCanonicalTime(s.HolderAttemptedAt),
			Attempted:   true,
		})
		return f, nil
	}

	if s.HolderTrustline == nil {
		f.Undetermined = true
		f.Reasoning = fmt.Sprintf(
			"Holder %s does not hold this asset: no trustline exists to inspect.",
			s.Holder,
		)
		return f, nil
	}

	tl := s.HolderTrustline
	var mech Mechanic
	if tl.IsClawbackEnabled {
		mech |= MechTrustlineClawbackEnabled
	}
	if !tl.IsAuthorized {
		mech |= MechTrustlineDeauthorized
	}
	f.Mechanics = mech

	f.Evidence = append(f.Evidence, Evidence{
		Source: "horizon",
		URL:    holderURL,
		Claim: fmt.Sprintf(
			"trustline %s-%s: is_clawback_enabled=%t is_authorized=%t",
			tl.AssetCode, tl.AssetIssuer, tl.IsClawbackEnabled, tl.IsAuthorized,
		),
		RetrievedAt: NewCanonicalTime(s.HolderFetchedAt),
	})

	switch {
	case tl.IsClawbackEnabled && !tl.IsAuthorized:
		f.Reasoning = fmt.Sprintf(
			"Holder %s opened this trustline while auth_clawback_enabled was active on "+
				"the issuer. Under CAP-0035, is_clawback_enabled was set on the trustline "+
				"at creation time and cannot be cleared retroactively. The issuer can "+
				"confiscate this holder's balance. The trustline is also deauthorized: the "+
				"holder cannot currently transact. Severity is not affected by this finding "+
				"because severity is issuer-level, not holder-specific.",
			s.Holder,
		)
	case tl.IsClawbackEnabled:
		f.Reasoning = fmt.Sprintf(
			"Holder %s opened this trustline while auth_clawback_enabled was active on "+
				"the issuer. Under CAP-0035, is_clawback_enabled was set on the trustline "+
				"at creation time and cannot be cleared retroactively. The issuer can "+
				"confiscate this holder's balance. Severity is not affected by this finding "+
				"because severity is issuer-level, not holder-specific.",
			s.Holder,
		)
	case !tl.IsAuthorized:
		f.Reasoning = fmt.Sprintf(
			"Holder %s has a deauthorized trustline: they cannot currently send or receive "+
				"this asset. The trustline does not have is_clawback_enabled set, so even if "+
				"the issuer currently holds auth_clawback_enabled, clawback does not apply to "+
				"this holder — they opened the trustline before it was enabled, or the issuer "+
				"cleared the account flag after this trustline was created (CAP-0035 "+
				"grandfathering). Severity is not affected by this finding.",
			s.Holder,
		)
	default:
		f.Reasoning = fmt.Sprintf(
			"Holder %s has an authorized trustline with is_clawback_enabled=false. Under "+
				"CAP-0035, this means the trustline was created when auth_clawback_enabled "+
				"was not active on the issuer account. Even if the issuer's current account "+
				"flag is set, clawback does not apply to this specific trustline — it applies "+
				"only to trustlines opened after the flag was enabled. This holder is "+
				"grandfathered out of the issuer's clawback power. Severity is not affected "+
				"by this finding because severity is issuer-level, not holder-specific.",
			s.Holder,
		)
	}

	return f, nil
}
