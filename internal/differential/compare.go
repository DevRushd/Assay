package differential

import (
	"context"
	"fmt"

	"github.com/use-assay/assay/internal/horizon"
)

// State answers what a comparison established. The four states are the point
// of the package: "agreed" and "could not check" are different answers, and a
// consumer that reads only the flags would collapse them. The rule is the
// same one docs/checks.md states for checks: 'we could not check' and 'this
// is fine' must never render the same.
type State string

const (
	// StateAgreement means both derivations ran and produced identical flags.
	StateAgreement State = "agreement"
	// StateDisagreement means both derivations ran and differ. Both values
	// are reported on the Result; nothing anywhere in this package picks a
	// winner, because auto-resolving a detected fault is how a detected fault
	// becomes an undetectable one.
	StateDisagreement State = "disagreement"
	// StateInconclusiveOneSide means exactly one derivation produced no
	// answer. One honest answer plus one absence is not agreement: the absent
	// side could have found exactly the fault this package exists to catch.
	StateInconclusiveOneSide State = "inconclusive_one_side"
	// StateInconclusiveBothSides means neither derivation produced an answer.
	StateInconclusiveBothSides State = "inconclusive_both_sides"
)

// PrimaryProvider supplies the scanner's reading of an issuer's flags — the
// primary derivation this package checks.
//
// In production the scanner's reading is assembled from the Subject the scan
// already fetched (the /assets record and the /accounts record, already
// reconciled by the capability check). It is an interface rather than a
// concrete type so tests can inject a deliberately wrong primary — the
// acceptance test from #48 — without standing up a network.
type PrimaryProvider interface {
	IssuerFlags(ctx context.Context, issuer string) (horizon.Flags, error)
}

// SubjectProvider adapts a fetched mechanics.Subject to PrimaryProvider.
//
// The scanner reads the issuer's flags twice — once on the /assets record and
// once on the issuer /accounts record — and the capability check already
// reconciles them by taking the more dangerous reading on disagreement. This
// provider hands over that same reconciled reading, because the differential
// check must compare against exactly what the scanner believed, not against
// one of its two copies. A nil Subject is an error, never zero flags: an
// unread flag must not serialize as a permissive answer, here or anywhere.
type SubjectProvider struct {
	// StatFlags and AccountFlags are the two copies the scanner fetched;
	// StatFlags is nil when the asset record was never loaded.
	StatFlags   *horizon.Flags
	AccountFlag *horizon.Flags
}

// NewSubjectProvider builds a SubjectProvider from the two flag copies a
// mechanics.Subject carries. Both arguments may be nil; at most one may be
// non-nil for a reading to exist.
func NewSubjectProvider(stat, account *horizon.Flags) *SubjectProvider {
	return &SubjectProvider{StatFlags: stat, AccountFlag: account}
}

// IssuerFlags implements PrimaryProvider, returning the reconciled reading the
// engine's capability check would have derived: a power counted as held if
// either copy reports it (the cautious direction), and reported as an error
// when neither copy exists.
func (p *SubjectProvider) IssuerFlags(_ context.Context, _ string) (horizon.Flags, error) {
	switch {
	case p.StatFlags != nil && p.AccountFlag != nil:
		// Same reconciliation rule as mechanics.reconcileFlags: the more
		// dangerous reading on disagreement. This provider is not the place
		// to invent a second rule.
		return horizon.Flags{
			AuthRequired:        p.StatFlags.AuthRequired || p.AccountFlag.AuthRequired,
			AuthRevocable:       p.StatFlags.AuthRevocable || p.AccountFlag.AuthRevocable,
			AuthClawbackEnabled: p.StatFlags.AuthClawbackEnabled || p.AccountFlag.AuthClawbackEnabled,
			AuthImmutable:       p.StatFlags.AuthImmutable && p.AccountFlag.AuthImmutable,
		}, nil
	case p.StatFlags != nil:
		return *p.StatFlags, nil
	case p.AccountFlag != nil:
		return *p.AccountFlag, nil
	default:
		// Neither copy exists: the scanner never read the flags. Refusing here
		// keeps an unread flag from rendering as agreement or as zero flags.
		return horizon.Flags{}, ErrNoPrimaryReading
	}
}

// ErrNoPrimaryReading reports that the primary side produced no flag reading
// at all — the scanner never loaded them. It is an inconclusive state, never
// agreement.
var ErrNoPrimaryReading = fmt.Errorf("differential: primary scan produced no issuer flag reading")

// Result is what one comparison concluded, with enough detail that a human or
// a program can audit it: both readings, both error paths, and the state that
// ties them together.
type Result struct {
	Asset     string         `json:"asset"`
	Issuer    string         `json:"issuer"`
	State     State          `json:"state"`
	Primary   *horizon.Flags `json:"primary,omitempty"`
	Secondary *horizon.Flags `json:"secondary,omitempty"`
	// PrimaryErr and SecondaryErr carry why a side produced no reading,
	// verbatim. A side that answered never populates its error, and a side
	// that errored never populates its reading — the two are the same axis,
	// and conflating them would make an outage indistinguishable from an
	// answer.
	PrimaryErr   string `json:"primary_error,omitempty"`
	SecondaryErr string `json:"secondary_error,omitempty"`
	// Reason states, in one line, why the state is what it is — in
	// particular why an inconclusive state is not agreement.
	Reason string `json:"reason"`
}

// Compare derives the issuer's flags independently and compares the result
// against the primary reading.
//
// The two derivations are fetched in this order — primary first, independent
// second — but no ordering assumption leaks into the result: the state
// depends only on which sides answered and whether the answers match. Any
// error from either side becomes an inconclusive state with the error named;
// nothing here retries, times out differently, or otherwise tries to make one
// side look better than it is.
func Compare(ctx context.Context, assetCode, issuer string, primary PrimaryProvider, secondary *Client) Result {
	res := Result{Asset: assetCode, Issuer: issuer}

	primFlags, primErr := primary.IssuerFlags(ctx, issuer)
	secFlags, secErr := secondary.AccountFlags(ctx, issuer)

	switch {
	case primErr != nil && secErr != nil:
		res.State = StateInconclusiveBothSides
		res.PrimaryErr = primErr.Error()
		res.SecondaryErr = secErr.Error()
		res.Reason = "neither derivation produced a reading, so nothing was verified; this is not agreement"
	case primErr != nil:
		res.State = StateInconclusiveOneSide
		res.PrimaryErr = primErr.Error()
		res.Secondary = &secFlags
		res.Reason = "the independent derivation answered but the scanner produced no reading, so nothing was compared"
	case secErr != nil:
		res.State = StateInconclusiveOneSide
		res.Primary = &primFlags
		res.SecondaryErr = secErr.Error()
		res.Reason = "the scanner produced a reading but the independent derivation could not run; an independent failure is not agreement"
	case primFlags == secFlags:
		res.State = StateAgreement
		res.Primary = &primFlags
		res.Secondary = &secFlags
		res.Reason = "both derivations read the same authorization flags from different protocols, servers, and encodings"
	default:
		res.State = StateDisagreement
		res.Primary = &primFlags
		res.Secondary = &secFlags
		res.Reason = "the two derivations disagree; both values are reported and neither is chosen"
	}
	return res
}
