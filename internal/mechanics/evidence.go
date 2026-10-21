package mechanics

import (
	"fmt"
	"net/url"

	"github.com/use-assay/assay/internal/horizon"
)

// horizonAssetURL returns the public Horizon URL backing an asset claim, so the
// reader can re-fetch exactly what Assay read.
func horizonAssetURL(a Asset) string {
	q := url.Values{}
	q.Set("asset_code", a.Code)
	q.Set("asset_issuer", a.Issuer)
	return horizon.DefaultURL + "/assets?" + q.Encode()
}

// horizonAccountURL returns the public Horizon URL for the issuer account, so
// a reader can re-fetch the second copy of the authorization flags themselves.
//
// Horizon publishes the issuer's flags twice: on the asset record and on the
// account. Verified live on 2026-09-25 across six assets, both endpoints carry
// the identical four field names and agreed in every case. That agreement is
// what makes a disagreement worth reporting rather than averaging away.
func horizonAccountURL(issuer string) string {
	return horizon.DefaultURL + "/accounts/" + url.PathEscape(issuer)
}

// flagSummary renders the issuer flag set in Horizon's own vocabulary.
func flagSummary(f horizon.Flags) string {
	return fmt.Sprintf(
		"auth_required=%t auth_revocable=%t auth_immutable=%t auth_clawback_enabled=%t",
		f.AuthRequired, f.AuthRevocable, f.AuthImmutable, f.AuthClawbackEnabled,
	)
}
