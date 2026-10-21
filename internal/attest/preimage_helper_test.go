package attest_test

import (
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// mustPreimage renders a report's preimage and fails the test if its bindings
// match no encoding.
func mustPreimage(t *testing.T, rep *mechanics.Report) string {
	t.Helper()
	pre, err := attest.Preimage(rep)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	return pre
}
