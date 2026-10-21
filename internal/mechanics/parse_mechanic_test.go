package mechanics_test

import (
	"testing"

	"github.com/use-assay/assay/internal/mechanics"
)

// TestParseMechanicNamesRoundTrips pins the inverse of Mechanic.Names. A saved
// report carries only the names, so a reader that needs the bits back has to be
// able to recover exactly the set the report was written with.
func TestParseMechanicNamesRoundTrips(t *testing.T) {
	for _, m := range []mechanics.Mechanic{
		0,
		mechanics.MechAuthRequired,
		mechanics.MechAuthRevocable | mechanics.MechDomainUnverified,
		mechanics.MechClawbackEnabled | mechanics.MechBlocklisted | mechanics.MechFlagsLocked,
		mechanics.MechAuthRequired | mechanics.MechAuthRevocable |
			mechanics.MechClawbackEnabled | mechanics.MechFlagsLocked |
			mechanics.MechDomainUnverified | mechanics.MechBlocklisted |
			mechanics.MechTrustlineClawbackEnabled | mechanics.MechTrustlineDeauthorized,
	} {
		got, err := mechanics.ParseMechanicNames(m.Names())
		if err != nil {
			t.Fatalf("ParseMechanicNames(%v): %v", m.Names(), err)
		}
		if got != m {
			t.Fatalf("ParseMechanicNames(%v) = %d, want %d", m.Names(), got, m)
		}
	}
}

func TestParseMechanicNamesRejectsUnknown(t *testing.T) {
	if _, err := mechanics.ParseMechanicNames([]string{"auth_revocable", "invented_power"}); err == nil {
		t.Fatal("ParseMechanicNames accepted an unknown mechanic; want an error")
	}
}
