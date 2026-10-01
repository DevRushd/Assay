package mechanics_test

// TestABIDriftBetweenGoAndRust fails if the Go engine and the Rust contract
// disagree on any SEVERITY_* value, any MECH_* bit position, or the value of
// CONFISCATION_MASK. The two sides independently define the same ABI (Go in
// internal/mechanics/severity.go, Rust in
// assay-contracts/contracts/safety-registry/src/lib.rs), both comment it as
// ABI that must not be renumbered, and until this test existed nothing
// enforced it.
//
// Drift is silent and dangerous: an attestation written with one bit layout
// and read with the other means a gate enforcing a different policy than the
// operator configured, with no error anywhere.
//
// The test reads the Rust file as text and parses every `pub const NAME: u32 =
// <expr>;`. The generation-first approach the issue prefers (soroban contract
// bindings) needs the stellar CLI, and CI must not depend on external
// toolchains for this check — a parser over source text runs anywhere the Go
// build does, without a network, without cargo, and without deploying
// anything. Adding a new MECH_* on one side without the other still fails the
// build, which is what the check is for.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/mechanics"
)

// contractSourcePath resolves the Rust file relative to this test file so the
// check works both from `go test ./...` at the repo root and from a package
// directory. runtime.Caller is used rather than a hard-coded relative path
// because Go tests can run from either.
func contractSourcePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/mechanics/abi_drift_test.go -> repo root
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	return filepath.Join(repoRoot, "assay-contracts", "contracts",
		"safety-registry", "src", "lib.rs")
}

// parseRustU32Consts extracts every `pub const NAME: u32 = <expr>;` from the
// Rust source and evaluates the small subset of expressions the ABI uses:
// integer literals (`0`, `3`), bit shifts (`1 << 5`), and bitwise-or
// combinations of previously-defined names (`A | B`). Anything else is
// reported as an error rather than silently ignored, so an ABI constant added
// in a shape the parser cannot read is a red build.
func parseRustU32Consts(t *testing.T, src string) map[string]uint32 {
	t.Helper()
	// Strip line comments so `//` text does not fool the extractor.
	commentRe := regexp.MustCompile(`//[^\n]*`)
	src = commentRe.ReplaceAllString(src, "")

	constRe := regexp.MustCompile(`pub const (\w+):\s*u32\s*=\s*([^;]+);`)
	out := map[string]uint32{}
	for _, m := range constRe.FindAllStringSubmatch(src, -1) {
		name := m[1]
		expr := strings.TrimSpace(m[2])
		v, err := evalU32Expr(expr, out)
		if err != nil {
			t.Fatalf("cannot evaluate rust const %s = %q: %v", name, expr, err)
		}
		out[name] = v
	}
	return out
}

func evalU32Expr(expr string, env map[string]uint32) (uint32, error) {
	// Bitwise-or: fold left over `|`.
	if strings.Contains(expr, "|") {
		var acc uint32
		for _, part := range strings.Split(expr, "|") {
			v, err := evalU32Expr(strings.TrimSpace(part), env)
			if err != nil {
				return 0, err
			}
			acc |= v
		}
		return acc, nil
	}
	// Left-shift: `a << b`, both integer literals.
	if strings.Contains(expr, "<<") {
		parts := strings.SplitN(expr, "<<", 2)
		lhs, err := parseU32Atom(strings.TrimSpace(parts[0]), env)
		if err != nil {
			return 0, err
		}
		rhs, err := parseU32Atom(strings.TrimSpace(parts[1]), env)
		if err != nil {
			return 0, err
		}
		return lhs << rhs, nil
	}
	return parseU32Atom(expr, env)
}

func parseU32Atom(s string, env map[string]uint32) (uint32, error) {
	if v, ok := env[s]; ok {
		return v, nil
	}
	n, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

func TestABIDriftSeverityValues(t *testing.T) {
	src, err := os.ReadFile(contractSourcePath(t))
	if err != nil {
		t.Fatalf("read contract source: %v", err)
	}
	rust := parseRustU32Consts(t, string(src))

	// Every ABI value the Go side pins must exist in the Rust source at the
	// same numeric value. Values only used on one side (e.g. mechanics.Unevaluated,
	// which deliberately does not reach the chain) are excluded here.
	cases := []struct {
		rustName string
		goValue  uint32
	}{
		{"SEVERITY_CLEAR", uint32(mechanics.Clear)},
		{"SEVERITY_LOW", uint32(mechanics.Low)},
		{"SEVERITY_MEDIUM", uint32(mechanics.Medium)},
		{"SEVERITY_HIGH", uint32(mechanics.High)},
		{"SEVERITY_CRITICAL", uint32(mechanics.Critical)},
	}
	for _, c := range cases {
		got, ok := rust[c.rustName]
		if !ok {
			t.Errorf("rust const %s missing: adding a severity on one side "+
				"without the other is drift", c.rustName)
			continue
		}
		if got != c.goValue {
			t.Errorf("severity drift on %s: rust=%d go=%d", c.rustName, got, c.goValue)
		}
	}
}

func TestABIDriftMechanicBits(t *testing.T) {
	src, err := os.ReadFile(contractSourcePath(t))
	if err != nil {
		t.Fatalf("read contract source: %v", err)
	}
	rust := parseRustU32Consts(t, string(src))

	// Every mechanic the contract publishes must exist on the Go side with the
	// same bit. The Go side may carry additional mechanics that are not part
	// of the on-chain ABI (trustline-scoped bits are not written to the
	// contract), so a Go-only mechanic is not drift on its own — but every
	// contract-side mechanic must match.
	cases := []struct {
		rustName string
		goValue  uint32
	}{
		{"MECH_AUTH_REQUIRED", uint32(mechanics.MechAuthRequired)},
		{"MECH_AUTH_REVOCABLE", uint32(mechanics.MechAuthRevocable)},
		{"MECH_CLAWBACK_ENABLED", uint32(mechanics.MechClawbackEnabled)},
		{"MECH_FLAGS_LOCKED", uint32(mechanics.MechFlagsLocked)},
		{"MECH_DOMAIN_UNVERIFIED", uint32(mechanics.MechDomainUnverified)},
		{"MECH_BLOCKLISTED", uint32(mechanics.MechBlocklisted)},
	}
	for _, c := range cases {
		got, ok := rust[c.rustName]
		if !ok {
			t.Errorf("rust const %s missing: adding a mechanic on one side "+
				"without the other is drift", c.rustName)
			continue
		}
		if got != c.goValue {
			t.Errorf("mechanic drift on %s: rust=1<<%d go=1<<%d", c.rustName,
				trailingZeros(got), trailingZeros(c.goValue))
		}
	}
}

func TestABIDriftConfiscationMask(t *testing.T) {
	src, err := os.ReadFile(contractSourcePath(t))
	if err != nil {
		t.Fatalf("read contract source: %v", err)
	}
	rust := parseRustU32Consts(t, string(src))

	got, ok := rust["CONFISCATION_MASK"]
	if !ok {
		t.Fatal("rust CONFISCATION_MASK missing")
	}
	if got != uint32(mechanics.ConfiscationMask) {
		t.Errorf("CONFISCATION_MASK drift: rust=%#x go=%#x",
			got, uint32(mechanics.ConfiscationMask))
	}
}

// TestABIDriftCapabilityMask extends the #15 drift check to the #34 mask: the
// capability/power bits must be selectable by name on BOTH sides and the two
// sides must agree on the value, or a consumer picking the mask from the wrong
// language's definition silently selects a different set of powers.
func TestABIDriftCapabilityMask(t *testing.T) {
	src, err := os.ReadFile(contractSourcePath(t))
	if err != nil {
		t.Fatalf("read contract source: %v", err)
	}
	rust := parseRustU32Consts(t, string(src))

	got, ok := rust["CAPABILITY_MASK"]
	if !ok {
		t.Fatal("rust CAPABILITY_MASK missing")
	}
	if got != uint32(mechanics.CapabilityMask) {
		t.Errorf("CAPABILITY_MASK drift: rust=%#x go=%#x",
			got, uint32(mechanics.CapabilityMask))
	}

	// The mask is exactly the three power bits and nothing else: a reported
	// bit leaking in (or a power bit left out) is the #26 failure shape.
	want := uint32(mechanics.MechAuthRequired | mechanics.MechAuthRevocable |
		mechanics.MechClawbackEnabled)
	if uint32(mechanics.CapabilityMask) != want {
		t.Errorf("CapabilityMask = %#x, want the three power bits %#x",
			uint32(mechanics.CapabilityMask), want)
	}
	if mechanics.CapabilityMask&^(mechanics.MechAuthRequired|mechanics.MechAuthRevocable|mechanics.MechClawbackEnabled) != 0 {
		t.Errorf("CapabilityMask carries reported-only bits: %#x", uint32(mechanics.CapabilityMask))
	}
}

func trailingZeros(x uint32) int {
	if x == 0 {
		return -1
	}
	n := 0
	for x&1 == 0 {
		x >>= 1
		n++
	}
	return n
}
