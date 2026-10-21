#!/usr/bin/env bash
# Tests for scripts/reproducibility.sh: version-aware comparison, the four
# outcomes (PASS/MISMATCH/ENCODING/INCONCLUSIVE), exit-code precedence, and
# refusal of a table whose Preimage column is missing or unknown. The assay
# binary is a stub and the deployment table is a fixture; nothing here talks
# to a network.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$ROOT/scripts/reproducibility.sh"
TMPDIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

BIN="$TMPDIR/assay"
cat >"$BIN" <<'STUB'
#!/usr/bin/env bash
# Test double for the assay binary. Serves one asset per run from
# $STUB_CONTROL, lines of "ASSET<TAB>rc<TAB>requested-hash<TAB>current-hash",
# and logs "VERSION ASSET" per invocation to $STUB_LOG. It accepts only
# `attestation -raw -preimage-version VN ASSET`: any other shape exits 64, so
# a script regression that drops or renames the flag fails the tests rather
# than silently comparing the wrong bytes.
set -u
if [ "${1:-}" != "attestation" ] || [ "${2:-}" != "-raw" ] || [ "${3:-}" != "-preimage-version" ] || [ $# -ne 5 ]; then
    echo "stub: unsupported invocation: $*" >&2
    exit 64
fi
version="$4"
asset="$5"
printf '%s %s\n' "$version" "$asset" >>"$STUB_LOG"
while IFS=$'\t' read -r a rc req cur; do
    [ -n "$a" ] || continue
    if [ "$a" = "$asset" ]; then
        if [ "${rc:-0}" != "0" ]; then
            echo "stub: forced failure for $asset" >&2
            exit "${rc:-0}"
        fi
        printf '0\t0\t%s\t%s\n' "$req" "$cur"
        exit 0
    fi
done <"$STUB_CONTROL"
echo "stub: unknown asset $asset" >&2
exit 1
STUB
chmod +x "$BIN"

ISSUER="GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"
SAC="CDJF2JQINO7WRFXB2AAHLONFDPPI4M3W2UM5THGQQ7JMJDIEJYC4CMPG"

H_PASS="$(printf 'a%.0s' {1..64})"
H_OTHER="$(printf 'b%.0s' {1..64})"
H_THIRD="$(printf 'c%.0s' {1..64})"
H_FOURTH="$(printf 'd%.0s' {1..64})"

CONTROL="$TMPDIR/control.tsv"
STUB_LOG="$TMPDIR/stub.log"
export STUB_CONTROL="$CONTROL" STUB_LOG

reset() {
    : >"$STUB_LOG"
    : >"$CONTROL"
}

# table ROWS: ROWS is a file of `| \`CODE\` | \`ISSUER\` | \`SAC\` | \`HASH\` | \`VERSION\` |` lines.
write_table() {
    {
        echo '| Asset | Issuer | Testnet SAC address | `evidence_hash` | Preimage |'
        echo '| --- | --- | --- | --- | --- |'
        cat "$1"
    } >"$TMPDIR/table.md"
}

run() {
    set +e
    OUTPUT="$("$SCRIPT" --bin "$BIN" --deployment "$TMPDIR/table.md" --attempts 1 --delay 0 2>&1)"
    RC=$?
    set -e
}

fail() {
    echo "FAIL: $1" >&2
    echo "--- output (rc=$RC) ---" >&2
    printf '%s\n' "$OUTPUT" >&2
    exit 1
}

expect_rc() {
    [ "$RC" -eq "$1" ] || fail "expected exit $1, got $RC"
}

expect_output() {
    printf '%s' "$OUTPUT" | grep -Fq -- "$1" || fail "output does not contain: $1"
}

# 1. PASS: the requested-version rendering matches the recorded hash.
reset
printf '%s\t0\t%s\t%s\n' "AQUA-$ISSUER" "$H_PASS" "$H_OTHER" >"$CONTROL"
printf '| `AQUA` | `%s` | `%s` | `%s` | `v1` |\n' "$ISSUER" "$SAC" "$H_PASS" >"$TMPDIR/rows"
write_table "$TMPDIR/rows"
run
expect_rc 0
expect_output "PASS AQUA-$ISSUER $H_PASS"
expect_output "result: PASS"
grep -Fq -- "v1 AQUA-$ISSUER" "$STUB_LOG" || fail "script did not ask the binary for v1 bytes"

# 2. PASS through a truncated `prefix…suffix` record, as the real table uses.
reset
printf '%s\t0\t%s\t%s\n' "AQUA-$ISSUER" "$H_PASS" "$H_OTHER" >"$CONTROL"
FRAG="$(printf 'a%.0s' {1..8})…$(printf 'a%.0s' {1..6})"
printf '| `AQUA` | `%s` | `%s` | `%s` | `v1` |\n' "$ISSUER" "$SAC" "$FRAG" >"$TMPDIR/rows"
write_table "$TMPDIR/rows"
run
expect_rc 0
expect_output "PASS"

# 3. MISMATCH: neither the requested version nor the current encoding
#    reproduces the recorded hash — the evidence itself moved.
reset
printf '%s\t0\t%s\t%s\n' "AQUA-$ISSUER" "$H_THIRD" "$H_FOURTH" >"$CONTROL"
printf '| `AQUA` | `%s` | `%s` | `%s` | `v1` |\n' "$ISSUER" "$SAC" "$H_PASS" >"$TMPDIR/rows"
write_table "$TMPDIR/rows"
run
expect_rc 1
expect_output "MISMATCH AQUA-$ISSUER expected $H_PASS actual $H_THIRD"
expect_output "result: FAIL"

# 4. ENCODING: the recorded hash reproduces under the current encoding but
#    not under the version the table records — evidence unchanged, metadata
#    (or the encoder behind it) disagrees.
reset
printf '%s\t0\t%s\t%s\n' "AQUA-$ISSUER" "$H_THIRD" "$H_PASS" >"$CONTROL"
printf '| `AQUA` | `%s` | `%s` | `%s` | `v1` |\n' "$ISSUER" "$SAC" "$H_PASS" >"$TMPDIR/rows"
write_table "$TMPDIR/rows"
run
expect_rc 3
expect_output "ENCODING AQUA-$ISSUER"
expect_output "result: ENCODING"

# 5. INCONCLUSIVE: a scan that cannot complete is neither a pass nor a
#    failure, and it is retried --attempts times.
reset
printf '%s\t1\t-\t-\n' "AQUA-$ISSUER" >"$CONTROL"
printf '| `AQUA` | `%s` | `%s` | `%s` | `v1` |\n' "$ISSUER" "$SAC" "$H_PASS" >"$TMPDIR/rows"
write_table "$TMPDIR/rows"
run
expect_rc 2
expect_output "INCONCLUSIVE AQUA-$ISSUER"
expect_output "result: INCONCLUSIVE"

# 6. Precedence: a mismatch outranks an encoding disagreement, which
#    outranks an incomplete scan.
reset
printf '%s\t0\t%s\t%s\n' "AQUA-$ISSUER" "$H_THIRD" "$H_FOURTH" >"$CONTROL"
printf '%s\t0\t%s\t%s\n' "USDC-$ISSUER" "$H_THIRD" "$H_PASS" >>"$CONTROL"
printf '%s\t1\t-\t-\n' "VELO-$ISSUER" >>"$CONTROL"
{
    printf '| `AQUA` | `%s` | `%s` | `%s` | `v1` |\n' "$ISSUER" "$SAC" "$H_PASS"
    printf '| `USDC` | `%s` | `%s` | `%s` | `v1` |\n' "$ISSUER" "$SAC" "$H_PASS"
    printf '| `VELO` | `%s` | `%s` | `%s` | `v1` |\n' "$ISSUER" "$SAC" "$H_PASS"
} >"$TMPDIR/rows"
write_table "$TMPDIR/rows"
run
expect_rc 1
expect_output "MISMATCH AQUA-$ISSUER"
expect_output "ENCODING USDC-$ISSUER"
expect_output "INCONCLUSIVE VELO-$ISSUER"

# ... and encoding outranks inconclusive when no mismatch exists.
reset
printf '%s\t0\t%s\t%s\n' "USDC-$ISSUER" "$H_THIRD" "$H_PASS" >"$CONTROL"
printf '%s\t1\t-\t-\n' "VELO-$ISSUER" >>"$CONTROL"
{
    printf '| `USDC` | `%s` | `%s` | `%s` | `v1` |\n' "$ISSUER" "$SAC" "$H_PASS"
    printf '| `VELO` | `%s` | `%s` | `%s` | `v1` |\n' "$ISSUER" "$SAC" "$H_PASS"
} >"$TMPDIR/rows"
write_table "$TMPDIR/rows"
run
expect_rc 3
expect_output "ENCODING USDC-$ISSUER"
expect_output "INCONCLUSIVE VELO-$ISSUER"

# 7. A table without the Preimage column is a script error, not an outcome:
#    the script cannot compare like with like and must not guess.
reset
printf '| `AQUA` | `%s` | `%s` | `%s` |\n' "$ISSUER" "$SAC" "$H_PASS" >"$TMPDIR/rows"
write_table "$TMPDIR/rows"
run
expect_rc 1
expect_output "records preimage version"

# ... and an unknown encoding is refused the same way.
reset
printf '| `AQUA` | `%s` | `%s` | `%s` | `v9` |\n' "$ISSUER" "$SAC" "$H_PASS" >"$TMPDIR/rows"
write_table "$TMPDIR/rows"
run
expect_rc 1
expect_output "records preimage version 'v9'"

# 8. The recorded version is what is asked for: a v2 record gets -preimage-version v2.
reset
printf '%s\t0\t%s\t%s\n' "AQUA-$ISSUER" "$H_PASS" "$H_OTHER" >"$CONTROL"
printf '| `AQUA` | `%s` | `%s` | `%s` | `v2` |\n' "$ISSUER" "$SAC" "$H_PASS" >"$TMPDIR/rows"
write_table "$TMPDIR/rows"
run
expect_rc 0
grep -Fq -- "v2 AQUA-$ISSUER" "$STUB_LOG" || fail "script did not ask the binary for v2 bytes"

echo "test-reproducibility: all checks passed"
