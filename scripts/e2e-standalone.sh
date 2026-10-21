#!/usr/bin/env bash
# End-to-end test on a local Stellar network (issue #463).
#
# It joins the two halves of the project that were previously tested apart:
#
#   1. the scanner derives attest() arguments from committed fixtures, never
#      from Horizon, StellarExpert, an issuer domain, or any public network;
#   2. the stellar CLI submits those exact arguments to the safety registry;
#   3. the registry and the example gate are read back, asserting admit and
#      refuse for clear, high and critical subjects.
#
# The fixture path is deliberate. A live scan would make this test depend on
# the same rate-limited, periodically reset public sources the hermetic test
# exists to escape. cmd/attestfixture runs the real engine over the captured
# payloads, so the same evidence the corpus uses produces the submitted values.
#
# Start a local network first; the CI workflow uses stellar/quickstart's local
# mode (port 8000), and `stellar container start local` does the same locally.
# This script refuses a non-loopback RPC URL: it is not a testnet tool.
#
# Usage:
#   scripts/e2e-standalone.sh [--rpc-url URL] [--network-passphrase TEXT]
#                             [--source NAME] [--fixtures DIR]
#
# Exit codes:
#   0  every assertion passed
#   1  an assertion failed
#   2  the test could not run (missing tool, unreachable local network, build
#      failure). Never reported as a pass.
set -euo pipefail

usage() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

RPC_URL="http://localhost:8000/rpc"
NETWORK_PASSPHRASE="Standalone Network ; February 2017"
SOURCE="assay-e2e"
FIXTURES="$ROOT/internal/mechanics/testdata"

while [ $# -gt 0 ]; do
  case "$1" in
    --rpc-url)              [ $# -ge 2 ] || { echo "e2e: --rpc-url needs a value" >&2; exit 2; }; RPC_URL=$2; shift 2 ;;
    --rpc-url=*)            RPC_URL=${1#--rpc-url=}; shift ;;
    --network-passphrase)   [ $# -ge 2 ] || { echo "e2e: --network-passphrase needs a value" >&2; exit 2; }; NETWORK_PASSPHRASE=$2; shift 2 ;;
    --network-passphrase=*) NETWORK_PASSPHRASE=${1#--network-passphrase=}; shift ;;
    --source)               [ $# -ge 2 ] || { echo "e2e: --source needs a value" >&2; exit 2; }; SOURCE=$2; shift 2 ;;
    --source=*)             SOURCE=${1#--source=}; shift ;;
    --fixtures)             [ $# -ge 2 ] || { echo "e2e: --fixtures needs a value" >&2; exit 2; }; FIXTURES=$2; shift 2 ;;
    --fixtures=*)           FIXTURES=${1#--fixtures=}; shift ;;
    -h|--help)              usage; exit 0 ;;
    *) echo "e2e: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

fail() {
  echo "e2e: FAIL: $*" >&2
  exit 1
}

log() {
  printf 'e2e: %s\n' "$*"
}

# The test only ever talks to a network on this machine. A public endpoint
# would make it non-hermetic and could write real attestations, so it is a
# usage error rather than something a flag can quietly turn on.
case "$RPC_URL" in
  http://localhost:*|http://127.0.0.1:*|http://\[::1\]:*) ;;
  *) echo "e2e: refusing non-loopback RPC URL: $RPC_URL" >&2; exit 2 ;;
esac

for tool in go stellar python3 curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "e2e: $tool is required" >&2; exit 2; }
done

cd "$ROOT"

# Fail before spending a contract build on an unreachable network, and make the
# message name the thing the user forgot to start.
if ! curl -fsS --max-time 5 -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$RPC_URL" >/dev/null; then
  echo "e2e: no local Stellar RPC at $RPC_URL (start quickstart local first)" >&2
  exit 2
fi

TMP=$(mktemp -d)
cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT

NETWORK_ARGS=(--rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE")

log "building the fixture attestor and contracts"
go build -o "$TMP/attestfixture" ./cmd/attestfixture

mkdir -p "$TMP/wasm"
# Build from assay-contracts, not the repository root: rustup selects the
# toolchain from the working directory, and the pinned channel plus the
# wasm32v1-none target live in assay-contracts/rust-toolchain.toml.
(
  cd "$ROOT/assay-contracts"
  stellar contract build --manifest-path Cargo.toml \
    --package assay-safety-registry --out-dir "$TMP/wasm" >/dev/null
  stellar contract build --manifest-path Cargo.toml \
    --package assay-example-gate --out-dir "$TMP/wasm" >/dev/null
)

REGISTRY_WASM="$TMP/wasm/assay_safety_registry.wasm"
GATE_WASM="$TMP/wasm/assay_example_gate.wasm"
[ -f "$REGISTRY_WASM" ] || fail "contract build did not produce $REGISTRY_WASM"
[ -f "$GATE_WASM" ] || fail "contract build did not produce $GATE_WASM"

if ! stellar keys address "$SOURCE" >/dev/null 2>&1; then
  log "generating and funding source account $SOURCE"
  stellar keys generate "$SOURCE" "${NETWORK_ARGS[@]}" --fund
fi
ADMIN=$(stellar keys address "$SOURCE")

log "deploying the safety registry"
REGISTRY=$(stellar contract deploy --wasm "$REGISTRY_WASM" \
  --source-account "$SOURCE" "${NETWORK_ARGS[@]}")
stellar contract invoke --id "$REGISTRY" --source-account "$SOURCE" \
  "${NETWORK_ARGS[@]}" -- init --admin "$ADMIN" >/dev/null

# The gate's freshness policy is a real age window, not the registry helper's
# "0 disables the check": check_policy treats any attestation older than
# max_age_secs as stale, and an attestation submitted in an earlier ledger is
# already older than zero. One day matches the example's own default and keeps
# the assertions about how the gate decides, not about ledger timing.
log "deploying the example gate (max severity 2, refuse freeze and clawback)"
GATE=$(stellar contract deploy --wasm "$GATE_WASM" \
  --source-account "$SOURCE" "${NETWORK_ARGS[@]}" -- \
  --registry "$REGISTRY" --max_severity 2 --max_age_secs 86400 --refused_mechanics 6)

# invoke_read returns an invocation's value without submitting a transaction.
# Every read assertion below uses it, so no state changes while asserting.
invoke_read() {
  local id=$1
  shift
  stellar contract invoke --id "$id" --source-account "$SOURCE" \
    "${NETWORK_ARGS[@]}" --send=no -- "$@"
}

assert_bool() {
  local label=$1 got=$2 want=$3
  # Compare the value, not the CLI's quoting: a boolean may render as true or
  # "true" depending on the type spec.
  got=$(printf '%s' "$got" | tr -d '[:space:]"')
  [ "$got" = "$want" ] || fail "$label: got $got, want $want"
  log "ok: $label = $want"
}

expect_refusal() {
  local label=$1
  shift
  if "$@" >"$TMP/refusal.log" 2>&1; then
    fail "$label: the call succeeded, but the gate must refuse"
  fi
  log "ok: $label refused"
}

# assert_safety compares get_safety with the values attestfixture derived. The
# contract returns BytesN<32>, which the CLI may render as hex; the parser
# accepts hex or a byte array so this stays about the values, not formatting.
cat >"$TMP/check_safety.py" <<'PY'
import json
import sys

want_sev, want_flags, want_hash, sac = sys.argv[1:5]
safety = json.load(sys.stdin)
if safety is None:
    raise SystemExit(f"get_safety({sac}) = None; expected an attestation")

if int(safety["severity"]) != int(want_sev):
    raise SystemExit(f"get_safety({sac}).severity = {safety['severity']}, want {want_sev}")
if int(safety["flags"]) != int(want_flags):
    raise SystemExit(f"get_safety({sac}).flags = {safety['flags']}, want {want_flags}")

raw = safety["evidence_hash"]
if isinstance(raw, list):
    got = "".join(f"{int(b):02x}" for b in raw)
elif isinstance(raw, dict) and "data" in raw:
    got = "".join(f"{int(b):02x}" for b in raw["data"])
else:
    got = str(raw)
got = got.lower().removeprefix("0x")
if got != want_hash.lower():
    raise SystemExit(f"get_safety({sac}).evidence_hash = {got}, want {want_hash}")

if int(safety.get("attested_at", 0)) <= 0:
    raise SystemExit(f"get_safety({sac}).attested_at is not a ledger timestamp")
PY

assert_safety() {
  local sac=$1 want_sev=$2 want_flags=$3 want_hash=$4
  invoke_read "$REGISTRY" get_safety --asset "$sac" |
    python3 "$TMP/check_safety.py" "$want_sev" "$want_flags" "$want_hash" "$sac"
  log "ok: get_safety($sac) = severity $want_sev, flags $want_flags, matching evidence_hash"
}

# The three subjects the issue names, with the values pinned in
# cmd/attestfixture/main_test.go. The gate is expected to admit the clear asset
# and refuse both the high (freeze/clawback) and critical (reputation only)
# ones.
SUBJECTS=(
  "aqua-clear-verified:clear:0:0"
  "usdz-clawback-regulated:high:3:6"
  "doge-noflags-scam:critical:4:48"
)

declare -A SACS=()
for entry in "${SUBJECTS[@]}"; do
  IFS=: read -r subject label want_sev want_flags <<<"$entry"
  line=$("$TMP/attestfixture" -fixtures "$FIXTURES" -subject "$subject" \
    -network "$NETWORK_PASSPHRASE")
  IFS=$'\t' read -r asset got_sev got_flags evidence_hash <<<"$line"

  [ "$got_sev" = "$want_sev" ] ||
    fail "$subject: derived severity $got_sev, want $want_sev"
  [ "$got_flags" = "$want_flags" ] ||
    fail "$subject: derived flags $got_flags, want $want_flags"

  sac=$(stellar contract id asset --asset "${asset/-/:}" "${NETWORK_ARGS[@]}")
  SACS[$label]=$sac

  log "attesting $subject ($label) as severity $got_sev, flags $got_flags"
  stellar contract invoke --id "$REGISTRY" --source-account "$SOURCE" \
    "${NETWORK_ARGS[@]}" -- attest \
    --asset "$sac" --severity "$got_sev" --flags "$got_flags" \
    --evidence_hash "$evidence_hash" >/dev/null

  assert_safety "$sac" "$got_sev" "$got_flags" "$evidence_hash"
done

CLEAR=${SACS[clear]}
HIGH=${SACS[high]}
CRITICAL=${SACS[critical]}

# The registry's two gate helpers. is_safe_masked is deliberately blind to a
# reputation-only critical: masked over capability bits, DOGE has no forbidden
# bit. That is exactly why the example gate also checks the severity ceiling,
# and the deposit assertions below prove the ceiling is what refuses it.
assert_bool "is_safe_masked(clear, freeze+clawback)" \
  "$(invoke_read "$REGISTRY" is_safe_masked --asset "$CLEAR" --forbidden_mask 6 --max_age_secs 0)" true
assert_bool "is_safe_masked(high, freeze+clawback)" \
  "$(invoke_read "$REGISTRY" is_safe_masked --asset "$HIGH" --forbidden_mask 6 --max_age_secs 0)" false
assert_bool "is_safe_masked(critical reputation-only, freeze+clawback)" \
  "$(invoke_read "$REGISTRY" is_safe_masked --asset "$CRITICAL" --forbidden_mask 6 --max_age_secs 0)" true

assert_bool "is_safe(clear, max severity 2)" \
  "$(invoke_read "$REGISTRY" is_safe --asset "$CLEAR" --max_severity 2 --max_age_secs 0)" true
assert_bool "is_safe(high, max severity 2)" \
  "$(invoke_read "$REGISTRY" is_safe --asset "$HIGH" --max_severity 2 --max_age_secs 0)" false
assert_bool "is_safe(critical, max severity 2)" \
  "$(invoke_read "$REGISTRY" is_safe --asset "$CRITICAL" --max_severity 2 --max_age_secs 0)" false

# The end-to-end gate decision: would_admit plus one real admitted deposit and
# two refused deposits. A refusal is asserted from the CLI's exit status; the
# contract error itself is not parsed, because the point is that no path from
# these attestations reaches a credit.
assert_bool "gate.would_admit(clear)" \
  "$(invoke_read "$GATE" would_admit --asset "$CLEAR")" true
assert_bool "gate.would_admit(high)" \
  "$(invoke_read "$GATE" would_admit --asset "$HIGH")" false
assert_bool "gate.would_admit(critical)" \
  "$(invoke_read "$GATE" would_admit --asset "$CRITICAL")" false

log "submitting an admitted deposit for the clear asset"
stellar contract invoke --id "$GATE" --source-account "$SOURCE" \
  "${NETWORK_ARGS[@]}" -- deposit --asset "$CLEAR" --from "$ADMIN" --amount 100 >/dev/null
BALANCE=$(invoke_read "$GATE" balance --asset "$CLEAR" --holder "$ADMIN")
BALANCE=$(printf '%s' "$BALANCE" | tr -d '[:space:]"')
[ "$BALANCE" = "100" ] || fail "gate.balance(clear) = $BALANCE, want 100"
log "ok: gate.balance(clear) = 100"

expect_refusal "gate.deposit(high)" \
  stellar contract invoke --id "$GATE" --source-account "$SOURCE" \
    "${NETWORK_ARGS[@]}" --send=no -- deposit --asset "$HIGH" --from "$ADMIN" --amount 100
expect_refusal "gate.deposit(critical)" \
  stellar contract invoke --id "$GATE" --source-account "$SOURCE" \
    "${NETWORK_ARGS[@]}" --send=no -- deposit --asset "$CRITICAL" --from "$ADMIN" --amount 100

log "PASS: scan -> attest -> get_safety -> gate on the local network"
