#!/usr/bin/env bash
# Verifies every live attestation end to end.
#
# Automates the verification procedure specified in docs/verifying.md:
# For each asset in the deployment table:
#   1. Derives the Stellar Asset Contract (SAC) address for the network
#   2. Reads the attestation record (severity, flags, evidence_hash) from the on-chain registry
#   3. Re-scans the asset live to verify the scan completed and is not undetermined
#   4. Recomputes the evidence_hash under the recorded preimage encoding version
#   5. Compares on-chain severity, flags, and evidence_hash against the live re-scanned values
#   6. Reports an unmistakable verdict per asset and a final run summary
#
# Crucially, the source of truth for verification is the CHAIN, not the markdown
# table. The deployment table is only used to know which assets and parameters
# to evaluate.
#
# Prerequisites:
#   - bash 4+
#   - python3 (with standard library urllib, json, base64)
#   - assay binary (built with `go build -o assay ./cmd/assay`)
#   - Optional: stellar/soroban CLI (if available, used for deriving SAC or reading contract;
#               otherwise transparently uses direct Soroban JSON-RPC calls)
#
# Configuration (via CLI flags or environment variables):
#   --bin PATH              Path to assay binary (default: $ASSAY_BIN or ./assay)
#   --stellar-bin PATH      Path to stellar/soroban CLI (default: $STELLAR_BIN, soroban, or stellar)
#   --deployment PATH       Path to deployment markdown table (default: $ASSAY_DEPLOYMENT or docs/deployment.md)
#   --rpc URL               Soroban JSON-RPC endpoint (default: $ASSAY_RPC_URL or https://soroban-testnet.stellar.org)
#   --network NAME          Stellar network name or passphrase (default: $ASSAY_NETWORK or testnet)
#   --contract ID           Registry contract address (default: $ASSAY_CONTRACT_ID or CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73)
#   --timeout SECS          Per-request network timeout (default: $ASSAY_TIMEOUT or 30)
#   --attempts N            Scan attempts per asset before concluding inconclusive (default: $ASSAY_ATTEMPTS or 3)
#   --delay SECS            Seconds between retries (default: $ASSAY_DELAY or 3)
#
# Outputs:
#   Outputs one line per asset:
#     <OUTCOME>  <ASSET>  <DETAIL>
#   where OUTCOME is one of:
#     VERIFIED      Chain data re-scanned and matches the on-chain registry value
#     MISMATCH      Chain data read successfully, but re-scanned values differ
#     INCONCLUSIVE  Could not complete the check (RPC failure, network timeout, scan undetermined, or missing registry entry)
#
# Exit codes:
#   0   All documented assets verified (PASS)
#   1   At least one mismatch found (takes priority over inconclusive)
#   2   No mismatches found, but at least one inconclusive
#   64  Bad command-line usage or configuration error
#
# Reference:
#   docs/verifying.md
#   docs/deployment.md
#   docs/contract-interface.md

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration and Defaults
# -----------------------------------------------------------------------------

BIN="${ASSAY_BIN:-./assay}"
STELLAR_CLI="${STELLAR_BIN:-}"
DEPLOYMENT="${ASSAY_DEPLOYMENT:-}"
RPC_URL="${ASSAY_RPC_URL:-https://soroban-testnet.stellar.org}"
NETWORK="${ASSAY_NETWORK:-testnet}"
CONTRACT_ID="${ASSAY_CONTRACT_ID:-CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73}"
TIMEOUT="${ASSAY_TIMEOUT:-30}"
ATTEMPTS="${ASSAY_ATTEMPTS:-3}"
DELAY="${ASSAY_DELAY:-3}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Temporary directory for scratch output, cleaned up on exit
TMP_DIR="$(mktemp -d)"
# shellcheck disable=SC2317 # Invoked indirectly via trap EXIT
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# -----------------------------------------------------------------------------
# Usage & Help
# -----------------------------------------------------------------------------

usage() {
    cat <<'EOF'
Usage: examples/verify-all.sh [OPTIONS]

Options:
  --bin PATH              Path to assay binary (default: $ASSAY_BIN or ./assay)
  --stellar-bin PATH      Path to stellar or soroban CLI (default: $STELLAR_BIN)
  --deployment PATH       Path to deployment.md (default: docs/deployment.md)
  --rpc URL               Soroban JSON-RPC URL (default: https://soroban-testnet.stellar.org)
  --network NAME          Stellar network (default: testnet)
  --contract ID           Safety registry contract ID
  --timeout SECS          Network timeout in seconds (default: 30)
  --attempts N            Scan attempts per asset (default: 3)
  --delay SECS            Delay between retries in seconds (default: 3)
  -h, --help              Show this help message and exit

Outcomes:
  VERIFIED                Recomputed scan matches live on-chain attestation
  MISMATCH                Scan succeeded but differs from on-chain attestation
  INCONCLUSIVE            Scan or chain read could not complete

Exit codes:
  0                       All assets verified
  1                       At least one mismatch found
  2                       No mismatches, but at least one inconclusive
  64                      Usage or configuration error
EOF
}

# -----------------------------------------------------------------------------
# Parse CLI arguments
# -----------------------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)
            [ $# -ge 2 ] || { echo "verify-all: --bin requires an argument" >&2; exit 64; }
            BIN="$2"; shift 2 ;;
        --stellar-bin)
            [ $# -ge 2 ] || { echo "verify-all: --stellar-bin requires an argument" >&2; exit 64; }
            STELLAR_CLI="$2"; shift 2 ;;
        --deployment)
            [ $# -ge 2 ] || { echo "verify-all: --deployment requires an argument" >&2; exit 64; }
            DEPLOYMENT="$2"; shift 2 ;;
        --rpc)
            [ $# -ge 2 ] || { echo "verify-all: --rpc requires an argument" >&2; exit 64; }
            RPC_URL="$2"; shift 2 ;;
        --network)
            [ $# -ge 2 ] || { echo "verify-all: --network requires an argument" >&2; exit 64; }
            NETWORK="$2"; shift 2 ;;
        --contract)
            [ $# -ge 2 ] || { echo "verify-all: --contract requires an argument" >&2; exit 64; }
            CONTRACT_ID="$2"; shift 2 ;;
        --timeout)
            [ $# -ge 2 ] || { echo "verify-all: --timeout requires an argument" >&2; exit 64; }
            TIMEOUT="$2"; shift 2 ;;
        --attempts)
            [ $# -ge 2 ] || { echo "verify-all: --attempts requires an argument" >&2; exit 64; }
            ATTEMPTS="$2"; shift 2 ;;
        --delay)
            [ $# -ge 2 ] || { echo "verify-all: --delay requires an argument" >&2; exit 64; }
            DELAY="$2"; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "verify-all: unknown option '$1'" >&2
            usage >&2
            exit 64 ;;
    esac
done

if [ -z "$DEPLOYMENT" ]; then
    DEPLOYMENT="$REPO_ROOT/docs/deployment.md"
fi

if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [ "$TIMEOUT" -lt 1 ]; then
    echo "verify-all: --timeout must be a positive integer" >&2
    exit 64
fi
if ! [[ "$ATTEMPTS" =~ ^[0-9]+$ ]] || [ "$ATTEMPTS" -lt 1 ]; then
    echo "verify-all: --attempts must be a positive integer" >&2
    exit 64
fi
if ! [[ "$DELAY" =~ ^[0-9]+$ ]]; then
    echo "verify-all: --delay must be a non-negative integer" >&2
    exit 64
fi

if [ ! -f "$DEPLOYMENT" ]; then
    echo "verify-all: deployment file not found: $DEPLOYMENT" >&2
    exit 64
fi

# Locate the assay binary (either as given, or relative to REPO_ROOT)
if [ ! -x "$BIN" ] && ! command -v "$BIN" >/dev/null 2>&1; then
    if [ -x "$REPO_ROOT/$BIN" ]; then
        BIN="$REPO_ROOT/$BIN"
    else
        echo "verify-all: assay binary not executable or found: $BIN" >&2
        echo "Build it with: go build -o assay ./cmd/assay" >&2
        exit 64
    fi
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "verify-all: python3 is required for table parsing and RPC encoding" >&2
    exit 64
fi

# Determine if a Stellar / Soroban CLI is available
find_stellar_cli() {
    if [ -n "$STELLAR_CLI" ]; then
        if [ -x "$STELLAR_CLI" ] || command -v "$STELLAR_CLI" >/dev/null 2>&1; then
            echo "$STELLAR_CLI"
            return 0
        fi
        echo ""
        return 0
    fi
    for candidate in soroban stellar /home/gamp/.local/bin/soroban; do
        if command -v "$candidate" >/dev/null 2>&1; then
            # Verify it's actually the Stellar CLI and not an unrelated tool (e.g. seqan stellar)
            if "$candidate" contract --help >/dev/null 2>&1; then
                echo "$candidate"
                return 0
            fi
        fi
    done
    echo ""
}
STELLAR_BIN="$(find_stellar_cli)"

# Color formatting if connected to a terminal and NO_COLOR is not set
USE_COLOR=0
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    USE_COLOR=1
fi

colorize() {
    local color="$1"
    local text="$2"
    if [ "$USE_COLOR" -eq 1 ]; then
        printf "\033[%sm%s\033[0m" "$color" "$text"
    else
        printf "%s" "$text"
    fi
}

# -----------------------------------------------------------------------------
# Step 1 Helper: Derive SAC address
# Reference: docs/verifying.md - Step 1: Derive the asset's SAC address
# -----------------------------------------------------------------------------

derive_sac() {
    local code="$1"
    local issuer="$2"
    local net="$3"

    if [ -n "$STELLAR_BIN" ]; then
        local out
        if out="$("$STELLAR_BIN" contract id asset --asset "${code}:${issuer}" --network "$net" 2>/dev/null)"; then
            local sac
            sac="$(printf '%s' "$out" | grep -E '^C[A-Z2-7]{55}' | head -n1 | tr -d ' \r\n')"
            if [ -n "$sac" ]; then
                printf '%s' "$sac"
                return 0
            fi
        fi
    fi

    # Fallback derivation using python if CLI is not present or failed
    python3 - "$code" "$issuer" "$net" <<'PY'
import hashlib, struct, sys, base64

code, issuer, net = sys.argv[1], sys.argv[2], sys.argv[3]

network_passphrases = {
    "testnet": "Test SDF Network ; September 2015",
    "pubnet": "Public Global Stellar Network ; September 2015",
    "public": "Public Global Stellar Network ; September 2015",
}
passphrase = network_passphrases.get(net.lower(), net)

def b32dec(s):
    return base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))

def b32enc(raw):
    return base64.b32encode(raw).decode().rstrip("=")

def crc16_xmodem(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

try:
    issuer_bytes = b32dec(issuer)[1:-2]
    net_id = hashlib.sha256(passphrase.encode("utf-8")).digest()

    code_bytes = code.encode("ascii")
    if len(code_bytes) <= 4:
        asset_type = 1
        asset_data = struct.pack(">4s", code_bytes) + issuer_bytes
    else:
        asset_type = 2
        asset_data = struct.pack(">12s", code_bytes) + issuer_bytes

    asset_xdr = struct.pack(">I", asset_type) + asset_data
    hasher = hashlib.sha256()
    hasher.update(net_id)
    hasher.update(struct.pack(">I", 0)) # EnvelopeTypeContractID
    hasher.update(struct.pack(">I", 1)) # ContractIDPreimageTypeAsset
    hasher.update(asset_xdr)
    contract_hash = hasher.digest()

    payload = bytes([16]) + contract_hash
    crc = crc16_xmodem(payload)
    sac = b32enc(payload + struct.pack("<H", crc))
    print(sac)
except Exception:
    sys.exit(1)
PY
}

# -----------------------------------------------------------------------------
# Step 2 Helper: Read registry from chain
# Reference: docs/verifying.md - Step 2: Read the attestation from the registry
# -----------------------------------------------------------------------------

read_registry() {
    local sac="$1"
    local contract="$2"
    local rpc="$3"
    local timeout="$4"

    # Python helper performs the getLedgerEntries query against the Soroban RPC.
    # Returns TSV on stdout: "SEVERITY\tFLAGS\tEVIDENCE_HASH\tATTESTED_AT"
    # Or exits 1 on RPC/network error, or prints "ABSENT" if entry is missing.
    python3 - "$rpc" "$timeout" "$contract" "$sac" <<'PY'
import base64, json, sys, urllib.request

RPC, TIMEOUT, CONTRACT, SAC = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

def u32(val): return val.to_bytes(4, "big")
def opaque(p): return u32(len(p)) + p + b"\x00" * ((-len(p)) % 4)
def contract_hash(addr):
    raw = base64.b32decode(addr + "=" * ((8 - len(addr) % 8) % 8))
    return raw[1:-2]

def scval_symbol(t): return u32(15) + opaque(t.encode())
def scval_contract_address(addr): return u32(18) + u32(1) + contract_hash(addr)
def scval_safety_key(sac_addr):
    return u32(16) + u32(1) + u32(2) + scval_symbol("Safety") + scval_contract_address(sac_addr)
def ledger_data_key(contract_addr, key_scval):
    return u32(6) + u32(1) + contract_hash(contract_addr) + key_scval + u32(1)

class Reader:
    def __init__(self, data): self.data, self.pos = data, 0
    def u32(self):
        v = int.from_bytes(self.data[self.pos:self.pos+4], "big")
        self.pos += 4
        return v
    def raw(self, n):
        v = self.data[self.pos:self.pos+n]
        self.pos += n
        return v
    def opaque(self):
        l = self.u32()
        return self.raw((l + 3) // 4 * 4)[:l]

def read_sc_address(r):
    tag = r.u32()
    if tag == 1: return ("contract", r.raw(32))
    if tag == 0:
        r.u32()
        return ("account", r.raw(32))
    if tag in (36, 40): return read_sc_address(Reader(r.raw(tag)))
    raise ValueError(f"tag {tag}")

def read_scval(r):
    kind = r.u32()
    if kind == 3: return {"u32": r.u32()}
    if kind == 5: return {"u64": int.from_bytes(r.raw(8), "big")}
    if kind == 13: return {"bytes": r.opaque().hex()}
    if kind == 15: return {"symbol": r.opaque().decode("utf-8", "replace")}
    if kind == 18: return {"address": read_sc_address(r)}
    if kind in (16, 17):
        if r.u32() == 0: return {"vec" if kind == 16 else "map": None}
        c = r.u32()
        if kind == 16: return {"vec": [read_scval(r) for _ in range(c)]}
        return {"map": [(read_scval(r), read_scval(r)) for _ in range(c)]}
    raise ValueError(f"kind {kind}")

def read_contract_data_entry(xdr_b64):
    r = Reader(base64.b64decode(xdr_b64))
    if r.u32() != 6: return None
    r.u32()
    read_sc_address(r)
    read_scval(r)
    r.u32()
    return read_scval(r)

try:
    key_bytes = ledger_data_key(CONTRACT, scval_safety_key(SAC))
    key_b64 = base64.b64encode(key_bytes).decode()
    body = json.dumps({"jsonrpc":"2.0", "id":1, "method":"getLedgerEntries", "params":{"keys":[key_b64]}}).encode()
    req = urllib.request.Request(RPC, data=body, headers={
        "Content-Type": "application/json",
        "User-Agent": "assay-verify-all (+https://github.com/use-assay/Assay)",
    })
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        res = json.loads(resp.read().decode())
    if "error" in res:
        print(f"ERROR: {res['error']}", file=sys.stderr)
        sys.exit(1)

    entries = res.get("result", {}).get("entries", [])
    if not entries:
        print("ABSENT")
        sys.exit(0)

    val = read_contract_data_entry(entries[0]["xdr"])
    stored = {k.get("symbol"): v for k, v in (val.get("map") or [])}
    sev = stored.get("severity", {}).get("u32")
    flags = stored.get("flags", {}).get("u32")
    ev = stored.get("evidence_hash", {}).get("bytes")
    att_at = stored.get("attested_at", {}).get("u64", 0)

    if sev is None or ev is None:
        print("ABSENT")
    else:
        print(f"{sev}\t{flags}\t{ev}\t{att_at}")
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
PY
}

# -----------------------------------------------------------------------------
# Parse Deployment Table
# Reference: docs/deployment.md
# Extracts: CODE, ISSUER, DOC_SAC, DOC_VERSION
# -----------------------------------------------------------------------------

parse_deployment_table() {
    local table_file="$1"
    python3 - "$table_file" <<'PY'
import re, sys
path = sys.argv[1]
issuer_re = re.compile(r'^G[A-Z2-7]{55}$')
versions = ("v1", "v2", "v3")
rows = []
with open(path, encoding='utf-8') as f:
    for line in f:
        line = line.rstrip('\n')
        if not line.startswith('|'):
            continue
        cols = [c.strip().strip('`').strip() for c in line.strip().strip('|').split('|')]
        if len(cols) < 4:
            continue
        code, issuer, sac, hashfrag = cols[:4]
        if not issuer_re.match(issuer):
            continue
        version = cols[4] if len(cols) > 4 else "v1"
        if version not in versions:
            print(f"verify-all: invalid preimage version '{version}' for {code}", file=sys.stderr)
            sys.exit(64)
        rows.append(f"{code}\t{issuer}\t{sac}\t{version}")

for r in rows:
    print(r)
PY
}

# -----------------------------------------------------------------------------
# Verify Asset Implementation
# -----------------------------------------------------------------------------

# Summary counters
COUNT_VERIFIED=0
COUNT_MISMATCH=0
COUNT_INCONCLUSIVE=0

verify_asset() {
    local code="$1"
    local issuer="$2"
    local doc_sac="$3"
    local version="$4"
    local asset_tag="${code}-${issuer}"

    # Step 1: Derive SAC address
    local derived_sac
    if ! derived_sac="$(derive_sac "$code" "$issuer" "$NETWORK")" || [ -z "$derived_sac" ]; then
        COUNT_INCONCLUSIVE=$((COUNT_INCONCLUSIVE + 1))
        printf "%-14s %-20s %s\n" \
            "$(colorize "33;1" "INCONCLUSIVE")" \
            "$code" \
            "could not derive SAC address for $NETWORK"
        return 0
    fi

    # Step 2: Read attestation from the registry
    local chain_data chain_rc=0
    chain_data="$(read_registry "$derived_sac" "$CONTRACT_ID" "$RPC_URL" "$TIMEOUT" 2>"$TMP_DIR/rpc_err.txt")" || chain_rc=$?

    if [ "$chain_rc" -ne 0 ]; then
        local rpc_err
        rpc_err="$(head -n 1 "$TMP_DIR/rpc_err.txt" | tr '\n' ' ')"
        COUNT_INCONCLUSIVE=$((COUNT_INCONCLUSIVE + 1))
        printf "%-14s %-20s %s\n" \
            "$(colorize "33;1" "INCONCLUSIVE")" \
            "$code" \
            "registry read failed: ${rpc_err:-RPC error}"
        return 0
    fi

    if [ "$chain_data" = "ABSENT" ] || [ -z "$chain_data" ]; then
        COUNT_INCONCLUSIVE=$((COUNT_INCONCLUSIVE + 1))
        printf "%-14s %-20s %s\n" \
            "$(colorize "33;1" "INCONCLUSIVE")" \
            "$code" \
            "no attestation entry on chain for $derived_sac"
        return 0
    fi

    local chain_sev chain_flags chain_hash chain_att_at
    chain_sev="$(printf '%s' "$chain_data" | cut -f1)"
    chain_flags="$(printf '%s' "$chain_data" | cut -f2)"
    chain_hash="$(printf '%s' "$chain_data" | cut -f3 | tr '[:upper:]' '[:lower:]')"
    chain_att_at="$(printf '%s' "$chain_data" | cut -f4)"

    # Steps 3 & 4: Re-scan the asset and recompute the hash
    local scan_ok=0
    local scan_output=""
    local scan_err=""
    local attempt=1

    while [ "$attempt" -le "$ATTEMPTS" ]; do
        local err_file="$TMP_DIR/scan_err_${attempt}.txt"
        local cmd_rc=0
        if command -v timeout >/dev/null 2>&1; then
            scan_output="$(timeout "$((TIMEOUT * 2))" "$BIN" attestation -raw -preimage-version "$version" "$asset_tag" 2>"$err_file")" || cmd_rc=$?
        else
            scan_output="$("$BIN" attestation -raw -preimage-version "$version" "$asset_tag" 2>"$err_file")" || cmd_rc=$?
        fi
        scan_err="$(head -c 200 "$err_file" | tr '\n' ' ')"
        rm -f "$err_file"

        if [ "$cmd_rc" -eq 0 ] && [ -n "$scan_output" ]; then
            scan_ok=1
            break
        fi

        if [ "$attempt" -lt "$ATTEMPTS" ]; then
            sleep "$DELAY"
        fi
        attempt=$((attempt + 1))
    done

    if [ "$scan_ok" -ne 1 ]; then
        COUNT_INCONCLUSIVE=$((COUNT_INCONCLUSIVE + 1))
        printf "%-14s %-20s %s\n" \
            "$(colorize "33;1" "INCONCLUSIVE")" \
            "$code" \
            "re-scan undetermined or failed: ${scan_err:-upstream scan error}"
        return 0
    fi

    # Parse re-scanned parameters
    local scan_sev scan_flags scan_hash
    scan_sev="$(printf '%s' "$scan_output" | cut -f1)"
    scan_flags="$(printf '%s' "$scan_output" | cut -f2)"
    scan_hash="$(printf '%s' "$scan_output" | cut -f3 | tr '[:upper:]' '[:lower:]')"

    # Step 5: Compare live chain vs re-scan
    local diffs=()
    if [ "$scan_sev" != "$chain_sev" ]; then
        diffs+=("severity chain=$chain_sev scan=$scan_sev")
    fi
    if [ "$scan_flags" != "$chain_flags" ]; then
        diffs+=("flags chain=$chain_flags scan=$scan_flags")
    fi
    if [ "$scan_hash" != "$chain_hash" ]; then
        diffs+=("hash chain=${chain_hash:0:12}… scan=${scan_hash:0:12}…")
    fi

    # Step 6: Interpret and report verdict
    if [ ${#diffs[@]} -eq 0 ]; then
        COUNT_VERIFIED=$((COUNT_VERIFIED + 1))
        printf "%-14s %-20s %s\n" \
            "$(colorize "32;1" "VERIFIED")" \
            "$code" \
            "severity=$chain_sev flags=$chain_flags hash=${chain_hash:0:12}… (attested_at=$chain_att_at)"
    else
        COUNT_MISMATCH=$((COUNT_MISMATCH + 1))
        local diff_msg
        diff_msg="$(IFS=, ; echo "${diffs[*]}")"
        printf "%-14s %-20s %s\n" \
            "$(colorize "31;1" "MISMATCH")" \
            "$code" \
            "$diff_msg"
    fi
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

main() {
    local assets_tsv
    if ! assets_tsv="$(parse_deployment_table "$DEPLOYMENT")"; then
        echo "verify-all: failed to parse deployment table from $DEPLOYMENT" >&2
        exit 64
    fi

    local total_assets
    total_assets="$(printf '%s\n' "$assets_tsv" | grep -c . || true)"
    if [ "$total_assets" -eq 0 ]; then
        echo "verify-all: 0 assets found in $DEPLOYMENT" >&2
        exit 64
    fi

    echo "Assay Attestation Verification (procedure: docs/verifying.md)"
    echo "Registry:   $CONTRACT_ID ($NETWORK)"
    echo "RPC:        $RPC_URL"
    echo "Deployment: $DEPLOYMENT ($total_assets assets)"
    echo ""

    while IFS=$'\t' read -r code issuer doc_sac version; do
        [ -n "$code" ] || continue
        verify_asset "$code" "$issuer" "$doc_sac" "$version"
    done <<< "$assets_tsv"

    echo ""
    echo "Summary:"
    echo "  Total:        $total_assets"
    echo "  Verified:     $COUNT_VERIFIED"
    echo "  Mismatch:     $COUNT_MISMATCH"
    echo "  Inconclusive: $COUNT_INCONCLUSIVE"
    echo ""

    # Exit code precedence:
    # 0 = all verified
    # 1 = at least one mismatch (mismatch takes priority)
    # 2 = no mismatches but at least one inconclusive
    if [ "$COUNT_MISMATCH" -gt 0 ]; then
        echo "Result: MISMATCH (exit 1)"
        exit 1
    elif [ "$COUNT_INCONCLUSIVE" -gt 0 ]; then
        echo "Result: INCONCLUSIVE (exit 2)"
        exit 2
    else
        echo "Result: ALL VERIFIED (exit 0)"
        exit 0
    fi
}

main
