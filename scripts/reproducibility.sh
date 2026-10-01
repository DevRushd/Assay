#!/usr/bin/env bash
# Cross-machine reproducibility check for Assay attestations.
#
# Recomputes the evidence_hash for every attested asset by scanning it live
# and diffs the result against the table in docs/deployment.md.
#
# Usage:
#   scripts/reproducibility.sh [--bin PATH] [--deployment PATH]
#                              [--attempts N] [--delay SECS]
#
#   --bin PATH         assay binary to run (default: $ASSAY_BIN or ./assay).
#                      The binary must support `attestation -raw CODE-ISSUER`.
#   --deployment PATH  markdown file holding the attested-assets table
#                      (default: docs/deployment.md relative to the repo root).
#   --attempts N       scan attempts per asset before giving up (default 3).
#                      Transient Horizon/DNS errors are common on rapid sweeps;
#                      a slower retry usually reproduces (see docs/attestation-run.md).
#   --delay SECS       seconds to wait between attempts (default 5).
#
# Source overrides (passed through to the assay binary, see internal/scan):
#   ASSAY_HORIZON_URL        override Horizon's base URL
#   ASSAY_STELLAREXPERT_URL  override StellarExpert's API root
# Pointing one at an unreachable address (e.g. http://127.0.0.1:1) forces the
# corresponding source to fail, which exercises the inconclusive path without
# editing code.
#
# Exit codes:
#   0  every asset reproduced (PASS).
#   1  at least one genuine mismatch (FAIL), or a script/usage error. Names
#      each mismatched asset with its expected and actual hashes.
#   2  no mismatches, but at least one scan could not complete (INCONCLUSIVE).
#      An undetermined scan — or any scan error, e.g. an upstream outage — is
#      never a pass and never a hard failure: there is nothing to compare, so
#      the job reports inconclusive rather than claiming reproducibility or a
#      reproducibility bug.
#
# The expected hashes in docs/deployment.md are truncated to
# `prefix…suffix` (8 + 6 hex chars) for readability. A fresh hash matches when
# it starts with the prefix and ends with the suffix (case-insensitive). A
# full 64-hex entry, if the table ever carries one, must match exactly.

set -u
set -o pipefail

BIN="${ASSAY_BIN:-./assay}"
DEPLOYMENT=""
ATTEMPTS=3
DELAY=5

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    sed -n '2,/^$/p' "$SCRIPT_DIR/reproducibility.sh" | sed 's/^# \{0,1\}//' >&2
    echo "usage: $0 [--bin PATH] [--deployment PATH] [--attempts N] [--delay SECS]" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN="${2:-}"; shift 2 ;;
        --deployment) DEPLOYMENT="${2:-}"; shift 2 ;;
        --attempts) ATTEMPTS="${2:-}"; shift 2 ;;
        --delay) DELAY="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "reproducibility: unknown argument $1" >&2; usage; exit 1 ;;
    esac
done

if [ -z "$DEPLOYMENT" ]; then
    DEPLOYMENT="$REPO_ROOT/docs/deployment.md"
fi

if ! [[ "$ATTEMPTS" =~ ^[0-9]+$ ]] || [ "$ATTEMPTS" -lt 1 ]; then
    echo "reproducibility: --attempts must be a positive integer" >&2
    exit 1
fi
if ! [[ "$DELAY" =~ ^[0-9]+$ ]]; then
    echo "reproducibility: --delay must be a non-negative integer" >&2
    exit 1
fi

if [ ! -x "$BIN" ] && ! command -v "$BIN" >/dev/null 2>&1; then
    # $BIN may be a relative path like ./assay from the repo root.
    if [ ! -x "$REPO_ROOT/$BIN" ] && [ ! -x "$BIN" ]; then
        echo "reproducibility: assay binary not found: $BIN (build with: go build -o assay ./cmd/assay)" >&2
        exit 1
    fi
fi
if [ ! -f "$DEPLOYMENT" ]; then
    echo "reproducibility: deployment file not found: $DEPLOYMENT" >&2
    exit 1
fi

# Parse docs/deployment.md for CODE-ISSUER + expected evidence_hash.
# The issuers table is the only one whose second column is a Stellar issuer
# (G...) and whose fourth column is a hash fragment. Emit TSV:
#   CODE-ISSUER<TAB>EXPECTED
ASSETS_TSV="$(python3 - "$DEPLOYMENT" <<'PY'
import re, sys
path = sys.argv[1]
issuer_re = re.compile(r'^G[A-Z2-7]{55}$')
rows = []
with open(path, encoding='utf-8') as f:
    for line in f:
        line = line.rstrip('\n')
        if not line.startswith('|'):
            continue
        cols = [c.strip().strip('`').strip() for c in line.strip().strip('|').split('|')]
        if len(cols) != 4:
            continue
        code, issuer, _sac, hashfrag = cols
        if not issuer_re.match(issuer):
            continue
        if not hashfrag or len(hashfrag) < 4:
            continue
        # Hash fragments are hex with an ellipsis, or full hex.
        frag = hashfrag.replace('`', '')
        if not re.search(r'[0-9a-fA-F]{4}', frag):
            continue
        rows.append(f"{code}-{issuer}\t{frag}")
for r in rows:
    print(r)
PY
)"
if [ -z "$ASSETS_TSV" ]; then
    echo "reproducibility: parsed 0 attested assets from $DEPLOYMENT; the table format may have changed" >&2
    exit 1
fi

N_ASSETS="$(printf '%s\n' "$ASSETS_TSV" | wc -l | tr -d ' ')"
echo "reproducibility: $N_ASSETS attested assets from $DEPLOYMENT" >&2
echo "reproducibility: binary $BIN, attempts $ATTEMPTS, delay ${DELAY}s" >&2

# hash_matches ACTUAL EXPECTED: exit 0 on match.
hash_matches() {
    python3 - "$1" "$2" <<'PY'
import sys
actual = sys.argv[1].strip().lower()
expected = sys.argv[2].strip().lower().strip('`')
# Normalise the three ellipsis spellings the docs use.
for sep in ('\u2026', '...', '..'):
    if sep in expected:
        prefix, _, suffix = expected.partition(sep)
        prefix, suffix = prefix.strip(), suffix.strip()
        sys.exit(0 if (actual.startswith(prefix) and actual.endswith(suffix)
                             and len(actual) >= len(prefix) + len(suffix)) else 1)
# No ellipsis: require an exact full-hash match.
sys.exit(0 if actual == expected else 1)
PY
}

pass_count=0
mismatch_count=0
inconclusive_count=0
mismatches=""
inconclusives=""

while IFS=$'\t' read -r asset expected; do
    [ -n "$asset" ] || continue
    echo "--- $asset (expected $expected)" >&2
    actual=""
    scan_err=""
    ok=0
    attempt=1
    while [ "$attempt" -le "$ATTEMPTS" ]; do
        errfile="$(mktemp)"
        # The assay CLI times out internally after 30s; `timeout` is a
        # backstop so one hung asset cannot stall the whole job.
        if command -v timeout >/dev/null 2>&1; then
            out="$(timeout 90 "$BIN" attestation -raw "$asset" 2>"$errfile")" && rc=0 || rc=$?
        else
            out="$("$BIN" attestation -raw "$asset" 2>"$errfile")" && rc=0 || rc=$?
        fi
        scan_err="$(head -c 500 "$errfile" | tr '\n' ' ')"
        rm -f "$errfile"
        if [ "$rc" -eq 0 ]; then
            # -raw prints: SEVERITY<TAB>FLAGS<TAB>HASH
            actual="$(printf '%s' "$out" | awk -F'\t' '{print $3}' | tr -d ' \r\n')"
            if [ -z "$actual" ]; then
                scan_err="empty output from assay attestation -raw"
                echo "  attempt $attempt/$ATTEMPTS: empty output, retrying" >&2
            else
                ok=1
                break
            fi
        else
            echo "  attempt $attempt/$ATTEMPTS failed (rc=$rc): $scan_err" >&2
        fi
        if [ "$attempt" -lt "$ATTEMPTS" ]; then
            sleep "$DELAY"
        fi
        attempt=$((attempt + 1))
    done

    if [ "$ok" -ne 1 ]; then
        inconclusive_count=$((inconclusive_count + 1))
        inconclusives="${inconclusives}${asset} :: ${scan_err:-scan failed}"$'\n'
        echo "INCONCLUSIVE $asset :: ${scan_err:-scan failed}"
        continue
    fi

    if hash_matches "$actual" "$expected"; then
        pass_count=$((pass_count + 1))
        echo "PASS $asset $actual"
    else
        mismatch_count=$((mismatch_count + 1))
        mismatches="${mismatches}${asset} expected $expected actual $actual"$'\n'
        echo "MISMATCH $asset expected $expected actual $actual"
    fi
done <<< "$ASSETS_TSV"

echo "" >&2
echo "reproducibility: $pass_count pass, $mismatch_count mismatch, $inconclusive_count inconclusive (of $N_ASSETS)" >&2

if [ "$mismatch_count" -gt 0 ]; then
    echo "" >&2
    echo "MISMATCHES (genuine reproducibility failures — asset and both hashes):" >&2
    printf '%s' "$mismatches" >&2
    echo "result: FAIL" >&2
    exit 1
fi

if [ "$inconclusive_count" -gt 0 ]; then
    echo "" >&2
    echo "INCONCLUSIVE assets (undetermined or unreachable — not failures, not passes):" >&2
    printf '%s' "$inconclusives" >&2
    echo "An upstream outage is not a reproducibility bug. Re-run when sources recover." >&2
    echo "result: INCONCLUSIVE" >&2
    exit 2
fi

echo "result: PASS — all $N_ASSETS evidence hashes reproduce" >&2
exit 0
