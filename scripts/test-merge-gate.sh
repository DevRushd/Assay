#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
BASE=$(git -C "$ROOT" rev-parse --verify "${1:-HEAD}^{commit}")
TMPDIR=$(mktemp -d)
WORKTREE="$TMPDIR/worktree"

cleanup() {
    git -C "$ROOT" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

git -C "$ROOT" worktree add --quiet --detach "$WORKTREE" "$BASE"

# Keep this expected set independent of merge-gate.sh: if a protected path is
# accidentally removed there, the probe below must fail.
CRITICAL_PATHS=(
    "docs/severity-model.md"
    "internal/mechanics/severity.go"
    "internal/mechanics/mechanics.go"
    "internal/mechanics/check_capability.go"
    "internal/mechanics/check_reputation.go"
    "internal/mechanics/check_domain.go"
    "internal/mechanics/eval_test.go"
    "internal/mechanics/testdata"
    "internal/scan/scan.go"
    "internal/stellarexpert/client.go"
    "internal/horizon/client.go"
    "internal/sep1/sep1.go"
    "docs/contract-interface.md"
    "internal/attest/attest.go"
    "internal/mechanics/evidence.go"
    "assay-contracts/contracts/safety-registry/src/lib.rs"
    "assay-contracts/contracts/example-gate/src/lib.rs"
    "scripts/merge-gate.sh"
    ".github/workflows"
)

DEPENDENCY_PATHS=(
    "go.mod"
    "go.sum"
    "assay-contracts/Cargo.toml"
    "assay-contracts/Cargo.lock"
)

reset_worktree() {
    git -C "$WORKTREE" checkout --quiet --detach --force "$BASE"
    git -C "$WORKTREE" clean -fdqx
}

commit_probe() {
    local path=$1
    local probe="$WORKTREE/$path"

    if [[ -d "$probe" ]]; then
        probe="$probe/.merge-gate-probe"
    fi
    mkdir -p "$(dirname "$probe")"
    printf 'merge gate test probe\n' >> "$probe"
    git -C "$WORKTREE" add -- "$path"
    GIT_AUTHOR_NAME='Merge gate test' \
        GIT_AUTHOR_EMAIL='merge-gate-test@example.invalid' \
        GIT_COMMITTER_NAME='Merge gate test' \
        GIT_COMMITTER_EMAIL='merge-gate-test@example.invalid' \
        git -C "$WORKTREE" commit --quiet -m 'merge gate test probe'
}

check_result() {
    local name=$1
    local expected=$2
    shift 2
    local output rc

    set +e
    output=$("$ROOT/scripts/merge-gate.sh" "$@" 2>&1)
    rc=$?
    set -e

    if [[ "$rc" -ne "$expected" ]]; then
        printf 'FAIL: %s (expected exit %s, got %s)\n%s\n' \
            "$name" "$expected" "$rc" "$output" >&2
        return 1
    fi
    printf 'PASS: %s (exit %s)\n' "$name" "$rc"
}

run_probe_case() {
    local name=$1
    local expected=$2
    shift 2

    reset_worktree
    for path in "$@"; do
        commit_probe "$path"
    done
    local head
    head=$(git -C "$WORKTREE" rev-parse HEAD)
    check_result "$name" "$expected" "$BASE" "$head"
}

run_probe_case 'docs-only change passes' 0 'docs/merge-gate-probe.md'
run_probe_case 'test-only change passes' 0 'tests/merge-gate-probe_test.rs'

for path in "${CRITICAL_PATHS[@]}"; do
    run_probe_case "owned path holds: $path" 1 "$path"
done

for path in "${DEPENDENCY_PATHS[@]}"; do
    run_probe_case "dependency file holds: $path" 1 "$path"
done

run_probe_case 'mixed docs and owned path holds' 1 \
    'docs/merge-gate-probe.md' 'internal/mechanics/severity.go'

check_result 'bad usage is unknown' 2
check_result 'unresolvable ref is unknown' 2 "$BASE" \
    'merge-gate-test-ref-that-does-not-exist'