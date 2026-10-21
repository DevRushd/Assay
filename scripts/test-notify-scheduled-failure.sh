#!/usr/bin/env bash
# Tests for scripts/notify-scheduled-failure.sh: a failure opens (or updates)
# exactly one open issue per workflow, an inconclusive run only comments, and a
# success closes the issue. gh is a stub on PATH; nothing here talks to GitHub.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
NOTIFY="$ROOT/scripts/notify-scheduled-failure.sh"
TMPDIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

BIN="$TMPDIR/bin"
mkdir -p "$BIN"

cat >"$BIN/gh" <<'STUB'
#!/usr/bin/env bash
# Test double for gh: logs every call, serves `issue list` from
# $GH_STUB_ISSUES (lines of "number<TAB>title"), fails everything when
# $GH_STUB_FAIL is set, and stashes the file a --body-file points at so the
# test can inspect what would have been posted.
printf '%s\n' "$*" >>"$GH_STUB_LOG"
prev=""
for arg in "$@"; do
    if [[ "$prev" == "--body-file" ]]; then
        cp "$arg" "$GH_STUB_LOG.body"
    fi
    prev=$arg
done
if [[ -n "${GH_STUB_FAIL:-}" ]]; then
    echo "gh stub: forced failure" >&2
    exit 1
fi
if [[ "${1:-}" == "issue" && "${2:-}" == "list" ]]; then
    if [[ -n "${GH_STUB_ISSUES:-}" && -f "${GH_STUB_ISSUES:-}" ]]; then
        cat "$GH_STUB_ISSUES"
    fi
elif [[ "${1:-}" == "issue" && "${2:-}" == "create" ]]; then
    echo "https://github.com/example/repo/issues/101"
fi
STUB
chmod +x "$BIN/gh"

export PATH="$BIN:$PATH"
export GITHUB_REPOSITORY="example/repo"
export GH_STUB_LOG="$TMPDIR/calls.log"
ISSUES="$TMPDIR/issues.txt"
LOG="$TMPDIR/step.log"
printf 'exit 1: 3 attested assets drifted\n' >"$LOG"

WORKFLOW="Reproducibility"
TITLE="Scheduled workflow failure: Reproducibility"

reset_state() {
    : >"$GH_STUB_LOG"
    rm -f "$GH_STUB_LOG.body" "$ISSUES"
    unset GH_STUB_ISSUES GH_STUB_FAIL
}

open_issues() {
    printf '%s\n' "$@" >"$ISSUES"
    export GH_STUB_ISSUES="$ISSUES"
}

run_notify() {
    local name=$1
    local expected=$2
    shift 2
    local rc

    set +e
    "$NOTIFY" "$@" >"$TMPDIR/output" 2>&1
    rc=$?
    set -e

    if [[ "$rc" -ne "$expected" ]]; then
        printf 'FAIL: %s (expected exit %s, got %s)\n' "$name" "$expected" "$rc" >&2
        sed 's/^/    /' "$TMPDIR/output" >&2
        return 1
    fi
    printf 'PASS: %s\n' "$name"
}

assert_log() {
    local name=$1
    local pattern=$2

    if ! grep -q -- "$pattern" "$GH_STUB_LOG"; then
        printf 'FAIL: %s (no call matched %s)\n' "$name" "$pattern" >&2
        sed 's/^/    call: /' "$GH_STUB_LOG" >&2
        return 1
    fi
    printf 'PASS: %s\n' "$name"
}

refute_log() {
    local name=$1
    local pattern=$2

    if grep -q -- "$pattern" "$GH_STUB_LOG"; then
        printf 'FAIL: %s (unexpected call matched %s)\n' "$name" "$pattern" >&2
        sed 's/^/    call: /' "$GH_STUB_LOG" >&2
        return 1
    fi
    printf 'PASS: %s\n' "$name"
}

assert_body() {
    local name=$1
    local pattern=$2

    if ! [ -f "$GH_STUB_LOG.body" ] || ! grep -q -- "$pattern" "$GH_STUB_LOG.body"; then
        printf 'FAIL: %s (no body matched %s)\n' "$name" "$pattern" >&2
        [ -f "$GH_STUB_LOG.body" ] && sed 's/^/    body: /' "$GH_STUB_LOG.body" >&2
        return 1
    fi
    printf 'PASS: %s\n' "$name"
}

# Failure with nothing open: opens the tracking issue, labelled, quoting the
# failing step's log.
reset_state
run_notify 'failure opens a tracking issue' 0 \
    --workflow "$WORKFLOW" --outcome failure --run-url "https://example/run/1" \
    --step "recompute and compare" --summary-file "$LOG"
assert_log "the issue carries the workflow in its title" "issue create --repo example/repo --title $TITLE"
assert_log 'the issue is labelled for filtering' "--label scheduled-failure"
assert_body 'the body links the run' "https://example/run/1"
assert_body 'the body names the failing step' "recompute and compare"
assert_body 'the body quotes the step log' "3 attested assets drifted"

# Failure with an open issue (and an unrelated tracker): comments, never a
# second issue.
reset_state
open_issues $'42\tScheduled workflow failure: Reproducibility' \
    $'99\tScheduled workflow failure: Security'
run_notify 'a second failure comments on the open issue' 0 \
    --workflow "$WORKFLOW" --outcome failure --run-url "https://example/run/2" \
    --summary-file "$LOG"
assert_log 'the comment goes to issue 42' "issue comment 42 --repo example/repo"
assert_body 'the comment links the new run' "https://example/run/2"
refute_log 'no second issue is created' "issue create"
refute_log 'an unrelated issue is not commented' "comment 99"
refute_log 'an unrelated issue is not closed' "close 99"

# Inconclusive (exit 2) with nothing open: not a failure, opens nothing.
reset_state
run_notify 'inconclusive opens nothing' 0 \
    --workflow "$WORKFLOW" --outcome inconclusive --run-url "https://example/run/3" \
    --summary-file "$LOG"
refute_log 'inconclusive creates no issue' "issue create"
refute_log 'inconclusive comments nowhere' "issue comment"

# Inconclusive with an open issue: comments for the record and stays open.
reset_state
open_issues $'42\tScheduled workflow failure: Reproducibility'
run_notify 'inconclusive comments on the open issue' 0 \
    --workflow "$WORKFLOW" --outcome inconclusive --run-url "https://example/run/4" \
    --summary-file "$LOG"
assert_log 'the inconclusive note goes to issue 42' "issue comment 42 --repo example/repo"
assert_body 'the note says it could not check' "could neither pass nor fail"
refute_log 'the issue is not closed' "issue close"

# Success with an open issue: comments and closes.
reset_state
open_issues $'42\tScheduled workflow failure: Reproducibility'
run_notify 'success closes the tracking issue' 0 \
    --workflow "$WORKFLOW" --outcome success --run-url "https://example/run/5"
assert_log 'the close comment links the passing run' "issue comment 42 --repo example/repo"
assert_log 'the issue is closed' "issue close 42 --repo example/repo"
assert_body 'the close comment links the passing run' "https://example/run/5"

# Success with nothing open: no issue churn at all.
reset_state
run_notify 'success with nothing open is a no-op' 0 \
    --workflow "$WORKFLOW" --outcome success --run-url "https://example/run/6"
refute_log 'no issue is created' "issue create"
refute_log 'nothing is commented' "issue comment"
refute_log 'nothing is closed' "issue close"

# Duplicates: keep the oldest, close the rest, then update the survivor.
reset_state
open_issues $'42\tScheduled workflow failure: Reproducibility' \
    $'43\tScheduled workflow failure: Reproducibility'
run_notify 'duplicates are collapsed to one issue' 0 \
    --workflow "$WORKFLOW" --outcome failure --run-url "https://example/run/7" \
    --summary-file "$LOG"
assert_log 'the newest duplicate is closed' "issue close 43 --repo example/repo"
assert_log 'the survivor is updated' "issue comment 42 --repo example/repo"
refute_log 'still no third issue' "issue create"

# A listing failure must not guess: it refuses rather than risk a duplicate.
reset_state
export GH_STUB_FAIL=1
run_notify 'a failed issue list is fatal, not a duplicate' 1 \
    --workflow "$WORKFLOW" --outcome failure --run-url "https://example/run/8"
unset GH_STUB_FAIL
refute_log 'nothing was created after the listing failed' "issue create"

# Usage errors are exit 2, distinct from a real failure.
reset_state
run_notify 'a missing run URL is a usage error' 2 \
    --workflow "$WORKFLOW" --outcome failure
run_notify 'an unknown outcome is a usage error' 2 \
    --workflow "$WORKFLOW" --outcome maybe --run-url "https://example/run/9"
run_notify 'a missing summary file is a usage error' 2 \
    --workflow "$WORKFLOW" --outcome failure --run-url "https://example/run/9" \
    --summary-file "$TMPDIR/absent.log"

printf 'test-notify-scheduled-failure: all cases passed\n'
