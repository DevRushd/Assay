#!/usr/bin/env bash
# Opens, updates, comments on, or closes the tracking issue for a failing
# scheduled workflow (issue #277).
#
# A red scheduled run that nobody sees is the same silence the scheduled jobs
# exist to end, one level up. This script is that escalation path, and it is
# deliberately small: it uses only `gh` and the workflow's GITHUB_TOKEN
# (issues: write), so no third-party action is added to the repository.
#
# One open issue per workflow, found by its exact title. A failure opens it or
# comments on it with the failing step's log and a link to the run. An
# inconclusive run (exit 2 from scripts/reproducibility.sh or
# scripts/check-deployment.sh) only comments: "could not check" is not a
# failure and must not open an issue, but it must not silently close one
# either. The next successful run comments and closes it.
#
# Usage:
#   notify-scheduled-failure.sh --workflow NAME \
#       --outcome failure|inconclusive|success --run-url URL \
#       [--step NAME] [--summary-file PATH]
#
#   --workflow NAME       workflow name as a human reads it ("Reproducibility")
#   --outcome OUTCOME     failure, inconclusive (exit 2), or success
#   --run-url URL         link to the run, from the workflow
#   --step NAME           the step that failed, named in the issue
#   --summary-file PATH   the captured step log to quote (truncated)
#
# Environment:
#   GITHUB_REPOSITORY  owner/repo; set by Actions
#   GH_TOKEN           the token gh authenticates with; the workflows pass
#                      ${{ github.token }}, which is the only credential used
#
# Exit status: 0 when the notification was performed (including the cases with
# nothing to do), 2 on usage errors, 1 when a gh call failed. A notification
# path that fails silently is the bug this script exists to prevent, so its
# own failures are loud.

set -u
set -o pipefail

WORKFLOW=""
OUTCOME=""
RUN_URL=""
STEP=""
SUMMARY=""
LABEL="scheduled-failure"

# GitHub's issue body limit is 65536 characters; a truncated log with a marker
# is more useful than a rejected create that notifies nobody.
SUMMARY_LIMIT=6000

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//' >&2
    echo "usage: $0 --workflow NAME --outcome failure|inconclusive|success --run-url URL [--step NAME] [--summary-file PATH]" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --workflow) WORKFLOW="${2:-}"; shift 2 ;;
        --outcome) OUTCOME="${2:-}"; shift 2 ;;
        --run-url) RUN_URL="${2:-}"; shift 2 ;;
        --step) STEP="${2:-}"; shift 2 ;;
        --summary-file) SUMMARY="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "notify-scheduled-failure: unknown argument $1" >&2; usage; exit 2 ;;
    esac
done

if [ -z "$WORKFLOW" ] || [ -z "$OUTCOME" ] || [ -z "$RUN_URL" ]; then
    echo "notify-scheduled-failure: --workflow, --outcome and --run-url are required" >&2
    usage
    exit 2
fi
case "$OUTCOME" in
    failure|inconclusive|success) ;;
    *) echo "notify-scheduled-failure: --outcome must be failure, inconclusive or success" >&2; exit 2 ;;
esac
if [ -z "${GITHUB_REPOSITORY:-}" ]; then
    echo "notify-scheduled-failure: GITHUB_REPOSITORY is not set" >&2
    exit 2
fi
if [ -n "$SUMMARY" ] && [ ! -f "$SUMMARY" ]; then
    echo "notify-scheduled-failure: --summary-file does not exist: $SUMMARY" >&2
    exit 2
fi
if ! command -v gh >/dev/null 2>&1; then
    echo "notify-scheduled-failure: gh is not on PATH" >&2
    exit 2
fi

REPO="$GITHUB_REPOSITORY"
TITLE="Scheduled workflow failure: $WORKFLOW"

run_gh() {
    if ! "$@"; then
        echo "notify-scheduled-failure: gh failed: $*" >&2
        exit 1
    fi
}

# The tracking issue carries a label so it can be found by people as well as by
# title. Label creation is best-effort: a token that cannot manage labels still
# opens the issue, just without one.
if ! gh label create "$LABEL" --repo "$REPO" --force \
        --color "b60205" \
        --description "Opened and closed automatically by a scheduled workflow run" >/dev/null 2>&1; then
    LABEL=""
fi

# The open tracking issues for this workflow, one number per line, oldest
# first. The search narrows, and the awk compares the whole title, so a
# differently-titled issue can never be mistaken for this workflow's tracker.
list_open_issues() {
    gh issue list --repo "$REPO" --state open --limit 100 \
        --search "in:title \"$TITLE\"" --json number,title \
        --template '{{range .}}{{.number}}{{"\t"}}{{.title}}{{"\n"}}{{end}}' 2>/dev/null \
        | awk -F'\t' -v want="$TITLE" '$2 == want { print $1 }'
}

summary_block() {
    if [ -n "$SUMMARY" ]; then
        head -c "$SUMMARY_LIMIT" "$SUMMARY"
        size=$(wc -c <"$SUMMARY" | tr -d ' ')
        if [ "$size" -gt "$SUMMARY_LIMIT" ]; then
            printf '\n… (%s bytes total; tail omitted)\n' "$size"
        fi
    else
        printf '(no step log was captured for this run)\n'
    fi
}

run_details() {
    printf -- '- Run: %s\n' "$RUN_URL"
    if [ -n "$STEP" ]; then
        printf -- '- Failing step: `%s`\n' "$STEP"
    fi
    printf '\nThe step log (truncated):\n\n'
    printf '```\n'
    summary_block
    printf '```\n'
}

if ! issues="$(list_open_issues)"; then
    echo "notify-scheduled-failure: could not list the open tracking issues; refusing to risk a duplicate" >&2
    exit 1
fi

# Exactly one open issue per workflow. If more than one exists, keep the
# oldest and close the rest rather than commenting on all of them.
existing=""
while IFS= read -r number; do
    [ -n "$number" ] || continue
    if [ -z "$existing" ]; then
        existing="$number"
    else
        echo "notify-scheduled-failure: closing duplicate tracking issue #$number"
        run_gh gh issue close "$number" --repo "$REPO" --reason "not planned" \
            --comment "Closing as a duplicate: #$existing is the single open tracking issue for this workflow."
    fi
done <<< "$issues"

body_file="$(mktemp)"
trap 'rm -f "$body_file"' EXIT

case "$OUTCOME" in
    failure)
        if [ -n "$existing" ]; then
            {
                printf 'Another scheduled run failed.\n\n'
                run_details
                printf '\n_Updated automatically by `scripts/notify-scheduled-failure.sh`._\n'
            } >"$body_file"
            run_gh gh issue comment "$existing" --repo "$REPO" --body-file "$body_file"
            echo "notify-scheduled-failure: updated issue #$existing for $WORKFLOW"
        else
            {
                printf 'A **scheduled** run of the %s workflow failed.\n\n' "$WORKFLOW"
                run_details
                printf '\n_Opened automatically by `scripts/notify-scheduled-failure.sh`; the next successful scheduled run closes it. It pages no one._\n'
            } >"$body_file"
            create_args=(issue create --repo "$REPO" --title "$TITLE" --body-file "$body_file")
            if [ -n "$LABEL" ]; then
                create_args+=(--label "$LABEL")
            fi
            run_gh gh "${create_args[@]}"
            echo "notify-scheduled-failure: opened the tracking issue for $WORKFLOW"
        fi
        ;;
    inconclusive)
        if [ -n "$existing" ]; then
            {
                printf 'A scheduled run was inconclusive (the check exited 2, so it could neither pass nor fail). This is not a failure and the issue stays open.\n\n'
                run_details
                printf '\n_Updated automatically by `scripts/notify-scheduled-failure.sh`._\n'
            } >"$body_file"
            run_gh gh issue comment "$existing" --repo "$REPO" --body-file "$body_file"
            echo "notify-scheduled-failure: commented on issue #$existing (inconclusive, still open)"
        else
            echo "notify-scheduled-failure: $WORKFLOW run was inconclusive and no tracking issue is open; nothing to do"
        fi
        ;;
    success)
        if [ -n "$existing" ]; then
            printf 'The scheduled run at %s passed. Closing this tracking issue.\n' "$RUN_URL" >"$body_file"
            run_gh gh issue comment "$existing" --repo "$REPO" --body-file "$body_file"
            run_gh gh issue close "$existing" --repo "$REPO" --reason completed
            echo "notify-scheduled-failure: closed issue #$existing; $WORKFLOW passed"
        else
            echo "notify-scheduled-failure: $WORKFLOW passed and no tracking issue is open; nothing to do"
        fi
        ;;
esac
