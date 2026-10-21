#!/usr/bin/env bash
# Per-package Go coverage, as a Markdown table.
#
# Reads the output of `go test -cover ...` (the per-package "coverage: N% of
# statements" lines) and, optionally, a coverage profile for the total:
#
#   go test -coverprofile=coverage.out ./... | tee go-test.log
#   scripts/coverage-report.sh go-test.log coverage.out
#
# Packages are listed lowest coverage first, so the ones that need tests are at
# the top. A package with no test files is listed as such rather than dropped:
# a package nobody tests is the case this report exists to make visible.
#
# This reports; it does not gate. There is no threshold, and the exit code is 0
# whenever the input could be read. Exit 2 means the input was missing or held
# no package lines, so the report is unknown rather than empty.

set -euo pipefail

LOG=${1:-}
PROFILE=${2:-}
if [ -z "$LOG" ] || [ ! -r "$LOG" ]; then
    echo "usage: $0 GO_TEST_LOG [COVERAGE_PROFILE]" >&2
    exit 2
fi

# These line shapes carry a package:
#   ok  <pkg>  <time>  coverage: 55.1% of statements
#       <pkg>          coverage: 0.0% of statements      (no test files, Go >= 1.22)
#   ?   <pkg>  [no test files]                           (no statements at all)
#   FAIL <pkg>  <time>                                   (tests failed: no number)
rows=$(awk '
    /coverage: [0-9.]+% of statements/ {
        pkg = ""
        for (i = 1; i <= NF; i++) if ($i ~ /\//) { pkg = $i; break }
        for (i = 1; i <= NF; i++) if ($i == "coverage:") { pct = $(i + 1); break }
        sub(/%$/, "", pct)
        if (pkg != "") printf "%s\t%s\n", pct, pkg
        next
    }
    /^\?[ \t]/ && /\[no test files\]/ { printf "-\t%s\n", $2 }
    /^FAIL[ \t]/ && $2 ~ /\// { printf "!\t%s\n", $2 }
' "$LOG" | sort -t "$(printf '\t')" -k1,1n)

if [ -z "$rows" ]; then
    echo "coverage-report: no package coverage lines in $LOG" >&2
    exit 2
fi

echo "| Package | Coverage |"
echo "| --- | ---: |"
printf '%s\n' "$rows" | while IFS="$(printf '\t')" read -r pct pkg; do
    if [ "$pct" = "-" ]; then
        printf '| `%s` | no test files |\n' "$pkg"
    elif [ "$pct" = "!" ]; then
        printf '| `%s` | tests failed |\n' "$pkg"
    else
        printf '| `%s` | %s%% |\n' "$pkg" "$pct"
    fi
done

if [ -n "$PROFILE" ] && [ -r "$PROFILE" ]; then
    total=$(go tool cover -func="$PROFILE" | awk '/^total:/ { print $NF }')
    echo
    echo "**Total: ${total}** of statements."
fi
