#!/usr/bin/env bash
set -eu

cd "$(dirname "$0")/.."

gate_paths=$(awk '
    $0 == "CRITICAL_PATHS=(" { in_paths = 1; next }
    in_paths && $0 == ")" { exit }
    in_paths && $1 ~ /^".*"$/ {
        gsub(/^"|"$/, "", $1)
        print $1
    }
' scripts/merge-gate.sh)

codeowners_paths=$(awk '
    /^[[:space:]]*(#|$)/ { next }
    NF != 2 || $2 !~ /^@/ {
        printf "CODEOWNERS:%d: expected a path and @owner\n", NR > "/dev/stderr"
        invalid = 1
    }
    {
        path = $1
        sub(/^\/+/, "", path)
        print path
    }
    END { if (invalid) exit 1 }
' .github/CODEOWNERS)

if ! diff -u <(printf '%s\n' "$gate_paths") <(printf '%s\n' "$codeowners_paths"); then
    echo "CODEOWNERS paths do not match CRITICAL_PATHS in scripts/merge-gate.sh" >&2
    exit 1
fi

echo "CODEOWNERS paths match CRITICAL_PATHS in scripts/merge-gate.sh."