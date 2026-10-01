#!/usr/bin/env bash
# The Assay merge gate.
#
# Fails when a pull request touches a maintainer-owned safety-critical path or
# a dependency file, so branch protection can hold the PR for review instead of
# letting CI green-tick it through. A PR touching only other docs or tests
# passes; the eval tests and fixtures are owned because they pin judgment.
#
# This is a script rather than inline CI YAML so it can be verified offline
# against real commit ranges before it is trusted against a real PR:
#
#   scripts/merge-gate.sh BASE HEAD        # e.g. scripts/merge-gate.sh origin/main HEAD
#
# Exit codes: 0 the gate passes; 1 a maintainer-owned path or dependency file
# changed; 2 usage/argument error.

set -u

BASE=${1:-}
HEAD=${2:-}
if [ -z "$BASE" ] || [ -z "$HEAD" ]; then
    echo "usage: $0 BASE HEAD" >&2
    exit 2
fi
for rev in "$BASE" "$HEAD"; do
    if ! git rev-parse --verify --quiet "$rev^{commit}" >/dev/null; then
        echo "merge-gate: $rev is not a commit I can resolve" >&2
        exit 2
    fi
done

# Maintainer-owned paths. Changing any of these changes what an on-chain gate
# will admit or how a verdict is derived, so they are held for review rather
# than auto-merged. Each entry says why it is owned.
#
# A directory entry covers everything beneath it. The list was audited on
# 2026-09-17 by committing a probe change to each path and running this script:
# the severity code, the aggregation, the scanner's error handling, this script
# and the CI workflow all passed unreviewed before they were added here, and an
# entry for internal/mechanics/eval.go named a file that does not exist.
CRITICAL_PATHS=(
    # The severity model: the rules, and the code that implements them.
    "docs/severity-model.md"                                  # the severity rules; every downstream gate trusts them
    "internal/mechanics/severity.go"                          # severity levels and mechanic bit positions (contract ABI)
    "internal/mechanics/mechanics.go"                         # aggregation: base vs escalated severity, undetermined
    "internal/mechanics/check_capability.go"                  # the only check that sets base severity
    "internal/mechanics/check_reputation.go"                  # the only check that can raise severity
    "internal/mechanics/check_domain.go"                      # accountability and the domain_unverified bit
    "internal/mechanics/eval_test.go"                         # pins judgment to the labelled set
    "internal/mechanics/testdata"                             # the labelled fixtures themselves

    # What a verdict is derived from: a change here moves results without
    # touching the checks.
    "internal/scan/scan.go"                                   # which fetch failures are fatal vs recorded as undetermined
    "internal/stellarexpert/client.go"                        # listed vs not listed vs unreachable
    "internal/horizon/client.go"                              # the ledger flags every severity comes from
    "internal/sep1/sep1.go"                                   # what counts as a domain claiming an asset

    # evidence_hash: any change to these bytes breaks reproducibility of every
    # attestation already on-chain.
    "docs/contract-interface.md"                              # the documented ABI and evidence_hash encoding
    "internal/attest/attest.go"                               # computes evidence_hash
    "internal/mechanics/evidence.go"                          # text that enters hashed evidence claims

    # The contracts.
    "assay-contracts/contracts/safety-registry/src/lib.rs"    # the contract's fail-closed logic and ABI constants
    "assay-contracts/contracts/example-gate/src/lib.rs"       # the published integration example

    # The gate itself. A PR must not be able to weaken the check that reviews it.
    "scripts/merge-gate.sh"
    "scripts/check-codeowners.sh"                         # keeps GitHub review routing aligned with this list
    ".github/workflows"
)

# Dependency files. A new Go module or Rust crate is a decision, not a side
# effect: it adds supply-chain trust that the registry's threat model did not
# ask for. The invariant is "no third-party dependency without a maintainer
# deciding it is warranted", so dependency changes hold the gate too.
DEPS=(
    "go.mod"
    "go.sum"
    "assay-contracts/Cargo.toml"
    "assay-contracts/Cargo.lock"
)

path_changed() {
    # git diff --quiet exits 1 when there ARE differences.
    ! git diff --quiet "$BASE" "$HEAD" -- "$1"
}

HITS=()
for path in "${CRITICAL_PATHS[@]}"; do
    if path_changed "$path"; then
        HITS+=("$path")
    fi
done

DEPS_CHANGED=()
for path in "${DEPS[@]}"; do
    if path_changed "$path"; then
        DEPS_CHANGED+=("$path")
    fi
done

if [ ${#HITS[@]} -gt 0 ]; then
    echo "merge-gate: this PR touches maintainer-owned safety-critical paths and needs review before merge:"
    for path in "${HITS[@]}"; do
        echo "  $path"
    done
    echo
    echo "A maintainer should review the change before it merges. This is a flag,"
    echo "not a verdict: much of the backlog cannot be done without touching these"
    echo "paths. In CI the flag is advisory and does not fail the job; run locally"
    echo "it exits 1 so you can use it as a pre-flight check."
    exit 1
fi

if [ ${#DEPS_CHANGED[@]} -gt 0 ]; then
    echo "merge-gate: dependency files changed:"
    for path in "${DEPS_CHANGED[@]}"; do
        echo "  $path"
    done
    echo
    echo "A new third-party dependency (Go or Rust) needs a maintainer decision first:"
    echo "is it warranted, is it maintained, and does the registry's threat model"
    echo "inherit its trust? Hold for review like a maintainer-owned path."
    exit 1
fi

echo "merge-gate: no maintainer-owned paths and no dependency files touched."
echo
echo "The PR author confirms (the checklist is also in the PR template):"
echo "  [ ] No new third-party dependency was added."
echo "  [ ] No severity threshold moved without a reason traceable to the attestation run."
echo "  [ ] No verdict was published that the evidence does not support."
echo "  [ ] Tests pass locally: go test ./... && (cd assay-contracts && cargo test)"
exit 0
