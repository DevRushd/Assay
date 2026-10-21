#!/usr/bin/env bash
# Verifies the wasm built from committed source in assay-contracts/ against
# the hashes recorded in docs/deployment.md.
#
# docs/deployment.md records what is deployed. Whether the committed source
# still produces those bytes is a separate question, and until it is answered
# the recorded hashes are a claim nobody has checked. This builds each
# contract from the committed source and compares.
#
# It never edits docs/deployment.md, never redeploys, and never rewrites a
# recorded hash. It reports.
#
# Usage:
#   scripts/verify-wasm-source.sh [--out-dir DIR] [--skip-build]
#
#   --out-dir DIR  where the built wasm is written. Defaults to a temporary
#                  directory that is removed on exit. The repository's
#                  assay-contracts/out/ is never written to, so a run cannot
#                  clobber the artifact a deploy would upload.
#   --skip-build   compare only the toolchain preconditions. Always exits 2
#                  unless the toolchain is pinned; useful for asking "could
#                  this be verified at all?" without paying for a build.
#
# Recorded toolchain (docs/deployment.md "Built with", CONTRIBUTING.md
# "Contract toolchain"):
#   stellar CLI 27.1.0, Rust target wasm32v1-none, soroban-sdk 27.0.5.
#
# Outcomes, one per contract:
#   verified      the freshly built wasm hashes to the recorded value.
#   mismatch      it does not. Both values are printed. Never tolerated.
#   unpinned      assay-contracts/rust-toolchain.toml does not exist, so
#                 "the source" does not determine the bytes: rustup picks
#                 whatever channel is installed. A match here would be luck
#                 and a mismatch would be meaningless, so neither is a
#                 verification. Measured: two rustc channels produce two
#                 different hashes from this same source and this same
#                 stellar CLI. See docs/deployment.md.
#   unverifiable  the stellar CLI is missing, or is not the recorded version,
#                 or the build failed. The build is not the recorded build.
#
# Exit codes:
#   0  every contract verified.
#   1  at least one mismatch.
#   2  the question could not be answered: any contract unpinned or
#      unverifiable, or the recorded hashes could not be read out of the
#      document. Exit 2 never means "verified" and never means "safe"; it
#      means this run could not tell. A run with any unpinned or
#      unverifiable contract therefore never exits 0, the same rule
#      scripts/reproducibility.sh and scripts/check-deployment.sh follow.
#
# Scope: this asks whether committed source produces the deployed bytes. It
# does not ask whether the deployed bytes are correct, whether the contract
# is safe, or whether the registry holds the attestations the document
# claims - the last of those is scripts/check-deployment.sh, which compares
# the document against the chain rather than against this repository.
set -u
set -o pipefail

usage() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

OUT_DIR=""
SKIP_BUILD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --out-dir)
      [ $# -ge 2 ] || { echo "verify-wasm-source: --out-dir needs a value" >&2; exit 2; }
      OUT_DIR=$2
      shift 2
      ;;
    --out-dir=*)
      OUT_DIR=${1#--out-dir=}
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "verify-wasm-source: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

cd "$REPO_ROOT" || exit 2

CONTRACTS_DIR=assay-contracts
MANIFEST="$CONTRACTS_DIR/Cargo.toml"
DOC=docs/deployment.md
PIN="$CONTRACTS_DIR/rust-toolchain.toml"
# The stellar CLI version docs/deployment.md records for the deployment. A
# different CLI runs a different wasm optimizer, so its output is not
# comparable to the recorded hash and must not be reported as a mismatch.
RECORDED_STELLAR=27.1.0

for f in "$MANIFEST" "$DOC"; do
  if [ ! -f "$f" ]; then
    echo "verify-wasm-source: $f not found; run from a checkout of the repository" >&2
    exit 2
  fi
done

# The build is a side effect, so keep it out of the tree by default.
TEMP_DIR=""
cleanup() {
  [ -n "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

if [ -z "$OUT_DIR" ]; then
  TEMP_DIR=$(mktemp -d)
  OUT_DIR=$TEMP_DIR
fi
mkdir -p "$OUT_DIR"

python3 - "$DOC" "$CONTRACTS_DIR" "$OUT_DIR" "$SKIP_BUILD" "$RECORDED_STELLAR" "$PIN" <<'PY'
import hashlib
import os
import re
import subprocess
import sys

doc_path, contracts_dir, out_dir, skip_build, recorded_stellar, pin_path = sys.argv[1:7]
skip_build = skip_build == "1"


def fail(msg, code=2):
    sys.stderr.write("verify-wasm-source: %s\n" % msg)
    raise SystemExit(code)


# --- what the document says ------------------------------------------------
#
# docs/deployment.md is the record, and the recorded hashes live in its tables
# rather than in a machine-readable block. If that stops being parseable the
# honest answer is "could not read the record", never "no drift".

with open(doc_path, encoding="utf-8") as fh:
    lines = fh.read().splitlines()

HEX8 = re.compile(r"\b[0-9a-f]{8,64}\b")
# A strkey contract address, as it appears in a table cell.
ADDR = re.compile(r"^`?C[A-Z2-7]{20,}`?$")


def cells(line):
    line = line.strip()
    if not line.startswith("|"):
        return None
    return [c.strip() for c in line.strip("|").split("|")]


def backticked_hex(cell):
    # The document truncates some hashes with a trailing ellipsis inside the
    # backticks (`` `ca40172e…` ``), so the closing backtick is not what ends
    # the hex run. Take the leading hex characters and ignore the rest.
    m = re.search(r"`([0-9a-f]{8,64})[^`]*`", cell)
    return m.group(1) if m else None


registry_hash = None      # safety-registry, from the registry table
gate_hash = None          # example-gate, from the gate table
instances = []            # (address, recorded wasm hash) from the instances table
recorded_cli = None       # the "Built with" row

context = None
for line in lines:
    row = cells(line)
    if row is None:
        context = None
        continue
    if not row:
        continue

    head = row[0]
    # A bolded contract row opens the table that names it.
    if head == "**Registry contract**":
        context = "registry"
        continue
    if head == "**Example gate contract**":
        context = "gate"
        continue
    if head == "Instance" and len(row) > 1 and row[1] == "Status":
        context = "instances"
        continue

    if head == "Built with" and len(row) > 1:
        m = re.search(r"stellar[` ]*CLI\s+([0-9]+\.[0-9]+\.[0-9]+)", row[1])
        if m:
            recorded_cli = m.group(1)
        continue

    if context in ("registry", "gate") and head == "Wasm hash" and len(row) > 1:
        h = backticked_hex(row[1])
        if h:
            if context == "registry":
                registry_hash = h
            else:
                gate_hash = h
        continue

    if context == "instances" and len(row) >= 3 and ADDR.match(head):
        h = backticked_hex(row[2])
        if h:
            instances.append((head.strip("`"), h))

if not registry_hash or not gate_hash:
    fail("could not read the recorded wasm hashes out of %s; the tables it "
         "parses must have changed" % doc_path)
if not instances:
    fail("could not read the gate instance table out of %s" % doc_path)

# The recorded CLI version in the document and the one this script is written
# against must agree, or the comparison below would be against the wrong
# optimizer.
if recorded_cli and recorded_cli != recorded_stellar:
    fail("%s records stellar CLI %s but this script compares against %s; the "
         "recorded build is not the build being performed"
         % (doc_path, recorded_cli, recorded_stellar))

# --- what is in the repository ---------------------------------------------

expected = {
    "assay-safety-registry": registry_hash,
    "assay-example-gate": gate_hash,
}

packages = []
contracts_root = os.path.join(contracts_dir, "contracts")
for entry in sorted(os.listdir(contracts_root)):
    manifest = os.path.join(contracts_root, entry, "Cargo.toml")
    if not os.path.isfile(manifest):
        continue
    with open(manifest, encoding="utf-8") as fh:
        text = fh.read()
    m = re.search(r'^name\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        fail("no package name in %s" % manifest)
    packages.append(m.group(1))

if not packages:
    fail("no contract packages found under %s" % contracts_root)

unrecorded = [p for p in packages if p not in expected]
if unrecorded:
    # A new contract with nothing recorded against it must be reported, not
    # skipped: skipping is how a deployment goes undocumented.
    fail("contract(s) %s have no recorded wasm hash in %s; record them there "
         "before this can verify them"
         % (", ".join(unrecorded), doc_path))

# --- toolchain preconditions -----------------------------------------------

pinned = os.path.isfile(pin_path)

stellar = None
try:
    stellar = subprocess.run(
        ["stellar", "--version"],
        capture_output=True, text=True, timeout=60, check=False,
    ).stdout.strip().splitlines()[0]
except (OSError, subprocess.SubprocessError, IndexError):
    stellar = None

stellar_ok = stellar is not None and re.search(
    r"\b%s\b" % re.escape(recorded_stellar), stellar
) is not None

rustc = None
for tool in ("rustc",):
    try:
        rustc = subprocess.run(
            [tool, "--version"], capture_output=True, text=True,
            timeout=60, check=False,
        ).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        rustc = None

env_report = [
    "toolchain",
    "  stellar   %s (recorded %s)" % (stellar or "not installed", recorded_stellar),
    "  rustc     %s" % (rustc or "not installed"),
    "  pin       %s" % (pin_path if pinned else
                        "%s MISSING (see #127)" % pin_path),
]

# --- build and compare ------------------------------------------------------

def manifest_of(contracts_dir, pkg):
    for entry in sorted(os.listdir(os.path.join(contracts_dir, "contracts"))):
        path = os.path.join(contracts_dir, "contracts", entry, "Cargo.toml")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            m = re.search(r'^name\s*=\s*"([^"]+)"', fh.read(), re.M)
        if m and m.group(1) == pkg:
            return path
    fail("no manifest for %s" % pkg)


def find_wasm(directory):
    for root, _dirs, files in os.walk(directory):
        for name in sorted(files):
            if name.endswith(".wasm"):
                return os.path.join(root, name)
    return None


results = []  # (outcome, label, detail)

for pkg in packages:
    recorded = expected[pkg]

    if not pinned:
        results.append(("unpinned", pkg,
                        "recorded %s; no %s, so this build cannot be "
                        "compared" % (recorded, os.path.basename(pin_path))))
        continue
    if not stellar_ok:
        results.append(("unverifiable", pkg,
                        "recorded %s; the stellar CLI in use is not %s, so "
                        "this would not be the recorded build"
                        % (recorded, recorded_stellar)))
        continue
    if skip_build:
        results.append(("unverifiable", pkg, "recorded %s; --skip-build" % recorded))
        continue

    pkg_dir = os.path.join(out_dir, pkg)
    os.makedirs(pkg_dir, exist_ok=True)
    proc = subprocess.run(
        ["stellar", "contract", "build",
         "--manifest-path", manifest_of(contracts_dir, pkg),
         "--package", pkg, "--out-dir", pkg_dir],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        results.append(("unverifiable", pkg,
                        "recorded %s; build failed: %s"
                        % (recorded, (proc.stderr or proc.stdout).strip().splitlines()[-1:])))
        continue

    wasm = find_wasm(pkg_dir)
    if wasm is None:
        results.append(("unverifiable", pkg,
                        "recorded %s; build produced no .wasm in %s" % (recorded, pkg_dir)))
        continue

    with open(wasm, "rb") as fh:
        built = hashlib.sha256(fh.read()).hexdigest()

    # A documented hash may be a truncated prefix (the gate instance table
    # records 8 characters). Compare at the length the document actually
    # recorded, and say so, rather than silently padding either side.
    if len(recorded) < 64:
        if built.startswith(recorded):
            results.append(("verified", pkg,
                            "recorded %s…, built %s (prefix match over the %d "
                            "characters the document records)"
                            % (recorded, built, len(recorded))))
        else:
            results.append(("mismatch", pkg,
                            "recorded %s…; built %s" % (recorded, built)))
    elif built == recorded:
        results.append(("verified", pkg, built))
    else:
        results.append(("mismatch", pkg,
                        "recorded %s; built %s" % (recorded, built)))


# --- report -----------------------------------------------------------------

for line in env_report:
    print(line)

print()
print("recorded deployments")
for addr, h in instances:
    print("  %s  %s…" % (addr, h))
print("  (safety-registry)  %s" % registry_hash)
print("  (example-gate)     %s" % gate_hash)
print()

width = max(len(label) for _o, label, _d in results)
for outcome, label, detail in results:
    print("%-11s %-*s %s" % (outcome, width, label, detail))

counts = {o: 0 for o in ("verified", "mismatch", "unpinned", "unverifiable")}
for outcome, _label, _detail in results:
    counts[outcome] += 1

print()
print("verify-wasm-source: %d contracts — %d verified, %d mismatch, %d unpinned, "
      "%d unverifiable" % (len(results), counts["verified"], counts["mismatch"],
                            counts["unpinned"], counts["unverifiable"]))

if counts["mismatch"]:
    print("result: FAIL — committed source does not produce the recorded bytes")
    raise SystemExit(1)
if counts["unpinned"] or counts["unverifiable"]:
    print("result: UNVERIFIABLE — this run could not answer the question; "
          "a recorded hash is not a verified one")
    raise SystemExit(2)
print("result: PASS — committed source produces every recorded wasm hash")
PY
