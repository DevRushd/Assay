#!/usr/bin/env bash
# Checks docs/deployment.md against live chain state.
#
# That document is the record of what is deployed: the registry and gate
# addresses, the three gate instances with their wasm hashes, and the ten
# attestations with their severity, flags and evidence hash. It has drifted
# before — the docs named a superseded gate after the redeploy, and an
# unexplained duplicate instance existed before anything recorded it — and
# drift is silent, because a stale document reads exactly like a correct one.
#
# This script reads the tables and the network and reports the difference. It
# only ever reads: it never edits docs/deployment.md and never submits a
# transaction. Fixing drift is a decision for whoever owns the deployment.
#
# Usage:
#   scripts/check-deployment.sh [--rpc URL] [--timeout SECS] [--deployment PATH]
#
#   --rpc URL         Soroban JSON-RPC endpoint
#                     (default $ASSAY_RPC_URL, else the public testnet
#                     endpoint docs/deployment.md describes).
#   --timeout SECS    per-request timeout (default $ASSAY_RPC_TIMEOUT or 15).
#                     An endpoint that hangs must yield UNKNOWN promptly
#                     rather than block the run forever.
#   --deployment PATH markdown file holding the tables
#                     (default docs/deployment.md). A copy can be passed to
#                     exercise the checker without touching the real file.
#
# Pointing --rpc at an unreachable address (e.g. http://127.0.0.1:1) is how
# the inconclusive path is exercised, the same trick scripts/reproducibility.sh
# documents for its own source overrides.
#
# Outcomes, one per check:
#   valid    the documented value matches chain state.
#   invalid  a mismatch, reported with BOTH values. For an address, "no
#            contract at this address" is the on-chain value.
#   absent   a documented attestation with no entry on chain — the expected
#            outcome for an archived or withdrawn attestation. Reported
#            distinctly from a mismatch, and never as a match.
#   unknown  the RPC was unreachable, timed out, or answered with an error.
#            Inconclusive by definition: counted as neither a match nor a
#            mismatch, and never as a pass.
#
# Exit codes:
#   0  every check valid.
#   1  at least one invalid or absent — drift found, named, with both values.
#   2  no drift found but at least one check is unknown (INCONCLUSIVE), or the
#      tables could not be parsed / the script was misused. Exit 2 never means
#      "no drift": it means this run could not answer the question.
#
# A run with any unknown check therefore never exits 0. When drift and an
# unknown check occur together the run exits 1, as in reproducibility.sh: the
# finding is the more important information, and the unknown checks are
# reported with it.
#
# How chain state is read, and why not through the stellar CLI:
# docs/deployment.md already reads ledger entries directly, and its "Entry
# lifetime" section records that getLedgerEntries returns the archived entries
# with liveUntilLedgerSeq: 0 — which is precisely the state this deployment is
# in. One getLedgerEntries call therefore answers everything: a contract
# instance entry carries that contract's wasm hash and, in its instance
# storage, the registry address a gate was constructed with; an attestation
# entry carries severity, flags and evidence_hash. No simulation and no CLI
# install is required, so this runs unattended in a scheduled job. Restoring
# an archived entry is what a transaction would do; reading what is documented
# does not need that, and this script submits nothing.
#
# Scope: this compares the document against the chain. It does not check that
# the recorded hashes correspond to the source in this repository — that is
# #93, which is still open, and it needs a reproducible build rather than a
# ledger read.

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RPC="${ASSAY_RPC_URL:-https://soroban-testnet.stellar.org}"
TIMEOUT="${ASSAY_RPC_TIMEOUT:-15}"
DEPLOYMENT=""

usage() {
    sed -n '2,/^$/p' "$SCRIPT_DIR/check-deployment.sh" | sed 's/^# \{0,1\}//' >&2
    echo "usage: $0 [--rpc URL] [--timeout SECS] [--deployment PATH]" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --rpc) RPC="${2:-}"; shift 2 ;;
        --timeout) TIMEOUT="${2:-}"; shift 2 ;;
        --deployment) DEPLOYMENT="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "check-deployment: unknown argument $1" >&2; usage; exit 2 ;;
    esac
done

if [ -z "$DEPLOYMENT" ]; then
    DEPLOYMENT="$REPO_ROOT/docs/deployment.md"
fi

if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [ "$TIMEOUT" -lt 1 ]; then
    echo "check-deployment: --timeout must be a positive integer" >&2
    exit 2
fi
if [ -z "$RPC" ]; then
    echo "check-deployment: --rpc needs a URL" >&2
    exit 2
fi
if [ ! -f "$DEPLOYMENT" ]; then
    echo "check-deployment: deployment file not found: $DEPLOYMENT" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "check-deployment: python3 not found; it is required (scripts/reproducibility.sh uses it too)" >&2
    exit 2
fi

python3 - "$RPC" "$TIMEOUT" "$DEPLOYMENT" <<'PY'
import base64
import json
import re
import sys
import urllib.request

RPC, TIMEOUT, DEPLOYMENT = sys.argv[1], int(sys.argv[2]), sys.argv[3]
CONTRACT_RE = re.compile(r"C[A-Z2-7]{55}\Z")
CODE_RE = re.compile(r"[A-Z0-9]{1,12}\Z")
ELLIPSIS = ("\u2026", "...")

# ---------------------------------------------------------------------------
# Abbreviated values. docs/deployment.md writes long hashes and addresses as
# prefix…suffix, or a bare prefix, and writes a bare prefix when the same
# value appears in full elsewhere in the document. A check therefore matches
# when the on-chain value satisfies the documented abbreviation — the same
# rule scripts/reproducibility.sh applies to evidence hashes.
# ---------------------------------------------------------------------------


def fragment_matches(actual, expected):
    a, e = actual.strip().lower(), expected.strip().lower()
    for sep in ELLIPSIS:
        if sep in e:
            prefix, _, suffix = e.partition(sep)
            prefix, suffix = prefix.strip(), suffix.strip()
            if not prefix or not a.startswith(prefix) or not a.endswith(suffix):
                return False
            return len(a) >= len(prefix) + len(suffix)
    return a == e


def wasm_fragment(cell):
    """`ca40172e…` (severity ceiling) -> `ca40172e…`."""
    return cell.split("(")[0].strip()


def leading_int(cell):
    match = re.search(r"\d+", cell)
    return int(match.group()) if match else None


def strkey_contract(digest_hex):
    """A 32-byte contract hash rendered as a C… strkey: version byte 16,
    the hash, then a CRC16-XMODEM over both, little-endian. The leading C of a
    contract address is base32 of that version byte."""
    payload = bytes([16]) + bytes.fromhex(digest_hex)
    crc, poly = 0, 0x1021
    for byte in payload:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return base64.b32encode(payload + crc.to_bytes(2, "little")).decode().rstrip("=")


# ---------------------------------------------------------------------------
# The documented state, read from the tables in place. A second copy of these
# values inside this script could itself drift, which is the failure this
# exists to catch, so the document is the only source.
# Tables are recognised by their header row, so an unrelated table added to
# the document later is ignored rather than misread.
# ---------------------------------------------------------------------------


def cells(line):
    if not line.startswith("|"):
        return None
    return [cell.strip().replace("`", "") for cell in line.strip().strip("|").split("|")]


def is_separator(row):
    return all(cell and set(cell) <= set("-: ") for cell in row)


def tables(lines):
    """Yield (header, rows) per table. The |---|---| rule under a header is
    part of that table, not the end of it; a non-table line closes one. The two
    live-address tables have an empty header row, so the header is whatever
    follows the rule."""
    header, rows = None, []
    for line in lines:
        row = cells(line)
        if row is None:
            if header is not None:
                yield header, rows
                header, rows = None, []
            continue
        if is_separator(row):
            continue
        if header is None:
            header = row
        else:
            rows.append(row)
    if header is not None:
        yield header, rows


def die(message):
    print(f"check-deployment: {message}", file=sys.stderr)
    sys.exit(2)


registry_tables = {}   # "registry" / "gate" -> {addr, wasm}
instances = []         # [{addr, wasm, bound}]
assets = {}            # code -> {severity, flags, sac, evidence}

with open(DEPLOYMENT, encoding="utf-8") as handle:
    for header, rows in tables(handle.read().splitlines()):
        head = " ".join(header)
        if "Registry at construction" in head:
            for row in rows:
                if len(row) >= 4 and CONTRACT_RE.match(row[0]):
                    instances.append({"addr": row[0], "wasm": row[2], "bound": row[3]})
        elif "Asset" in header[0] and "Issuer" in head and "SAC" in head:
            for row in rows:
                if len(row) >= 4 and CODE_RE.match(row[0]):
                    assets.setdefault(row[0], {}).update(sac=row[2], evidence=row[3])
        elif "Asset" in header[0] and "Severity" in head and "Flags" in head:
            for row in rows:
                if len(row) >= 3 and CODE_RE.match(row[0]):
                    assets.setdefault(row[0], {}).update(severity=leading_int(row[1]),
                                                          flags=leading_int(row[2]))
        elif len(header) == 2 and "Asset" not in head:
            # The two live-address tables: a bolded row names the contract and
            # the next "Wasm hash" row belongs to it.
            pending = None
            for row in rows:
                if len(row) < 2:
                    continue
                if "Registry contract" in row[0]:
                    pending, registry_tables["registry"] = "registry", {"addr": row[1]}
                elif "Example gate contract" in row[0]:
                    pending, registry_tables["gate"] = "gate", {"addr": row[1]}
                elif row[0].startswith("Wasm hash") and pending:
                    registry_tables[pending]["wasm"] = row[1]

# The canonical gate is named in both the live-address table and the instance
# table. One check per contract; a full hash is preferred over an abbreviation
# of the same value.
contracts = {}
for label, entry in registry_tables.items():
    if entry.get("addr") and CONTRACT_RE.match(entry["addr"]):
        contracts[entry["addr"]] = {"wasm": entry.get("wasm"), "bound": None, "label": label}
for inst in instances:
    entry = contracts.setdefault(inst["addr"],
                                 {"wasm": None, "bound": None, "label": f"instance {inst['addr'][:8]}…"})
    if inst["wasm"] and (not entry["wasm"] or len(inst["wasm"]) > len(entry["wasm"])):
        entry["wasm"] = inst["wasm"]
    if inst["bound"]:
        entry["bound"] = inst["bound"]

registry_addr = next((addr for addr, e in contracts.items() if e["label"] == "registry"), None)
for code, entry in assets.items():
    for field in ("severity", "flags", "sac", "evidence"):
        if entry.get(field) in (None, ""):
            die(f"asset {code} has no documented {field}; the tables in {DEPLOYMENT} may have changed")
if not contracts or not assets or registry_addr is None:
    die(f"parsed {len(contracts)} contracts and {len(assets)} assets from {DEPLOYMENT}; "
        "the table format may have changed")

# ---------------------------------------------------------------------------
# XDR, built by hand. These are the bytes `stellar xdr encode --type ScVal`
# produces for the attestation key that docs/deployment.md prints, with the
# union and enum tags taken from the Stellar XDR definitions; each encoding
# here was checked against the official stellar-base encoder.
# ---------------------------------------------------------------------------

SCV_U32, SCV_U64, SCV_BYTES, SCV_SYMBOL = 3, 5, 13, 15
SCV_VEC, SCV_MAP, SCV_ADDRESS = 16, 17, 18
SCV_CONTRACT_INSTANCE, SCV_LEDGER_KEY_INSTANCE = 19, 20

# The instance storage of a contract is ScContractInstance.storage: an
# optional map, which the wire format carries as vec[map[...]] — the outer
# vec is the Option, the inner map the entries.
LEDGER_KEY_CONTRACT_DATA = 6
LEDGER_ENTRY_CONTRACT_DATA = 6
DURABILITY_PERSISTENT = 1


def u32(value):
    return value.to_bytes(4, "big")


def opaque(payload):
    return u32(len(payload)) + payload + b"\x00" * ((-len(payload)) % 4)


def contract_hash(address):
    return base64.b32decode(address)[1:-2]


def scval_symbol(text):
    return u32(SCV_SYMBOL) + opaque(text.encode())


def scval_contract_address(address):
    return u32(SCV_ADDRESS) + u32(1) + contract_hash(address)


def scval_safety_key(sac):
    """The key the registry stores an attestation under:
    vec[ symbol("Safety"), address(<SAC>) ] — the shape docs/deployment.md
    prints when it explains extending one entry by hand."""
    return (u32(SCV_VEC) + u32(1) + u32(2)
            + scval_symbol("Safety") + scval_contract_address(sac))


def ledger_data_key(contract, key_scval):
    """LedgerKey::CONTRACT_DATA. The ScAddress is a fixed-size union arm and
    so carries no length prefix, matching the bytes `stellar xdr encode` emits
    for the key docs/deployment.md prints."""
    return (u32(LEDGER_KEY_CONTRACT_DATA)
            + u32(1) + contract_hash(contract)
            + key_scval
            + u32(DURABILITY_PERSISTENT))


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def u32(self):
        value = int.from_bytes(self.data[self.pos:self.pos + 4], "big")
        self.pos += 4
        return value

    def raw(self, count):
        value = self.data[self.pos:self.pos + count]
        self.pos += count
        return value

    def opaque(self):
        """An XDR opaque: its own length, then the payload padded to 4 bytes."""
        length = self.u32()
        return self.raw((length + 3) // 4 * 4)[:length]


def read_sc_address(reader):
    tag = reader.u32()
    if tag == 1:
        return ("contract", reader.raw(32))
    if tag == 0:
        reader.u32()  # public key type
        return ("account", reader.raw(32))
    if tag in (36, 40):  # length-prefixed in some encodings
        return read_sc_address(Reader(reader.raw(tag)))
    raise ValueError(f"unexpected ScAddress tag {tag}")


def read_scval(reader):
    kind = reader.u32()
    if kind == SCV_U32:
        return {"u32": reader.u32()}
    if kind == SCV_U64:
        return {"u64": int.from_bytes(reader.raw(8), "big")}
    if kind == SCV_BYTES:
        return {"bytes": reader.opaque().hex()}
    if kind == SCV_SYMBOL:
        return {"symbol": reader.opaque().decode("utf-8", "replace")}
    if kind == SCV_ADDRESS:
        return {"address": read_sc_address(reader)}
    if kind in (SCV_VEC, SCV_MAP):
        if reader.u32() == 0:
            return {"vec" if kind == SCV_VEC else "map": None}
        count = reader.u32()
        if kind == SCV_VEC:
            return {"vec": [read_scval(reader) for _ in range(count)]}
        return {"map": [(read_scval(reader), read_scval(reader)) for _ in range(count)]}
    if kind == SCV_CONTRACT_INSTANCE:
        # The executable arm is bare (no length prefix): 0 selects wasm, and a
        # wasm-backed contract then carries the 32-byte hash. The optional
        # storage follows as a presence word, an entry count, then that many
        # key/value pairs — the count is of entries, not of values.
        arm = reader.u32()
        wasm = reader.raw(32).hex() if arm == 0 else None
        storage = []
        if reader.u32() != 0:
            for _ in range(reader.u32()):
                key_scval = read_scval(reader)
                storage.append((key_scval, read_scval(reader)))
        return {"instance": wasm, "storage": storage}
    if kind == SCV_LEDGER_KEY_INSTANCE:
        return {"instance_key": True}
    raise ValueError(f"unexpected ScVal tag {kind}")


def read_contract_data_entry(xdr_b64):
    """Decodes to the entry's value: the contract instance, or one
    attestation. LedgerEntryData discriminants mirror LedgerKey's, so
    CONTRACT_DATA is 6; CONTRACT_CODE (7) carries the wasm bytes instead."""
    reader = Reader(base64.b64decode(xdr_b64))
    if reader.u32() != LEDGER_ENTRY_CONTRACT_DATA:
        return None
    reader.u32()  # ContractDataEntryExt version
    read_sc_address(reader)  # contract
    read_scval(reader)  # key
    reader.u32()  # durability
    return read_scval(reader)


# ---------------------------------------------------------------------------
# One check per documented value; one request for all of them.
# ---------------------------------------------------------------------------

checks = []
for addr, entry in sorted(contracts.items()):
    label = entry["label"]
    instance_key = ledger_data_key(addr, u32(SCV_LEDGER_KEY_INSTANCE))
    checks.append((f"address {label}", "address", addr, instance_key))
    if entry["wasm"]:
        checks.append((f"wasm {label}", "wasm", wasm_fragment(entry["wasm"]), instance_key))
    if entry["bound"]:
        checks.append((f"registry-binding {label}", "bound", entry["bound"], instance_key))
for code, entry in sorted(assets.items()):
    checks.append((f"attestation {code}", "attestation",
                   (entry["severity"], entry["flags"], entry["evidence"]),
                   ledger_data_key(registry_addr, scval_safety_key(entry["sac"]))))

keys = {}
for name, kind, expected, key in checks:
    keys.setdefault(base64.b64encode(key).decode(), []).append((name, kind, expected))
key_list = list(keys)


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(RPC, data=body, headers={
        "Content-Type": "application/json",
        "User-Agent": "assay-check-deployment (+https://github.com/use-assay/Assay)",
    })
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        payload = json.loads(response.read().decode())
    if "error" in payload:
        raise RuntimeError(payload["error"].get("message", str(payload["error"])))
    return payload["result"]


results = {"valid": 0, "invalid": 0, "absent": 0, "unknown": 0}
findings, inconclusives = [], []


def report(outcome, name, detail):
    results[outcome] += 1
    print(f"{outcome.upper():<8}{name} :: {detail}")
    if outcome in ("invalid", "absent"):
        findings.append(f"{name}: {detail}")
    elif outcome == "unknown":
        inconclusives.append(f"{name}: {detail}")


def finish():
    print()
    print(f"check-deployment: {len(checks)} checks — {results['valid']} valid, "
          f"{results['invalid']} invalid, {results['absent']} absent, {results['unknown']} unknown "
          f"(rpc {RPC})", file=sys.stderr)
    if findings:
        print("", file=sys.stderr)
        print("FINDINGS (documented value vs on-chain value):", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
    if inconclusives:
        print("", file=sys.stderr)
        print("INCONCLUSIVE (not a pass, not a failure):", file=sys.stderr)
        for item in inconclusives:
            print(f"  {item}", file=sys.stderr)
    if findings:
        print("result: FAIL", file=sys.stderr)
        sys.exit(1)
    if inconclusives:
        print("result: INCONCLUSIVE", file=sys.stderr)
        sys.exit(2)
    print(f"result: PASS — every documented value matches the chain", file=sys.stderr)
    sys.exit(0)


# An unreachable or erroring RPC is inconclusive for every check, never a
# pass. Report it per check so the summary counts are the same shape as a
# real run, and so nothing silently reads as a match.
try:
    rpc("getHealth", {})
except Exception as exc:  # noqa: BLE001 — any failure here means "unknown"
    print(f"check-deployment: RPC unreachable ({exc})", file=sys.stderr)
    for name, _kind, _expected, _key in checks:
        report("unknown", name, f"RPC unreachable or timed out after {TIMEOUT}s")
    finish()

try:
    result = rpc("getLedgerEntries", {"keys": key_list})
except Exception as exc:  # noqa: BLE001
    for name, _kind, _expected, _key in checks:
        report("unknown", name, f"getLedgerEntries failed: {exc}")
    finish()

entries, undecodable = {}, set()
for entry in result.get("entries", []):
    try:
        entries[entry["key"]] = read_contract_data_entry(entry["xdr"])
    except (ValueError, KeyError, IndexError, base64.binascii.Error) as exc:
        undecodable.add(entry["key"])
        print(f"check-deployment: could not decode the entry {entry['key'][:24]}… ({exc})",
              file=sys.stderr)

for key, group in keys.items():
    if key in undecodable:
        for name, _, _ in group:
            report("unknown", name, "the ledger entry could not be decoded")
        continue
    value = entries.get(key)
    for name, kind, expected in group:
        if value is None:
            # Nothing at this key on chain.
            if kind == "attestation":
                report("absent", name,
                       f"documented severity {expected[0]}, flags {expected[1]}, evidence "
                       f"{expected[2]}; no attestation entry on chain")
            else:
                report("invalid", name,
                       f"documented {expected}; on-chain: no contract at this address")
            continue

        if kind == "address":
            report("valid", name, f"contract on chain at {expected}")

        elif kind == "wasm":
            actual = value.get("instance")
            if actual and fragment_matches(actual, expected):
                report("valid", name, f"{expected}")
            else:
                report("invalid", name, f"documented {expected}; on-chain {actual or 'no executable'}")

        elif kind == "bound":
            # The example gate's constructor argument lives in its instance
            # storage, keyed by "Registry". The key arrives either as a bare
            # symbol or wrapped in a single-element vec, so both are accepted;
            # any other key name reads as "names no registry" rather than
            # passing silently.
            bound = None
            for key_scval, val_scval in value.get("storage") or []:
                symbol = key_scval.get("symbol")
                if symbol is None:
                    wrapped = key_scval.get("vec") or []
                    if len(wrapped) == 1:
                        symbol = wrapped[0].get("symbol")
                if symbol == "Registry":
                    tag, digest = val_scval.get("address", (None, None))
                    if tag == "contract":
                        bound = strkey_contract(digest.hex())
            if bound is None:
                report("invalid", name,
                       f"documented registry {expected}; on-chain: the contract's instance storage "
                       "names no registry")
            elif fragment_matches(bound, expected):
                report("valid", name, f"{expected}")
            else:
                report("invalid", name, f"documented {expected}; on-chain {bound}")

        else:  # attestation
            stored = {key_scval.get("symbol"): val_scval
                      for key_scval, val_scval in (value.get("map") or [])}
            chain_severity = stored.get("severity", {}).get("u32")
            chain_flags = stored.get("flags", {}).get("u32")
            chain_evidence = stored.get("evidence_hash", {}).get("bytes")
            doc_severity, doc_flags, doc_evidence = expected
            if chain_severity is None and not chain_evidence:
                report("absent", name,
                       f"documented severity {doc_severity}, flags {doc_flags}, evidence "
                       f"{doc_evidence}; the entry on chain holds no attestation")
                continue
            problems = []
            if chain_severity != doc_severity:
                problems.append(f"severity documented {doc_severity} vs on-chain {chain_severity}")
            if chain_flags != doc_flags:
                problems.append(f"flags documented {doc_flags} vs on-chain {chain_flags}")
            if not chain_evidence or not fragment_matches(chain_evidence, doc_evidence):
                problems.append(f"evidence_hash documented {doc_evidence} vs on-chain {chain_evidence}")
            if problems:
                report("invalid", name, "; ".join(problems))
            else:
                report("valid", name,
                       f"severity {doc_severity}, flags {doc_flags}, evidence {doc_evidence}")

finish()
PY
