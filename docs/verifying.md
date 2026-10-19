# Verifying a release binary

When you download the `assay` scanner binary from a release, you should check
two things **before you execute it**:

1. **Checksum** — the SHA-256 of the exact bytes you downloaded matches the
   published checksum file. A checksum proves the file is intact; it does not
   prove *who* wrote it.
2. **Provenance** — a cryptographically signed build provenance block that
   records *which Git commit* the binary was built from and *which CI job*
   produced it. Provenance (not the checksum alone) is what lets a verifier
   confirm the binary matches the code they intend to run.

The release pipeline publishes **both**: a `.sha256` file and a provenance
block attached to the artifact by
[`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance).
This page describes how to verify both.

---

## 1. Download the release assets

From a GitHub release tag (for example `v1.2.3`), download two files into the
same directory:

* `assay-v1.2.3` — the compiled scanner binary.
* `assay-v1.2.3.sha256` — the published checksum.

Verify the directory contents before proceeding:

```sh
ls -la
# assay-v1.2.3  assay-v1.2.3.sha256
```

---

## 2. Check the checksum

```sh
cat assay-v1.2.3.sha256
# 9f7e...  assay-v1.2.3

sha256sum -c assay-v1.2.3.sha256
```

`sha256sum -c` prints `assay-v1.2.3: OK` when the downloaded bytes hash to the
published value. If it prints anything else, **discard the file** — do not run
it.

> The checksum is a necessary but not sufficient condition. An attacker who
> replaces the binary must also replace the checksum file (both are in the
> same GitHub release, so one compromise defeats both). That is exactly what
> provenance guards against below.

---

## 3. Verify the provenance

Provenance records the exact source commit and the CI job that built the
binary. It is an independent, cryptographically-signed statement that a
verifier can check without trusting GitHub's build machine.

### 3.1. Install the provenance tooling

```sh
# Linux
sudo apt-get install -y slsa-verifier

# macOS
brew install slsa-verifier
```

### 3.2. Attach the provenance to the artifact URL

```sh
artifact_url="https://github.com/use-assay/Assay/releases/download/v1.2.3/assay-v1.2.3"
provenance_url="https://github.com/use-assay/Assay/releases/download/v1.2.3/assay-v1.2.3.sig"  # produced by actions/attest-build-provenance

slsa-verifier verify-component \
  --provenance-identity "$provenance_url" \
  --source-uri "github.com/use-assay/Assay" \
  --source-tag "v1.2.3" \
  "$artifact_url"
```

The command exits `0` and prints `verified` when the provenance is valid and
the builder matches the declared source commit and tag.

### 3.3. Interpret the result

| Result | What it means |
| --- | --- |
| `verified` | The artifact is genuine: it was built from the exact Git commit/tag in the provenance, by the release CI. |
| `invalid` | The provenance did not verify (wrong tag, wrong commit, or corrupt signature). Do not trust the binary. |
| `not found` | The provenance artifact is missing. Re-download and re-check. |
| `untrusted` | The provenance verified but the CI workflow that produced it is not on the allow-list. See *Trust anchor* below. |

---

## 4. Cross-check the provenance against the local checkout

Provenance alone is only as trustworthy as the allow-list the verifier uses.
The safest verification workflow couples the two:

```sh
# 1. Check out the exact tagged source on your machine.
git clone --depth 1 --branch v1.2.3 https://github.com/use-assay/Assay
cd Assay

# 2. Confirm your downloaded binary's checksum still matches.
cd ..
sha256sum -c Assay/assay-v1.2.3.sha256

# 3. Confirm the provenance was emitted from THIS commit/tag.
slsa-verifier verify-component \
  --provenance-identity "https://github.com/use-assay/Assay/releases/download/v1.2.3/assay-v1.2.3.sig" \
  --source-uri "github.com/use-assay/Assay" \
  --source-tag "v1.2.3" \
  "Assay/assay-v1.2.3"
```

If the provenance verifies and the checksum matches, you can be confident that
the binary on your machine corresponds to the tagged source.

---

## 5. When you run `assay verify`

Once the binary is verified, the normal `assay verify` pipeline command is
used exactly as documented in [docs/cli.md](cli.md). If the provenance or
checksum does not verify, `assay` must refuse to run:

```text
assay: refusing to execute an unverifiable binary
       run ./assay-v1.2.3.sha256 to confirm the checksum,
       or fetch a fresh artifact from the release tag.
```

This is a policy decision on the *verifier's* side, not a property of the
Assay code. Assay itself reports findings from a scan; it does not police the
binary it was invoked by.

---

## 6. Trust anchor

`actions/attest-build-provenance` signs provenance against GitHub's OIDC
identity. A verifier's `slsa-verifier` allow-list should therefore include
**GitHub Actions** as a trusted builder for this repository's releases, so
that provenance produced by GitHub CI is not rejected as `untrusted`.

If you operate an air-gapped or hardened environment, pin the OIDC
issuer/workflow allow-list to the exact workflow file (`.github/workflows/release.yml`)
in this repository and treat any provenance not matching it as untrusted.

---

## 7. Summary of release files

| File | Purpose |
| --- | --- |
| `assay-v1.2.3` | Compiled scanner binary. |
| `assay-v1.2.3.sha256` | SHA-256 checksum of the binary (generated per release). |
| `assay-v1.2.3.sig` | Signed provenance block (generated by `actions/attest-build-provenance`). |

Verify the checksum first, then the provenance, and only then treat the binary
as trustworthy. Do not run it without both checks passing.
