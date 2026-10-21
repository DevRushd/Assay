# Preimage vectors

Each `<name>.preimage` file is the exact canonical byte sequence that
`evidence_hash` commits to for one report, and `<name>.digest` is its SHA-256
hex digest. A third-party reimplementation of the encoding (any language) can
verify itself against these fixtures without running this repo's code.

`aqua-mainnet-onchain`, `usdc-mainnet-onchain` and `usdz-mainnet-onchain` are
traceable to the testnet attestations for those mainnet assets: each digest
equals the `evidence_hash` recorded on chain and in `docs/attestation-run.md`
(AQUA tx `1b6bafc1226570b2415299f5531256716f4d8dc489a9784fcd6ea347d0f63f5f`,
USDC tx `9869957e510ac6cb9ba4e5ffaff66ad0286e420e824efc0095d9e578be37564e`,
USDZ tx `069d519fa20c472bbc3756291307fb30719219903c1e62a27b4967c0b07ecfd6`).
`onchain_test.go` pins those three digests as literal constants, so a vector
regenerated from whatever the encoder emits fails even if its `.digest` file is
rewritten to match.

**Do not regenerate these files from the encoder.** They are the reference the
encoder is checked against. A v1 vector whose bytes change no longer describes
an attestation that exists. That happened once: a script added an empty
`checks` line to every v1 vector and rewrote the digests, and for a while no
on-chain hash reproduced (#269). If the encoder and a vector disagree, the
encoder is wrong unless the change is a deliberate new encoding, and a new
encoding gets a new version tag and new vector files, never edits to existing
ones.

Every version tag has at least one vector: the v1 set above and the
`escaped`/`sorted`/`accountability` cases, `checkset-bound-v2`, the v3 pair
below, and `scanner-network-bound-v4`, whose scanner identity is pinned to
`v1.2.3` in `vectors_test.go`.

`network-bound-pubnet` and `network-bound-testnet` are the v3 pair: two vectors
byte-identical except for the `network` line, which is why their digests
differ. They pin the property #41 asks for — the same facts read from two
ledgers can no longer hash identically — and a reimplementation can verify
itself against both without running this repo's code.

The vectors were produced by an independent implementation of the documented
rules (`docs/contract-interface.md`), not by the Go encoder — see
`vectors_test.go`, which re-derives every vector from a Report and refuses any
vector file that is not pinned there.
