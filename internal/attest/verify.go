package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrHashMismatch reports a preimage that does not hash to the claimed
// evidence_hash.
//
// It is the one verdict a verifier exists to produce, and it is a failure
// rather than a note: the bytes the attester published and the hash the
// contract stores do not correspond, so whatever is on chain is not an
// attestation of this evidence.
var ErrHashMismatch = errors.New("attest: preimage does not hash to the claimed evidence_hash")

// ErrMalformedHash reports an evidence_hash that is not 32 bytes of hex.
//
// A truncated or mistyped hash is refused rather than compared, because
// comparing it would report a mismatch and blame the preimage for what is
// actually a copy-paste error in the hash.
var ErrMalformedHash = errors.New("attest: malformed evidence_hash")

// PreimageInfo is what a canonical preimage says about itself.
//
// It is deliberately a small subset: only the fields a verifier needs in order
// to describe what it checked. Every other field is covered by the hash, so
// re-stating it would add no assurance.
type PreimageInfo struct {
	// Version is the encoding line. It is itself inside the hash, so a verifier
	// reading it is reading a value the attestation already committed to.
	Version string `json:"version"`
	// Asset is the CODE-ISSUER the preimage is about.
	Asset string `json:"asset"`
	// Checks is the sorted check set a v2 preimage binds. It is nil — not an
	// empty set — for a v1 preimage, because v1 bound no check set at all and
	// "bound nothing" and "bound the empty set" are different claims.
	Checks []string `json:"checks,omitempty"`
}

// Verification is the outcome of checking a preimage against a hash.
type Verification struct {
	PreimageInfo
	// Computed is the SHA-256 of the exact bytes supplied, lowercase hex.
	Computed string `json:"computed"`
	// Claimed is the normalized hash that was checked against, or empty when
	// no hash was supplied.
	Claimed string `json:"claimed,omitempty"`
	// Match is true only when a hash was supplied and it equals Computed.
	Match bool `json:"match"`
	// Notes carries what a verifier should know that is not itself a failure:
	// a v1 preimage whose check set is therefore unknown, or a header that
	// could not be read. The hash check is unaffected by either.
	Notes []string `json:"notes,omitempty"`
}

// HashPreimage returns the lowercase hex SHA-256 of canonical preimage bytes.
//
// The bytes are hashed exactly as given. No trimming, no re-encoding: the hash
// covers the bytes themselves, so normalising anything before hashing would
// verify a different document from the one the attester published.
func HashPreimage(pre []byte) string {
	sum := sha256.Sum256(pre)
	return hex.EncodeToString(sum[:])
}

// NormalizeEvidenceHash accepts a 32-byte hex evidence_hash in any of the forms
// a verifier is likely to have copied it and returns it lowercase and bare.
//
// An on-chain `BytesN<32>` has no 0x prefix, but the same value pasted out of a
// block explorer or a shell usually does, and neither spelling changes what is
// being compared. Deviation in length or alphabet is an error rather than a
// mismatch so the two failures stay distinguishable.
func NormalizeEvidenceHash(s string) (string, error) {
	h := strings.TrimSpace(s)
	h = strings.TrimPrefix(h, "0x")
	h = strings.TrimPrefix(h, "0X")
	h = strings.ToLower(h)
	if len(h) != sha256.Size*2 {
		return "", fmt.Errorf("%w: %d hex characters, want %d",
			ErrMalformedHash, len(h), sha256.Size*2)
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformedHash, err)
	}
	return h, nil
}

// ParsePreimage reads the header of a canonical preimage.
//
// It is strict about the two things a verifier cannot afford to guess: the
// version line, because an unrecognised encoding may not mean what this package
// assumes, and the presence of the lines that make these bytes a preimage
// rather than a file of the right shape. Both are refusal cases rather than
// warnings — a verifier that shrugs at an unknown version is one whose
// agreement means nothing.
//
// The trailing newline is not required. HashPreimage still hashes the exact
// bytes, so a preimage that lost its final LF in transit can be verified while
// still being reported accurately.
func ParsePreimage(pre []byte) (PreimageInfo, error) {
	if len(pre) == 0 {
		return PreimageInfo{}, errors.New("attest: empty preimage")
	}
	lines := strings.Split(strings.TrimSuffix(string(pre), "\n"), "\n")

	info := PreimageInfo{Version: lines[0]}
	switch info.Version {
	case PreimageVersion, PreimageVersionCheckSet:
	default:
		return PreimageInfo{}, fmt.Errorf("attest: unrecognised preimage version %q", info.Version)
	}

	sawAsset, sawChecks := false, false
	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		key, val, ok := strings.Cut(l, "\t")
		if !ok {
			return PreimageInfo{}, fmt.Errorf("attest: line %q is not key<TAB>value", l)
		}
		switch key {
		case "asset":
			info.Asset, sawAsset = unescape(val), true
		case "checks":
			sawChecks = true
			if val != "" {
				checks := strings.Split(val, ",")
				sort.Strings(checks)
				info.Checks = checks
			}
		}
	}

	if !sawAsset {
		return PreimageInfo{}, errors.New("attest: preimage has no asset line")
	}
	if info.Version == PreimageVersionCheckSet && !sawChecks {
		return PreimageInfo{}, errors.New("attest: v2 preimage has no checks line")
	}
	return info, nil
}

// VerifyPreimage checks a canonical preimage against the evidence_hash an
// attestation carries.
//
// This is the verification the contract-interface document describes, reduced
// from two commands and a human comparing hex against each other to one command
// with an exit status: the attester publishes the preimage
// (`assay attestation -preimage`), the contract stores the hash, and this
// decides whether the two agree.
//
// An empty claimed hash reports the computed hash without a verdict, so the
// command doubles as the way to produce the hash of a preimage without a
// second tool. A claimed hash that does not match is returned as
// ErrHashMismatch with Verified still populated, so a caller can print both
// values and a script can act on the exit status alone.
func VerifyPreimage(pre []byte, claimed string) (Verification, error) {
	v := Verification{Computed: HashPreimage(pre)}

	// Parsing is best effort. A preimage whose header cannot be read can still
	// have its hash checked, and refusing to hash it would let a cosmetic
	// problem hide a real mismatch.
	if info, err := ParsePreimage(pre); err == nil {
		v.PreimageInfo = info
		if info.Version == PreimageVersion {
			v.Notes = append(v.Notes,
				"preimage is v1: it binds no check set, so check-set completeness is unknown")
		}
	} else {
		v.Notes = append(v.Notes, err.Error())
	}

	if strings.TrimSpace(claimed) == "" {
		return v, nil
	}

	want, err := NormalizeEvidenceHash(claimed)
	if err != nil {
		return v, err
	}
	v.Claimed = want
	v.Match = want == v.Computed
	if !v.Match {
		return v, fmt.Errorf("%w: computed %s, claimed %s", ErrHashMismatch, v.Computed, want)
	}
	return v, nil
}

// unescape reverses escape, so a verifier reports the claim a source published
// rather than its on-the-wire form. The replacement order mirrors escape: the
// doubled-backslash form is consumed first, so an escaped backslash followed by
// a literal "t" does not read back as a tab.
func unescape(s string) string {
	r := strings.NewReplacer(
		`\\`, `\`,
		`\t`, "\t",
		`\n`, "\n",
		`\r`, "\r",
	)
	return r.Replace(s)
}
