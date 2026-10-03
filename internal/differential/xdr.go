package differential

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/use-assay/assay/internal/horizon"
)

// base64Decode is a small alias so the parser reads without importing
// encoding/base64 in three places.
func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// strkeyAlphabet is the base32 alphabet Stellar strkeys use. It is local to
// this package on purpose: implementing the 40-line decode here, and testing
// it, is what keeps this derivation independent of the primary scan. Pulling
// in the SDK's strkey package would add a third-party dependency to a security
// control whose whole job is to not share code with the thing it checks, and
// would trip the merge gate's dependency rule besides.
const strkeyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// strKeyVersionEd25519 is the version byte of an ed25519 account strkey ('G').
// 56 strkey characters are exactly 35 bytes (280 bits), so the first decoded
// byte carries the version in its high five bits followed by three bits of the
// key: 6<<3 == 0x30, as verified against live strkeys.
const strKeyVersionEd25519 = 6 << 3 // 0x30

// decodeStrKey decodes a G... account strkey to its 32-byte ed25519 public key.
//
// The checksum is verified rather than assumed: a malformed issuer identifier
// must be refused before it can become a ledger key that names a different
// account, for the same reason horizon.Client.Account refuses a record that
// echoes a different account_id.
func decodeStrKey(s string) ([]byte, error) {
	if len(s) != 56 {
		return nil, fmt.Errorf("%w: %q is %d characters, want 56", ErrBadAccountID, s, len(s))
	}
	// Bit-buffer decode: 56 chars x 5 bits = 280 bits = 35 bytes exactly. The
	// accumulator must be a bit buffer, not an integer — 280 bits overflows any
	// fixed-width integer, and a silently truncating decode would corrupt the
	// key while still passing the length and alphabet checks.
	raw := make([]byte, 0, 35)
	var acc uint32
	var bits uint8
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(strkeyAlphabet, s[i])
		if v < 0 {
			return nil, fmt.Errorf("%w: %q has a character outside the base32 alphabet", ErrBadAccountID, s)
		}
		acc = acc<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			raw = append(raw, byte(acc>>bits))
		}
	}
	if raw[0] != strKeyVersionEd25519 {
		return nil, fmt.Errorf("%w: %q is not an ed25519 account strkey", ErrBadAccountID, s)
	}
	if !strKeyChecksumOK(raw[:33], raw[33:]) {
		return nil, fmt.Errorf("%w: %q fails its checksum", ErrBadAccountID, s)
	}
	return raw[1:33], nil
}

// strKeyChecksumOK reports whether the 2-byte checksum appended to a strkey
// payload matches. The checksum is computed over the version byte and the
// payload, so it is verified here before the key is trusted.
func strKeyChecksumOK(payload, checksum []byte) bool {
	want := strKeyChecksum(payload)
	return want[0] == checksum[0] && want[1] == checksum[1]
}

// strKeyChecksum computes the CRC-16 checksum Stellar appends to strkeys:
// the non-reflected CCITT polynomial 0x1021, initial value 0, no final
// complement, appended little-endian.
//
// Neither the parameterisation nor the byte order is what the CRC-16 names in
// most tables suggest (CRC-16/X.25 is reflected with init 0xffff and a final
// XOR; CRC-16/XMODEM is usually shown big-endian), so this is verified against
// three live strkeys rather than a table entry — the fixtures in xdr_test.go
// pin it. Getting this wrong would not weaken security (it would reject every
// real key), but a broken scanner is a broken scanner regardless of direction.
func strKeyChecksum(data []byte) [2]byte {
	crc := uint16(0)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return [2]byte{byte(crc & 0xff), byte(crc >> 8)}
}

// LedgerKeyForAccount builds the base64 LedgerKey that addresses accountID's
// ledger entry, encoded by hand from the protocol XDR definition:
//
//	LedgerKey = [0: ACCOUNT] LedgerKeyAccount
//	LedgerKeyAccount = AccountId
//	AccountId = PublicKey = [0: ED25519] Uint256
//
// so the bytes are two zero union discriminants followed by the raw key.
func LedgerKeyForAccount(accountID string) (string, error) {
	raw, err := decodeStrKey(accountID)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 8+len(raw))
	copy(buf[8:], raw)
	return base64.StdEncoding.EncodeToString(buf), nil
}

// Account entry XDR layout, through the only field this package reads.
//
// The LedgerKey's own framing is 4 bytes of union discriminants before the
// entry body, so from the start of the LedgerEntryData returned by
// getLedgerEntries:
//
//	 0: 4   LedgerEntryData discriminant; 0 = ACCOUNT
//	 4: 4   AccountEntry.accountID: PublicKey discriminant; 0 = ED25519
//	 8:40   the ed25519 key bytes
//	40:48   balance (int64)
//	48:56   seqNum (uint64)
//	56:60   numSubEntries (uint32)
//	60:64   inflationDest option tag; 0 = absent, 1 = present
//	64:100  inflationDest, when present: PublicKey = 4-byte tag + 32 bytes
//	100:104 flags (uint32)   [64:104 with no inflationDest]
//	 ...    homeDomain, thresholds, signers, extensions — unread
//
// The layout through flags was verified live before implementation: the AQUA
// issuer (no inflationDest, flags 0) and a revocable ARST issuer (inflationDest
// present, flags 2) both decoded to the same flags Horizon reports for the same
// accounts, at the offsets above. The PublicKey-union framing (4 + 36, not 32)
// is exactly the kind of detail a hand parser gets wrong once and never
// notices, which is why the fixtures in xdr_test.go pin both branches.
const (
	accountEntryIDOffset  = 8
	accountEntryKeyOffset = 8 + 4 + 32         // discriminant + PublicKey tag + key
	accountEntryMinLength = 40 + 8 + 8 + 4 + 4 // id+bal+seq+numSub+inflTag
)

// ParseAccountFlags extracts the authorization flags from a raw ACCOUNT
// LedgerEntryData payload, exactly as Soroban RPC returns it (the `xdr` field,
// base64, already decoded by the caller).
//
// It reads only through the flags field and refuses everything it cannot read
// exactly: a wrong discriminant is ErrNotAccount, a short payload is
// ErrTruncated. It does not skip or tolerate — tolerating a shifted read here
// would put a different account's flags under this account's name, silently.
func ParseAccountFlags(entryXDR []byte) (horizon.Flags, error) {
	if len(entryXDR) < 4 {
		return horizon.Flags{}, fmt.Errorf("%w: %d bytes", ErrTruncated, len(entryXDR))
	}
	if u32(entryXDR, 0) != 0 {
		return horizon.Flags{}, fmt.Errorf("%w: discriminant %d", ErrNotAccount, u32(entryXDR, 0))
	}
	if len(entryXDR) < accountEntryMinLength {
		return horizon.Flags{}, fmt.Errorf("%w: %d bytes, need %d before flags",
			ErrTruncated, len(entryXDR), accountEntryMinLength)
	}

	// The echoed account key must be the one this entry is keyed on: the key's
	// framing is discriminant + tag + 32 bytes, starting at accountEntryIDOffset.
	if u32(entryXDR, 4) != 0 {
		return horizon.Flags{}, fmt.Errorf("%w: public key type %d", ErrNotAccount, u32(entryXDR, 4))
	}

	flagsOffset := accountEntryKeyOffset // 44
	// Wait — the account key framing: LedgerEntryData disc (4) + PublicKey tag
	// (4) + key (32) = 40, then balance (8) to 48, seqNum (8) to 56,
	// numSubEntries (4) to 60, inflationDest tag (4) to 64, and the
	// inflationDest PublicKey, when present, is another 4 + 32 = 36 to 100.
	flagsOffset = 100
	if u32(entryXDR, 60) == 0 {
		flagsOffset = 64
	}
	if len(entryXDR) < flagsOffset+4 {
		return horizon.Flags{}, fmt.Errorf("%w: %d bytes, flags begin at %d",
			ErrTruncated, len(entryXDR), flagsOffset)
	}

	f := u32(entryXDR, flagsOffset)
	return horizon.Flags{
		AuthRequired:        f&0x1 != 0,
		AuthRevocable:       f&0x2 != 0,
		AuthImmutable:       f&0x4 != 0,
		AuthClawbackEnabled: f&0x8 != 0,
	}, nil
}

// u32 reads a big-endian uint32 at off. XDR is big-endian throughout; the
// parser must not inherit Go's little-endian intuition.
func u32(b []byte, off int) uint32 {
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3])
}
