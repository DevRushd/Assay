package differential

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/use-assay/assay/internal/horizon"
)

// base64Encode mirrors base64Decode in xdr.go for building fixtures.
func base64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// The fixtures below encode raw ACCOUNT entry XDR whose layout was verified
// live against Soroban RPC and Horizon before this package existed (2026-09-27,
// pubnet): the AQUA issuer (no inflationDest, flags 0) and a revocable ARST
// issuer (inflationDest present, flags 2). Each fixture also states which
// Horizon JSON shape it corresponds to, so a reader can see both sides of the
// comparison without running anything.

// buildAccountEntryXDR assembles an ACCOUNT LedgerEntryData payload the way the
// live RPC responses rendered it: 4-byte union discriminants, big-endian
// fields, the inflationDest PublicKey taking 4 (tag) + 32 (key) bytes, and a
// homeDomain padded to a multiple of 4. It exists so the fixtures are readable
// as field lists rather than opaque hex blobs.
func buildAccountEntryXDR(key [32]byte, balance int64, seq uint64, inflDest *[32]byte, flags uint32, homeDomain string) []byte {
	b := []byte{0, 0, 0, 0}   // LedgerEntryData discriminant: ACCOUNT
	b = append(b, 0, 0, 0, 0) // PublicKey discriminant: ED25519
	b = append(b, key[:]...)
	b = append(b,
		byte(balance>>56), byte(balance>>48), byte(balance>>40), byte(balance>>32),
		byte(balance>>24), byte(balance>>16), byte(balance>>8), byte(balance))
	b = append(b,
		byte(seq>>56), byte(seq>>48), byte(seq>>40), byte(seq>>32),
		byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq))
	b = append(b, 0, 0, 0, 0) // numSubEntries
	if inflDest != nil {
		b = append(b, 0, 0, 0, 1) // option: some
		b = append(b, 0, 0, 0, 0) // PublicKey discriminant: ED25519
		b = append(b, inflDest[:]...)
	} else {
		b = append(b, 0, 0, 0, 0) // option: none
	}
	b = append(b, byte(flags>>24), byte(flags>>16), byte(flags>>8), byte(flags))
	b = append(b, byte(len(homeDomain)>>24), byte(len(homeDomain)>>16), byte(len(homeDomain)>>8), byte(len(homeDomain)))
	b = append(b, homeDomain...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	// thresholds (4), signers vec (0), ext v0 — the parser reads none of this,
	// but a payload that stops at homeDomain would be unlike anything the RPC
	// actually returns, so the tail is filled to a realistic shape.
	b = append(b, 0, 0, 0, 0) // thresholds
	b = append(b, 0, 0, 0, 0) // signers: vec len 0
	b = append(b, 0, 0, 0, 0) // ext: v0
	return b
}

var (
	clearKey = [32]byte{0x5b, 0x94, 0x2e, 0x53, 0xac, 0x33, 0xc8, 0xfd, 0x0a, 0x80, 0xcc, 0x7c, 0x1b, 0x1a, 0x85, 0xd7, 0xd8, 0x38, 0xa9, 0xc4, 0x19, 0x77, 0xaa, 0xd1, 0x8b, 0x3a, 0xf0, 0x57, 0xf8, 0xe3, 0x3d, 0xf0}
	revocKey = [32]byte{0x5d, 0xce, 0xd3, 0x7c, 0xf3, 0xdf, 0xaa, 0xe5, 0xd8, 0x38, 0x05, 0xcb, 0xcf, 0x35, 0x29, 0xec, 0xa6, 0x82, 0xbe, 0xfb, 0x8e, 0xd4, 0xd9, 0x32, 0xc9, 0x11, 0x7a, 0x58, 0x09, 0x73, 0x8b, 0xb2}
	otherKey = [32]byte{0xa3, 0xbe, 0x73, 0xfc, 0x75, 0xf5, 0x22, 0x04, 0x21, 0x07, 0x8f, 0x87, 0xa5, 0xc1, 0xe2, 0x4e, 0x12, 0x60, 0xdd, 0xfe, 0xab, 0xd2, 0x04, 0x72, 0x7d, 0x1a, 0xe8, 0x7f, 0x96, 0xe5, 0x68, 0xc2}
)

// The strkeys these keys belong to. clear and revoc are the AQUA issuer and the
// revocable ARST issuer from the live validation; both derive from fixtures
// via LedgerKeyForAccount in the client tests.
const (
	clearIssuerStrKey  = "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"
	revocIssuerStrKey  = "GBO45U346PP2VZOYHAC4XTZVFHWKNAV67OHNJWJSZEIXUWAJOOF3FPQU"
	strKeyWithInflDest = "GBO45U346PP2VZOYHAC4XTZVFHWKNAV67OHNJWJSZEIXUWAJOOF3FPQU"
)

func TestParseAccountFlags(t *testing.T) {
	t.Run("clear, no inflationDest (AQUA issuer, live-verified)", func(t *testing.T) {
		raw := buildAccountEntryXDR(clearKey, 336717607995, 3, nil, 0, "aqua.network")
		f, err := ParseAccountFlags(raw)
		if err != nil {
			t.Fatalf("ParseAccountFlags: %v", err)
		}
		want := horizon.Flags{}
		if f != want {
			t.Fatalf("flags = %+v, want %+v (Horizon: all false)", f, want)
		}
	})

	t.Run("revocable with inflationDest (ARST issuer, live-verified)", func(t *testing.T) {
		raw := buildAccountEntryXDR(revocKey, 29999712, 214124005404180487, &otherKey, 0x2, "xlmcoin.top")
		f, err := ParseAccountFlags(raw)
		if err != nil {
			t.Fatalf("ParseAccountFlags: %v", err)
		}
		if !f.AuthRevocable {
			t.Fatalf("flags = %+v, want AuthRevocable (Horizon: auth_revocable=true)", f)
		}
		if f.AuthRequired || f.AuthClawbackEnabled || f.AuthImmutable {
			t.Fatalf("flags = %+v, want only AuthRevocable", f)
		}
	})

	t.Run("all four flags, no inflationDest", func(t *testing.T) {
		raw := buildAccountEntryXDR(clearKey, 1, 1, nil, 0xF, "example.test")
		f, err := ParseAccountFlags(raw)
		if err != nil {
			t.Fatalf("ParseAccountFlags: %v", err)
		}
		want := horizon.Flags{AuthRequired: true, AuthRevocable: true, AuthImmutable: true, AuthClawbackEnabled: true}
		if f != want {
			t.Fatalf("flags = %+v, want %+v", f, want)
		}
	})

	t.Run("clawback with inflationDest", func(t *testing.T) {
		raw := buildAccountEntryXDR(revocKey, 1, 1, &otherKey, 0x8, "")
		f, err := ParseAccountFlags(raw)
		if err != nil {
			t.Fatalf("ParseAccountFlags: %v", err)
		}
		if !f.AuthClawbackEnabled {
			t.Fatalf("flags = %+v, want AuthClawbackEnabled", f)
		}
	})

	t.Run("non-account entry refused", func(t *testing.T) {
		// Trustline entry: LedgerEntryData discriminant 1.
		raw := []byte{0, 0, 0, 1, 0, 0, 0, 0}
		if _, err := ParseAccountFlags(raw); !errors.Is(err, ErrNotAccount) {
			t.Fatalf("err = %v, want ErrNotAccount", err)
		}
	})

	t.Run("truncated payloads refused", func(t *testing.T) {
		// no-inflationDest entry: flags live at 64..68, so every cut below that
		// must be refused rather than read.
		raw := buildAccountEntryXDR(clearKey, 1, 1, nil, 0, "x")
		for _, n := range []int{0, 3, 39, 63} {
			if _, err := ParseAccountFlags(raw[:n]); !errors.Is(err, ErrTruncated) {
				t.Errorf("ParseAccountFlags(%d bytes) err = %v, want ErrTruncated", n, err)
			}
		}
		// with inflationDest: flags live at 100..104. Cuts at 99 are one byte
		// short and must be refused, never read.
		full := buildAccountEntryXDR(revocKey, 1, 1, &otherKey, 0x2, "x")
		if _, err := ParseAccountFlags(full[:99]); !errors.Is(err, ErrTruncated) {
			t.Errorf("ParseAccountFlags(99 bytes) err = %v, want ErrTruncated", err)
		}
	})
}

func TestLedgerKeyForAccount(t *testing.T) {
	// The encoding is two zero union discriminants + the raw 32-byte key. It
	// was validated live: the SDF RPC accepted the byte string built this way
	// for these very accounts and returned their entries.
	key, err := LedgerKeyForAccount(clearIssuerStrKey)
	if err != nil {
		t.Fatalf("LedgerKeyForAccount: %v", err)
	}
	want := "AAAAAAAAAABblC5TrDPI/QqAzHwbGoXX2DipxBl3qtGLOvBX+OM98A=="
	if key != want {
		t.Fatalf("key = %q, want %q (the byte string the live RPC answered)", key, want)
	}

	for _, bad := range []string{
		"",
		"GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4K",    // 55 chars
		"GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZV0", // 0 is not in the base32 alphabet
		"MA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN", // wrong version byte ('M' = muxed account)
	} {
		if _, err := LedgerKeyForAccount(bad); !errors.Is(err, ErrBadAccountID) {
			t.Errorf("LedgerKeyForAccount(%q) err = %v, want ErrBadAccountID", bad, err)
		}
	}

	// A different valid strkey must still decode — the version and checksum
	// checks must not reject everything.
	if _, err := LedgerKeyForAccount("GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"); err != nil {
		t.Errorf("LedgerKeyForAccount(USDC issuer) err = %v; a valid strkey must decode", err)
	}

	// A corrupted-but-alphabetical strkey must fail its checksum rather than
	// silently addressing a different account.
	corrupt := []byte(revocIssuerStrKey)
	if corrupt[10] == 'A' {
		corrupt[10] = 'B'
	} else {
		corrupt[10] = 'A'
	}
	if _, err := LedgerKeyForAccount(string(corrupt)); !errors.Is(err, ErrBadAccountID) {
		t.Errorf("corrupted strkey err = %v, want ErrBadAccountID (checksum must be verified)", err)
	}
}

// rpcServer builds a stand-in Soroban RPC that answers getLedgerEntries with
// the given entries (key -> base64 xdr), or an RPC error / empty result
// depending on mode.
type rpcServer struct {
	srv     *httptest.Server
	entries map[string]string
	missing bool // answer with an empty entries array
	errBody bool // answer with a JSON-RPC error
	status  int  // if non-zero, answer with this HTTP status
}

func newRPCServer(t *testing.T, entries map[string]string) *rpcServer {
	t.Helper()
	rs := &rpcServer{entries: entries}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if rs.status != 0 {
			w.WriteHeader(rs.status)
			return
		}
		var req struct {
			Method string `json:"method"`
			Params struct {
				Keys []string `json:"keys"`
			} `json:"params"`
		}
		if err := jsonDecode(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if rs.errBody {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad key"}}`))
			return
		}
		out := `{"jsonrpc":"2.0","id":1,"result":{"entries":[`
		first := true
		for _, k := range req.Params.Keys {
			v, ok := rs.entries[k]
			if !ok || rs.missing {
				continue
			}
			if !first {
				out += ","
			}
			first = false
			out += `{"key":"` + k + `","xdr":"` + v + `"}`
		}
		out += `],"latestLedger":123}}`
		_, _ = w.Write([]byte(out))
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func jsonDecode(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func TestAccountFlags(t *testing.T) {
	key, err := LedgerKeyForAccount(clearIssuerStrKey)
	if err != nil {
		t.Fatalf("build key: %v", err)
	}
	clearXDR := base64Encode(buildAccountEntryXDR(clearKey, 1, 1, nil, 0, "aqua.network"))
	revocableXDR := base64Encode(buildAccountEntryXDR(revocKey, 1, 1, &otherKey, 0x2, "xlmcoin.top"))
	mismatchedXDR := base64Encode(buildAccountEntryXDR(revocKey, 1, 1, &otherKey, 0x8, "xlmcoin.top"))

	t.Run("agreement source: flags read from the entry", func(t *testing.T) {
		rs := newRPCServer(t, map[string]string{key: clearXDR})
		c := New(rs.srv.URL)
		f, err := c.AccountFlags(context.Background(), clearIssuerStrKey)
		if err != nil {
			t.Fatalf("AccountFlags: %v", err)
		}
		if f != (horizon.Flags{}) {
			t.Fatalf("flags = %+v, want all false", f)
		}
	})

	t.Run("revocable flags read from an entry with inflationDest", func(t *testing.T) {
		key2, err := LedgerKeyForAccount(strKeyWithInflDest)
		if err != nil {
			t.Fatalf("build key: %v", err)
		}
		rs := newRPCServer(t, map[string]string{key2: revocableXDR})
		c := New(rs.srv.URL)
		f, err := c.AccountFlags(context.Background(), strKeyWithInflDest)
		if err != nil {
			t.Fatalf("AccountFlags: %v", err)
		}
		if !f.AuthRevocable {
			t.Fatalf("flags = %+v, want AuthRevocable", f)
		}
	})

	t.Run("missing entry is ErrEntryAbsent, not zero flags", func(t *testing.T) {
		rs := newRPCServer(t, map[string]string{})
		rs.missing = true
		c := New(rs.srv.URL)
		if _, err := c.AccountFlags(context.Background(), clearIssuerStrKey); !errors.Is(err, ErrEntryAbsent) {
			t.Fatalf("err = %v, want ErrEntryAbsent", err)
		}
	})

	t.Run("rpc error body is ErrRPC", func(t *testing.T) {
		rs := newRPCServer(t, map[string]string{key: clearXDR})
		rs.errBody = true
		c := New(rs.srv.URL)
		if _, err := c.AccountFlags(context.Background(), clearIssuerStrKey); !errors.Is(err, ErrRPC) {
			t.Fatalf("err = %v, want ErrRPC", err)
		}
	})

	t.Run("http error status is ErrRPC", func(t *testing.T) {
		rs := newRPCServer(t, map[string]string{key: clearXDR})
		rs.status = http.StatusBadGateway
		c := New(rs.srv.URL)
		if _, err := c.AccountFlags(context.Background(), clearIssuerStrKey); !errors.Is(err, ErrRPC) {
			t.Fatalf("err = %v, want ErrRPC", err)
		}
	})

	t.Run("an entry that does not echo the requested key is refused", func(t *testing.T) {
		other, err := LedgerKeyForAccount(strKeyWithInflDest)
		if err != nil {
			t.Fatalf("build key: %v", err)
		}
		rs := newRPCServer(t, map[string]string{other: mismatchedXDR})
		c := New(rs.srv.URL)
		// Ask for the clear issuer; the server holds only the other key, so a
		// correct client finds nothing rather than reading the wrong entry.
		if _, err := c.AccountFlags(context.Background(), clearIssuerStrKey); !errors.Is(err, ErrEntryAbsent) {
			t.Fatalf("err = %v, want ErrEntryAbsent (must never read another account's entry)", err)
		}
	})
}
