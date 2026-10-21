package main

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The RPC here is a local httptest server replaying getHealth/getEvents
// responses whose XDR is laid out per the Stellar XDR spec (ScVal symbol, map,
// u32, u64, contract address), so the test needs no network.

func testContractStrkey(fill byte) string {
	payload := append([]byte{2 << 3}, bytes.Repeat([]byte{fill}, 32)...)
	var sum [2]byte
	binary.LittleEndian.PutUint16(sum[:], crc16(payload))
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(append(payload, sum[:]...))
}

func xSymbol(s string) []byte {
	b := binary.BigEndian.AppendUint32(nil, scvSymbol)
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	b = append(b, s...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func xMap(fields ...any) string {
	b := binary.BigEndian.AppendUint32(nil, scvMap)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint32(b, uint32(len(fields)/2))
	for i := 0; i < len(fields); i += 2 {
		b = append(b, xSymbol(fields[i].(string))...)
		switch v := fields[i+1].(type) {
		case uint32:
			b = binary.BigEndian.AppendUint32(b, scvU32)
			b = binary.BigEndian.AppendUint32(b, v)
		case uint64:
			b = binary.BigEndian.AppendUint32(b, scvU64)
			b = binary.BigEndian.AppendUint64(b, v)
		}
	}
	return base64.StdEncoding.EncodeToString(b)
}

func b64Symbol(s string) string { return base64.StdEncoding.EncodeToString(xSymbol(s)) }

func TestRegistryHistoryOrdersAttestAndRevokeAndReportsRetention(t *testing.T) {
	registry := testContractStrkey(1)
	sac := testContractStrkey(2)
	wantTopic, err := scAddressContract(sac)
	if err != nil {
		t.Fatal(err)
	}

	var methods []string
	var sawTopicFilter, sawCursor bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		methods = append(methods, req.Method)
		switch req.Method {
		case "getHealth":
			_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"status":"healthy","latestLedger":5000,"oldestLedger":3000,"ledgerRetentionWindow":2000}}`)
		case "getEvents":
			if f, ok := req.Params["filters"].([]any); ok {
				js, _ := json.Marshal(f)
				sawTopicFilter = strings.Contains(string(js), wantTopic) && strings.Contains(string(js), registry)
			}
			pg, _ := req.Params["pagination"].(map[string]any)
			if _, ok := pg["cursor"]; ok {
				sawCursor = true
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"events":[{"ledger":4100,"ledgerClosedAt":"2026-10-02T10:00:00Z","id":"b","topic":[%q],"value":%q,"txHash":"tx-revoke"}],"cursor":"c2"}}`,
					b64Symbol("revoke"), xMap("revoked_at", uint64(1_700_000_200)))
				return
			}
			// A full page forces the client to follow the cursor.
			var evs []string
			for i := 0; i < eventsPageLimit; i++ {
				evs = append(evs, fmt.Sprintf(`{"ledger":%d,"ledgerClosedAt":"2026-10-01T10:00:00Z","id":"a%d","topic":[%q],"value":%q,"txHash":"tx-%d"}`,
					3500+i, i, b64Symbol("attest"), xMap("attested_at", uint64(1_700_000_000+i), "flags", uint32(i%4), "severity", uint32(1)), i))
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"events":[%s],"cursor":"c1"}}`, strings.Join(evs, ","))
		}
	}))
	defer srv.Close()

	var out bytes.Buffer
	err = runRegistryHistory([]string{"-rpc", srv.URL, "-contract", registry, "-json", sac}, commandDeps{stdout: &out})
	if err != nil {
		t.Fatal(err)
	}

	if len(methods) != 3 || methods[0] != "getHealth" {
		t.Fatalf("calls = %v, want getHealth then two getEvents pages", methods)
	}
	if !sawTopicFilter || !sawCursor {
		t.Fatalf("topic filter sent = %v, cursor followed = %v", sawTopicFilter, sawCursor)
	}

	var h registryHistory
	if err := json.Unmarshal(out.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if len(h.Events) != eventsPageLimit+1 {
		t.Fatalf("events = %d, want %d", len(h.Events), eventsPageLimit+1)
	}
	first, last := h.Events[0], h.Events[len(h.Events)-1]
	if first.Kind != "attest" || first.Fields["severity"] != 1 || first.Fields["attested_at"] != 1_700_000_000 {
		t.Errorf("first event = %+v", first)
	}
	if last.Kind != "revoke" || last.Fields["revoked_at"] != 1_700_000_200 || last.Ledger != 4100 {
		t.Errorf("last event = %+v", last)
	}
	for i := 1; i < len(h.Events); i++ {
		if h.Events[i].Ledger < h.Events[i-1].Ledger {
			t.Fatalf("events out of order at %d", i)
		}
	}
	if h.OldestLedger != 3000 || h.RetentionWindow != 2000 {
		t.Errorf("retention = oldest %d window %d", h.OldestLedger, h.RetentionWindow)
	}
}

func TestRegistryHistoryTextStatesRetention(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "getHealth" {
			_, _ = fmt.Fprint(w, `{"result":{"latestLedger":900,"oldestLedger":100,"ledgerRetentionWindow":800}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"result":{"events":[],"cursor":""}}`)
	}))
	defer srv.Close()

	var out bytes.Buffer
	if err := runRegistryHistory([]string{"-rpc", srv.URL, testContractStrkey(2)}, commandDeps{stdout: &out}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"RPC retention window: 800 ledgers", "earlier attestations and revocations may be missing", "no attest or revoke events"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestRegistryHistoryRejectsBadAddress(t *testing.T) {
	if _, err := scAddressContract("CNOTAREALADDRESS"); err == nil {
		t.Fatal("expected an error for a malformed contract address")
	}
}
