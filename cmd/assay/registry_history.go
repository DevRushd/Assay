package main

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/scan"
)

// This file implements `assay registry-history ASSET` (issue #342): read the
// registry's attest and revoke events for one asset back out of Soroban RPC
// `getEvents`, in ledger order.
//
// Overwritten attestations are recoverable only from these events, and the
// events are only as durable as the RPC node serving them. A node keeps a
// bounded window of ledgers (reported by getHealth as ledgerRetentionWindow;
// the stellar-rpc default is 17280 ledgers, about 24 hours, and hosted
// providers choose their own). Anything older than the window's oldest ledger
// is gone from that node, so an empty or short history is NOT proof that the
// asset was never attested. The command prints the window it could see so
// that gap is never silent.

const (
	defaultRegistry = "CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73"
	defaultRPC      = "https://soroban-testnet.stellar.org"
	eventsPageLimit = 200
)

// registryEvent is one decoded attest or revoke event.
type registryEvent struct {
	Ledger    int64             `json:"ledger"`
	ClosedAt  string            `json:"closed_at"`
	Kind      string            `json:"kind"`
	TxHash    string            `json:"tx_hash"`
	Fields    map[string]uint64 `json:"fields"`
	EventID   string            `json:"id"`
	AssetAddr string            `json:"asset"`
}

// registryHistory is the command's whole answer, including the retention
// window the RPC reported so the reader can see what the history cannot cover.
type registryHistory struct {
	Asset           string          `json:"asset"`
	Contract        string          `json:"contract"`
	OldestLedger    int64           `json:"rpc_oldest_ledger"`
	LatestLedger    int64           `json:"rpc_latest_ledger"`
	RetentionWindow int64           `json:"rpc_retention_window_ledgers"`
	Events          []registryEvent `json:"events"`
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func rpcCall(ctx context.Context, client *http.Client, url, method string, params any, out any) error {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("%s: encode request: %w", method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: build request: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: unexpected status %s", method, resp.Status)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&env); err != nil {
		return fmt.Errorf("%s: decode response: %w", method, err)
	}
	if env.Error != nil {
		return fmt.Errorf("%s: rpc error %d: %s", method, env.Error.Code, env.Error.Message)
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("%s: decode result: %w", method, err)
	}
	return nil
}

type rpcEvent struct {
	Ledger       int64    `json:"ledger"`
	ClosedAt     string   `json:"ledgerClosedAt"`
	ContractID   string   `json:"contractId"`
	ID           string   `json:"id"`
	Topic        []string `json:"topic"`
	Value        string   `json:"value"`
	TxHash       string   `json:"txHash"`
	InSuccessful *bool    `json:"inSuccessfulContractCall"`
}

// fetchRegistryHistory pages getEvents from the start of the node's retention
// window to its latest ledger. Events arrive in ledger order and are kept in
// that order.
func fetchRegistryHistory(ctx context.Context, client *http.Client, rpcURL, registry, sac string) (*registryHistory, error) {
	assetScVal, err := scAddressContract(sac)
	if err != nil {
		return nil, err
	}

	var health struct {
		Latest int64 `json:"latestLedger"`
		Oldest int64 `json:"oldestLedger"`
		Window int64 `json:"ledgerRetentionWindow"`
	}
	if err := rpcCall(ctx, client, rpcURL, "getHealth", nil, &health); err != nil {
		return nil, err
	}

	h := &registryHistory{
		Asset: sac, Contract: registry,
		OldestLedger: health.Oldest, LatestLedger: health.Latest, RetentionWindow: health.Window,
		Events: []registryEvent{},
	}

	filter := map[string]any{
		"type":        "contract",
		"contractIds": []string{registry},
		// topic 0 is the event label (attest or revoke), topic 1 the asset.
		"topics": [][]string{{"*", assetScVal}},
	}
	cursor := ""
	for {
		pagination := map[string]any{"limit": eventsPageLimit}
		params := map[string]any{"filters": []any{filter}}
		if cursor == "" {
			params["startLedger"] = health.Oldest
		} else {
			pagination["cursor"] = cursor
		}
		params["pagination"] = pagination

		var page struct {
			Events []rpcEvent `json:"events"`
			Cursor string     `json:"cursor"`
		}
		if err := rpcCall(ctx, client, rpcURL, "getEvents", params, &page); err != nil {
			return nil, err
		}
		for _, e := range page.Events {
			ev, err := decodeRegistryEvent(e, sac)
			if err != nil {
				return nil, fmt.Errorf("event %s: %w", e.ID, err)
			}
			h.Events = append(h.Events, ev)
		}
		if len(page.Events) < eventsPageLimit || page.Cursor == "" || page.Cursor == cursor {
			return h, nil
		}
		cursor = page.Cursor
	}
}

func decodeRegistryEvent(e rpcEvent, sac string) (registryEvent, error) {
	if len(e.Topic) < 1 {
		return registryEvent{}, errors.New("event has no topics")
	}
	t0, err := base64.StdEncoding.DecodeString(e.Topic[0])
	if err != nil {
		return registryEvent{}, fmt.Errorf("topic 0: %w", err)
	}
	kind, err := xdrSymbol(t0)
	if err != nil {
		return registryEvent{}, fmt.Errorf("topic 0: %w", err)
	}
	if kind != "attest" && kind != "revoke" {
		return registryEvent{}, fmt.Errorf("unexpected event label %q", kind)
	}
	val, err := base64.StdEncoding.DecodeString(e.Value)
	if err != nil {
		return registryEvent{}, fmt.Errorf("value: %w", err)
	}
	fields, err := xdrSymbolMap(val)
	if err != nil {
		return registryEvent{}, fmt.Errorf("value: %w", err)
	}
	return registryEvent{
		Ledger: e.Ledger, ClosedAt: e.ClosedAt, Kind: kind, TxHash: e.TxHash,
		Fields: fields, EventID: e.ID, AssetAddr: sac,
	}, nil
}

// --- the little XDR this command needs: a Symbol, a contract Address and a
// Map<Symbol, u32|u64>. Nothing else is accepted, so a changed event shape
// fails loudly instead of printing a wrong history.

const (
	scvU32     = 3
	scvU64     = 5
	scvMap     = 17
	scvAddress = 18
	scvSymbol  = 15
)

func xdrSymbol(b []byte) (string, error) {
	if len(b) < 8 || binary.BigEndian.Uint32(b) != scvSymbol {
		return "", errors.New("not a symbol")
	}
	n := int(binary.BigEndian.Uint32(b[4:]))
	if n < 0 || 8+n > len(b) {
		return "", errors.New("truncated symbol")
	}
	return string(b[8 : 8+n]), nil
}

func xdrSymbolMap(b []byte) (map[string]uint64, error) {
	if len(b) < 12 || binary.BigEndian.Uint32(b) != scvMap {
		return nil, errors.New("not a map")
	}
	if binary.BigEndian.Uint32(b[4:]) != 1 {
		return nil, errors.New("map is absent")
	}
	count := int(binary.BigEndian.Uint32(b[8:]))
	off := 12
	out := make(map[string]uint64, count)
	for i := 0; i < count; i++ {
		if off+8 > len(b) || binary.BigEndian.Uint32(b[off:]) != scvSymbol {
			return nil, errors.New("map key is not a symbol")
		}
		n := int(binary.BigEndian.Uint32(b[off+4:]))
		padded := (n + 3) &^ 3
		if n < 0 || off+8+padded > len(b) {
			return nil, errors.New("truncated map key")
		}
		key := string(b[off+8 : off+8+n])
		off += 8 + padded

		if off+4 > len(b) {
			return nil, errors.New("truncated map value")
		}
		switch binary.BigEndian.Uint32(b[off:]) {
		case scvU32:
			if off+8 > len(b) {
				return nil, errors.New("truncated u32")
			}
			out[key] = uint64(binary.BigEndian.Uint32(b[off+4:]))
			off += 8
		case scvU64:
			if off+12 > len(b) {
				return nil, errors.New("truncated u64")
			}
			out[key] = binary.BigEndian.Uint64(b[off+4:])
			off += 12
		default:
			return nil, fmt.Errorf("field %q has an unsupported type", key)
		}
	}
	return out, nil
}

// scAddressContract returns the base64 XDR of an ScVal address holding the
// contract (C...) strkey, the form getEvents topic filters take.
func scAddressContract(strkey string) (string, error) {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strkey))
	if err != nil || len(raw) != 35 || raw[0] != 2<<3 {
		return "", fmt.Errorf("invalid contract address %q", strkey)
	}
	if crc16(raw[:33]) != binary.LittleEndian.Uint16(raw[33:]) {
		return "", fmt.Errorf("invalid contract address %q: bad checksum", strkey)
	}
	buf := make([]byte, 0, 40)
	buf = binary.BigEndian.AppendUint32(buf, scvAddress)
	buf = binary.BigEndian.AppendUint32(buf, 1) // SC_ADDRESS_TYPE_CONTRACT
	buf = append(buf, raw[1:33]...)
	return base64.StdEncoding.EncodeToString(buf), nil
}

// crc16 is CRC16-XMODEM, the checksum Stellar strkeys carry.
func crc16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// stellarSACID derives an asset's SAC address through the stellar CLI, as
// `assay verify` does. It is a variable so tests do not need the CLI.
var stellarSACID = func(code, issuer, network string) (string, error) {
	out, err := exec.Command("stellar", "contract", "id", "asset",
		"--asset", code+":"+issuer, "--network", network).Output()
	if err != nil {
		return "", fmt.Errorf("derive SAC id: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func runRegistryHistory(args []string, d commandDeps) error {
	fs := flag.NewFlagSet("registry-history", flag.ContinueOnError)
	rpcURL := fs.String("rpc", envOr("ASSAY_RPC_URL", defaultRPC), "Soroban RPC endpoint (env ASSAY_RPC_URL)")
	registry := fs.String("contract", envOr("ASSAY_CONTRACT_ID", defaultRegistry), "registry contract id (env ASSAY_CONTRACT_ID)")
	network := fs.String("network", envOr("ASSAY_NETWORK", "testnet"), "network used to derive the SAC id (env ASSAY_NETWORK)")
	asJSON := fs.Bool("json", false, "print the history as JSON")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("registry-history: %w", err)
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("registry-history takes exactly one asset (CODE-ISSUER or a C... SAC address)")
	}

	sac := fs.Arg(0)
	if !strings.HasPrefix(sac, "C") || strings.Contains(sac, "-") {
		asset, err := scan.ParseAsset(sac)
		if err != nil {
			return fmt.Errorf("registry-history: %w", err)
		}
		if sac, err = stellarSACID(asset.Code, asset.Issuer, *network); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h, err := fetchRegistryHistory(ctx, &http.Client{Timeout: 30 * time.Second}, *rpcURL, *registry, sac)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(d.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(h); err != nil {
			return fmt.Errorf("registry-history: write: %w", err)
		}
		return nil
	}
	printRegistryHistory(d.stdout, h)
	return nil
}

func printRegistryHistory(w io.Writer, h *registryHistory) {
	_, _ = fmt.Fprintf(w, "registry %s, asset %s\n", h.Contract, h.Asset)
	_, _ = fmt.Fprintf(w, "RPC retention window: %d ledgers (ledgers %d-%d). Events older than ledger %d are not\n"+
		"available from this RPC, so earlier attestations and revocations may be missing.\n",
		h.RetentionWindow, h.OldestLedger, h.LatestLedger, h.OldestLedger)
	if len(h.Events) == 0 {
		_, _ = fmt.Fprintln(w, "no attest or revoke events in the retained window")
		return
	}
	for _, e := range h.Events {
		if e.Kind == "revoke" {
			_, _ = fmt.Fprintf(w, "%s  ledger %d  revoke  revoked_at=%d  tx %s\n",
				e.ClosedAt, e.Ledger, e.Fields["revoked_at"], e.TxHash)
			continue
		}
		_, _ = fmt.Fprintf(w, "%s  ledger %d  attest  severity=%d flags=%d attested_at=%d  tx %s\n",
			e.ClosedAt, e.Ledger, e.Fields["severity"], e.Fields["flags"], e.Fields["attested_at"], e.TxHash)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
