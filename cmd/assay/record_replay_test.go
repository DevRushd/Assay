package main

// Record-and-replay coverage (issue #466): a live scan recorded to a
// directory must be reproducible from that directory alone — after the live
// sources are gone — with the same preimage bytes, the same evidence hash
// and the same report apart from the retrieval timestamps, which the
// encoding deliberately excludes so a hash is verifiable by anyone, at any
// later time, from the recorded evidence alone.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
)

const rrIssuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

// rrSources stands up the two upstreams a no-home-domain scan actually
// fetches: Horizon (asset record, issuer account) and the StellarExpert
// directory. With no home_domain the stellar.toml and blocklist fetches are
// skipped, so the recording contains exactly these requests — and closing
// both servers before the replay proves the replay needs no network.
func rrSources(t *testing.T) (*httptest.Server, *httptest.Server) {
	t.Helper()

	horizon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/assets":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_embedded": map[string]any{
					"records": []map[string]any{{
						"asset_type":   "credit_alphanum4",
						"asset_code":   "USDC",
						"asset_issuer": rrIssuer,
						"flags":        map[string]bool{},
					}},
				},
			})
		case "/accounts/" + rrIssuer:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"account_id":  rrIssuer,
				"home_domain": "",
				"flags":       map[string]bool{},
			})
		default:
			http.NotFound(w, r)
		}
	}))

	expert := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/explorer/directory/"+rrIssuer {
			// The directory's 200-with-empty-body answer for an unlisted address.
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.NotFound(w, r)
	}))

	t.Cleanup(horizon.Close)
	t.Cleanup(expert.Close)
	return horizon, expert
}

// stripTimestamps removes every retrieval-time field from a decoded report.
// They are wall-clock facts about when a scan ran, not verdicts: the preimage
// excludes them on purpose, which is what makes a hash recomputable later.
func stripTimestamps(v any) {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range []string{"scanned_at", "retrieved_at", "observation_window_start", "observation_window_end"} {
			delete(t, k)
		}
		for _, child := range t {
			stripTimestamps(child)
		}
	case []any:
		for _, child := range t {
			stripTimestamps(child)
		}
	}
}

func reportJSON(t *testing.T, rep *mechanics.Report, strip bool) string {
	t.Helper()
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if !strip {
		return string(b)
	}
	var decoded any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	stripTimestamps(decoded)
	out, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal report: %v", err)
	}
	return string(out)
}

// TestScanRecordThenReplayIsDeterministic is the acceptance test for #466:
// record a live scan, take the network away, replay, and compare.
func TestScanRecordThenReplayIsDeterministic(t *testing.T) {
	horizon, expert := rrSources(t)
	t.Setenv("ASSAY_HORIZON_URL", horizon.URL)
	t.Setenv("ASSAY_STELLAREXPERT_URL", expert.URL)

	asset, err := scan.ParseAsset("USDC-" + rrIssuer)
	if err != nil {
		t.Fatalf("ParseAsset: %v", err)
	}
	d := commandDeps{stdout: io.Discard, stderr: io.Discard}
	dir := t.TempDir()

	// 1. Record a live scan.
	scanFn, finish, err := scanFuncForRecording(nil, d, dir, "")
	if err != nil {
		t.Fatalf("record setup: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	live, err := scanFn(ctx, asset)
	if err != nil {
		t.Fatalf("live scan: %v", err)
	}
	finish() // writes the manifest and bodies, as the CLI does via defer

	// 2. Take the network away. The only responses a replay can get are the
	// recorded ones.
	horizon.Close()
	expert.Close()

	// 3. Replay. No network exists to reach; an unrecorded request would be
	// a loud error rather than a live fetch.
	replayFn, _, err := scanFuncForRecording(nil, d, "", dir)
	if err != nil {
		t.Fatalf("replay setup: %v", err)
	}
	replayed, err := replayFn(ctx, asset)
	if err != nil {
		t.Fatalf("replayed scan with every source offline: %v", err)
	}

	// 4. The canonical preimage bytes — what evidence_hash commits to — are
	// identical. This is the claim the reproducibility job depends on.
	if got, want := mustPreimage(t, replayed), mustPreimage(t, live); got != want {
		t.Errorf("preimage differs between recorded and replayed scan\n--- recorded ---\n%s\n--- replayed ---\n%s",
			want, got)
	}

	// 5. So is the evidence hash: it is the SHA-256 of those bytes, computed
	// directly here because attest.FromReport refuses an undetermined report
	// outright — and a fake issuer with no home_domain is undetermined by
	// design (the blocklist is never asked, which the engine reports rather
	// than reads as a clean answer).
	liveSum := sha256.Sum256([]byte(mustPreimage(t, live)))
	replaySum := sha256.Sum256([]byte(mustPreimage(t, replayed)))
	if liveSum != replaySum {
		t.Errorf("evidence hash: recorded=%x replayed=%x", liveSum, replaySum)
	}

	// 6. And the reports are identical apart from the retrieval timestamps,
	// which are the one thing that must differ: they record when each scan
	// asked, and freezing them would require a clock hook through the whole
	// scanner for no verifiability gain.
	if a, b := reportJSON(t, live, true), reportJSON(t, replayed, true); a != b {
		t.Errorf("reports differ beyond retrieval timestamps\n--- recorded ---\n%s\n--- replayed ---\n%s", a, b)
	}
}

// A recording is the artifact, so its contents are checked: the manifest
// indexes every request the scan made, and a replay of an unrecorded request
// is a loud error rather than a live call.
func TestRecordingManifestAndLoudReplayMiss(t *testing.T) {
	horizon, expert := rrSources(t)
	t.Setenv("ASSAY_HORIZON_URL", horizon.URL)
	t.Setenv("ASSAY_STELLAREXPERT_URL", expert.URL)

	asset, err := scan.ParseAsset("USDC-" + rrIssuer)
	if err != nil {
		t.Fatalf("ParseAsset: %v", err)
	}
	d := commandDeps{stdout: io.Discard, stderr: io.Discard}
	dir := t.TempDir()

	scanFn, finish, err := scanFuncForRecording(nil, d, dir, "")
	if err != nil {
		t.Fatalf("record setup: %v", err)
	}
	if _, err := scanFn(context.Background(), asset); err != nil {
		t.Fatalf("live scan: %v", err)
	}
	finish()

	replayFn, _, err := scanFuncForRecording(nil, d, "", dir)
	if err != nil {
		t.Fatalf("replay setup: %v", err)
	}
	// Scanning a DIFFERENT asset asks for requests the recording does not
	// hold. The scan must fail with the replay error naming the request —
	// never fall through to the (still live, here) network.
	other, err := scan.ParseAsset("NOTREC-" + rrIssuer)
	if err != nil {
		t.Fatalf("ParseAsset: %v", err)
	}
	_, err = replayFn(context.Background(), other)
	if err == nil {
		t.Fatal("replay of an unrecorded asset succeeded; it must fail loudly")
	}
	if !strings.Contains(err.Error(), "replay: unrecorded request") {
		t.Errorf("error is not the loud replay failure: %v", err)
	}
}

func TestScanRecordAndReplayFlagsAreMutuallyExclusive(t *testing.T) {
	var stderr bytes.Buffer
	d := commandDeps{stdout: io.Discard, stderr: &stderr}
	err := runWith([]string{"scan", "-record", "a", "-replay", "b", "USDC-" + rrIssuer}, d)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want the mutual-exclusion refusal", err)
	}
}

func TestScanReplayMissingRecordingFailsBeforeAnyFetch(t *testing.T) {
	d := commandDeps{stdout: io.Discard, stderr: io.Discard}
	err := runWith([]string{"scan", "-replay", t.TempDir(), "USDC-" + rrIssuer}, d)
	if err == nil || !strings.Contains(err.Error(), "replay: read manifest") {
		t.Fatalf("error = %v, want the manifest refusal", err)
	}
}

// mustPreimage renders a report's preimage and fails the test if its bindings
// match no encoding.
func mustPreimage(t *testing.T, rep *mechanics.Report) string {
	t.Helper()
	pre, err := attest.Preimage(rep)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	return pre
}
