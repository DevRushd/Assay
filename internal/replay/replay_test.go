package replay

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubTransport answers fixed responses and counts calls, so a test can
// assert both what was recorded and that nothing reached further than the
// stub.
type stubTransport struct {
	responses map[string]stubResponse
	calls     []string
}

type stubResponse struct {
	status      int
	contentType string
	body        string
	err         error
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.calls = append(s.calls, req.Method+" "+req.URL.String())
	r, ok := s.responses[req.Method+" "+req.URL.String()]
	if !ok {
		return nil, errors.New("stub: unexpected request " + req.Method + " " + req.URL.String())
	}
	if r.err != nil {
		return nil, r.err
	}
	h := http.Header{}
	if r.contentType != "" {
		h.Set("Content-Type", r.contentType)
	}
	return &http.Response{
		StatusCode: r.status,
		Status:     http.StatusText(r.status),
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Request:    req,
	}, nil
}

func mustRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

// doResult is what a caller may inspect once do() has consumed and closed
// the response. The concrete *http.Response never leaves the helper, so no
// caller can forget to close it.
type doResult struct {
	status int
	header http.Header
}

func do(t *testing.T, rt http.RoundTripper, url string) (doResult, string) {
	t.Helper()
	resp, err := rt.RoundTrip(mustRequest(t, url))
	if err != nil {
		t.Fatalf("RoundTrip(%s): %v", url, err)
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return doResult{status: resp.StatusCode, header: resp.Header}, string(b)
}

const (
	sourceURL   = "https://horizon.test/assets?x=1"
	sourceBody  = `{"_embedded":{"records":[{"asset_code":"USDC"}]}}`
	otherURL    = "https://horizon.test/accounts/GABC"
	otherBody   = `{"account_id":"GABC"}`
	contentType = "application/json; charset=utf-8"
)

func TestRecordThenReplayServesIdenticalResponses(t *testing.T) {
	dir := t.TempDir()
	stub := &stubTransport{responses: map[string]stubResponse{
		"GET " + sourceURL: {200, contentType, sourceBody, nil},
		"GET " + otherURL:  {200, contentType, otherBody, nil},
	}}

	rec, err := NewRecorder(dir, stub)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}

	// The caller must not be able to tell it is being recorded.
	resp, body := do(t, rec, sourceURL)
	if resp.status != 200 || body != sourceBody {
		t.Fatalf("recorded response altered: status=%d body=%q", resp.status, body)
	}
	if got := resp.header.Get("Content-Type"); got != contentType {
		t.Errorf("Content-Type = %q, want %q", got, contentType)
	}
	if _, body := do(t, rec, otherURL); body != otherBody {
		t.Fatalf("second recorded response altered: %q", body)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The replayer replaces the transport entirely; the stub below is the
	// only network that exists, and the replayer never sees it.
	rp, err := NewReplayer(dir)
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	resp, body = do(t, rp, sourceURL)
	if resp.status != 200 || body != sourceBody {
		t.Errorf("replayed response differs: status=%d body=%q", resp.status, body)
	}
	if got := resp.header.Get("Content-Type"); got != contentType {
		t.Errorf("replayed Content-Type = %q, want %q", got, contentType)
	}
	if _, body := do(t, rp, otherURL); body != otherBody {
		t.Errorf("second replayed response differs: %q", body)
	}
	if len(stub.calls) != 2 {
		t.Errorf("stub was called %d times, want exactly the 2 recording calls", len(stub.calls))
	}
}

// A recording that does not contain a request must fail loudly rather than
// fall through to the network: a replay that quietly reached live sources
// would turn into a live scan the moment a new fetch path appeared.
func TestReplayUnrecordedRequestFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	stub := &stubTransport{responses: map[string]stubResponse{
		"GET " + sourceURL: {200, contentType, sourceBody, nil},
	}}
	rec, err := NewRecorder(dir, stub)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	do(t, rec, sourceURL)
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rp, err := NewReplayer(dir)
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	resp, err := rp.RoundTrip(mustRequest(t, otherURL))
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("unrecorded request was served; replay must fail loudly")
	}
	if !strings.Contains(err.Error(), "unrecorded request") || !strings.Contains(err.Error(), otherURL) {
		t.Errorf("error does not name the request: %v", err)
	}
	if !strings.Contains(err.Error(), "refusing to reach the network") {
		t.Errorf("error does not state the refusal: %v", err)
	}
}

// The replayer is also exercised through a real http.Client, which is how
// the fetchers will use it: the client's Do must surface the loud failure
// and no transport underneath can exist.
func TestReplayThroughHTTPClientNeverTouchesNetwork(t *testing.T) {
	dir := t.TempDir()
	stub := &stubTransport{responses: map[string]stubResponse{
		"GET " + sourceURL: {200, contentType, sourceBody, nil},
	}}
	rec, err := NewRecorder(dir, stub)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	do(t, rec, sourceURL)
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rp, err := NewReplayer(dir)
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}

	client := &http.Client{Transport: rp}
	resp, err := client.Get(sourceURL)
	if err != nil {
		t.Fatalf("recorded request through http.Client: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp, err = client.Get("https://example.invalid/not-recorded")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "unrecorded request") {
		t.Fatalf("unrecorded request through http.Client: %v", err)
	}
}

// A transport error is not a response: nothing is cached, so a replay of a
// failed live scan fails loudly on the missing request instead of replaying
// the failure forever.
func TestRecorderDoesNotRecordTransportErrors(t *testing.T) {
	dir := t.TempDir()
	stub := &stubTransport{responses: map[string]stubResponse{
		"GET " + sourceURL: {0, "", "", errors.New("dial: connection refused")},
	}}
	rec, err := NewRecorder(dir, stub)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	resp, err := rec.RoundTrip(mustRequest(t, sourceURL))
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("RoundTrip should have failed")
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.Contains(string(raw), `"entries": []`) {
		t.Errorf("manifest should record nothing for a failed fetch:\n%s", raw)
	}
}

// Recording the same responses twice rewrites the same bytes: entries are
// sorted, so the recording diffs cleanly across runs.
func TestRecordingIsDeterministic(t *testing.T) {
	manifest := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		stub := &stubTransport{responses: map[string]stubResponse{
			"GET " + otherURL:  {200, contentType, otherBody, nil},
			"GET " + sourceURL: {200, contentType, sourceBody, nil},
		}}
		rec, err := NewRecorder(dir, stub)
		if err != nil {
			t.Fatalf("NewRecorder: %v", err)
		}
		do(t, rec, otherURL)
		do(t, rec, sourceURL)
		if err := rec.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
		if err != nil {
			t.Fatalf("read manifest: %v", err)
		}
		return string(raw)
	}
	if a, b := manifest(t), manifest(t); a != b {
		t.Errorf("manifests differ between identical recordings:\n--- first ---\n%s\n--- second ---\n%s", a, b)
	}
}

func TestReplayRefusesPartialOrForeignRecordings(t *testing.T) {
	t.Run("missing manifest", func(t *testing.T) {
		if _, err := NewReplayer(t.TempDir()); err == nil {
			t.Error("NewReplayer on an empty directory must fail")
		}
	})

	t.Run("missing body file", func(t *testing.T) {
		dir := t.TempDir()
		m := Manifest{
			Version: ManifestVersion,
			Entries: []Entry{{Method: "GET", URL: sourceURL, Status: 200, Body: "gone.body"}},
		}
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ManifestName), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := NewReplayer(dir); err == nil {
			t.Error("NewReplayer must refuse a recording whose body file is missing")
		}
	})

	t.Run("unknown manifest version", func(t *testing.T) {
		dir := t.TempDir()
		m := Manifest{Version: ManifestVersion + 1}
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ManifestName), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err = NewReplayer(dir)
		if err == nil || !strings.Contains(err.Error(), "manifest version") {
			t.Errorf("NewReplayer on a foreign version: %v", err)
		}
	})
}

// TestRecorderIsTransparentUnderHTTPServer exercises the recorder through a
// real HTTP round trip (headers, chunked bodies, trailers-free JSON) the way
// the fetchers will drive it.
func TestRecorderIsTransparentUnderHTTPServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(sourceBody))
	}))
	defer srv.Close()

	dir := t.TempDir()
	rec, err := NewRecorder(dir, nil) // nil inner: the default transport
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	client := &http.Client{Transport: rec}

	resp, err := client.Get(srv.URL + "/assets")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != sourceBody {
		t.Fatalf("body through recorder = %q", b)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The server is now closed; only the recording can answer.
	srv.Close()
	rp, err := NewReplayer(dir)
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	got, err := (&http.Client{Transport: rp}).Get(srv.URL + "/assets")
	if err != nil {
		t.Fatalf("replayed GET with the server closed: %v", err)
	}
	b, _ = io.ReadAll(got.Body)
	_ = got.Body.Close()
	if string(b) != sourceBody {
		t.Errorf("replayed body = %q, want %q", b, sourceBody)
	}
}
