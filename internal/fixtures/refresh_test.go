package fixtures_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/fixtures"
)

const (
	demoDate = "2026-01-01"
	// refreshed is the date the tests pin the capture to, so the assertion is
	// about behaviour rather than whatever day the suite happens to run.
	refreshed = "2026-02-02"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func provenanceDoc(baseURL string) string {
	return "# Fixture provenance\n\n" +
		"Captured " + demoDate + " from live public sources.\n\n" +
		"| file | source URL |\n" +
		"| --- | --- |\n" +
		"| `demo-subject/asset.json` | " + baseURL + "/assets?asset_code=AQUA&asset_issuer=GABC |\n" +
		"| `demo-subject/directory.json` | " + baseURL + "/directory/GABC |\n" +
		"| `other-subject/asset.json` | " + baseURL + "/other |\n"
}

const demoManifest = `{
  "schema_version": "1.0",
  "dataset": "test",
  "subjects": [
    {
      "fixture": "demo-subject",
      "asset": "AQUA-GABC",
      "capture_date": "` + demoDate + `",
      "source_urls": []
    }
  ]
}
`

// stagingRoot lays out a single-subject fixture root beside a stubbed source.
func stagingRoot(t *testing.T, baseURL, asset, directory string) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "PROVENANCE.md"), provenanceDoc(baseURL))
	writeFile(t, filepath.Join(root, "manifest.json"), demoManifest)
	writeFile(t, filepath.Join(root, "demo-subject", "asset.json"), asset)
	writeFile(t, filepath.Join(root, "demo-subject", "directory.json"), directory)
	return root
}

func fixedNow() time.Time {
	return time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC)
}

func TestRefreshWritesChangesAndUpdatesCaptureDate(t *testing.T) {
	oldAsset := "{\n  \"asset_code\": \"AQUA\",\n  \"flags\": {\n    \"auth_revocable\": false\n  }\n}\n"
	// Same entry as the committed file, differing only in key order and
	// whitespace: a semantic no-op must not produce a diff.
	oldDirectory := "{\"address\":\"GABC\",\"name\":\"Old\"}\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/assets"):
			// The flag moved: a real change the maintainer must review.
			_, _ = w.Write([]byte(`{"flags":{"auth_revocable":true},"asset_code":"AQUA"}`))
		case strings.HasPrefix(r.URL.Path, "/directory"):
			_, _ = w.Write([]byte(`{"name":"Old","address":"GABC"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	root := stagingRoot(t, srv.URL, oldAsset, oldDirectory)
	r := &fixtures.Refresher{
		Client: srv.Client(),
		Now:    fixedNow,
	}

	res, err := r.Refresh(context.Background(), root, "demo-subject", true)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if len(res.Changed) != 1 || res.Changed[0].File != "demo-subject/asset.json" {
		t.Fatalf("expected only asset.json to change, got %+v", res.Changed)
	}
	if !strings.Contains(fixtures.Unified(res.Changed[0].File, res.Changed[0].Old, res.Changed[0].New), "+") {
		t.Fatalf("diff did not show the change:\n%s", fixtures.Unified(res.Changed[0].File, res.Changed[0].Old, res.Changed[0].New))
	}

	// The rewritten file is JSON with the moved flag, in the committed layout.
	var got map[string]any
	b, err := os.ReadFile(filepath.Join(root, "demo-subject", "asset.json"))
	if err != nil {
		t.Fatalf("read refreshed asset.json: %v", err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("refreshed asset.json is not JSON: %v", err)
	}
	flags, _ := got["flags"].(map[string]any)
	if flags == nil || flags["auth_revocable"] != true {
		t.Fatalf("asset.json was not updated with the new flag: %s", b)
	}
	if !strings.Contains(string(b), "\n  ") {
		t.Fatalf("asset.json lost its indented layout:\n%s", b)
	}

	// A semantically unchanged file is not rewritten.
	dir, err := os.ReadFile(filepath.Join(root, "demo-subject", "directory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(dir) != oldDirectory {
		t.Fatalf("directory.json was rewritten for a no-op:\n%s", dir)
	}

	prov, err := os.ReadFile(filepath.Join(root, "PROVENANCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(prov), "(captured "+refreshed+")") != 2 {
		t.Fatalf("capture date not written on the subject's source lines:\n%s", prov)
	}
	if strings.Contains(string(prov), "other-subject/asset.json` | "+srv.URL+"/other (captured") {
		t.Fatalf("capture date leaked onto another subject:\n%s", prov)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifestBytes), `"capture_date": "`+refreshed+`"`) {
		t.Fatalf("manifest capture date not updated:\n%s", manifestBytes)
	}
}

func TestFailedFetchLeavesFixturesUntouched(t *testing.T) {
	oldAsset := "{\n  \"asset_code\": \"AQUA\"\n}\n"
	oldDirectory := "{\"address\":\"GABC\",\"name\":\"Old\"}\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets") {
			http.Error(w, "upstream is down", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"name":"Old","address":"GABC"}`))
	}))
	t.Cleanup(srv.Close)

	root := stagingRoot(t, srv.URL, oldAsset, oldDirectory)

	before := map[string]string{}
	for _, name := range []string{"PROVENANCE.md", "manifest.json", "demo-subject/asset.json", "demo-subject/directory.json"} {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = string(b)
	}

	r := &fixtures.Refresher{Client: srv.Client(), Now: fixedNow}
	res, err := r.Refresh(context.Background(), root, "demo-subject", true)
	if err == nil {
		t.Fatal("expected an unreachable source to fail the refresh")
	}
	if res != nil {
		t.Fatalf("a failed refresh returned a result: %+v", res)
	}

	// Nothing — not a fixture, not the metadata — may change.
	for name, want := range before {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(b) != want {
			t.Fatalf("%s was modified by a failed refresh:\n got: %q\nwant: %q", name, b, want)
		}
	}
}

func TestDryRunDoesNotWrite(t *testing.T) {
	oldAsset := "{\n  \"asset_code\": \"AQUA\"\n}\n"
	oldDirectory := "{\"address\":\"GABC\"}\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets") {
			_, _ = w.Write([]byte(`{"asset_code":"AQUA","changed":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"address":"GABC"}`))
	}))
	t.Cleanup(srv.Close)

	root := stagingRoot(t, srv.URL, oldAsset, oldDirectory)
	r := &fixtures.Refresher{Client: srv.Client(), Now: fixedNow}

	res, err := r.Refresh(context.Background(), root, "demo-subject", false)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(res.Changed) != 1 {
		t.Fatalf("dry run should still report the change, got %+v", res.Changed)
	}
	b, err := os.ReadFile(filepath.Join(root, "demo-subject", "asset.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != oldAsset {
		t.Fatalf("dry run wrote the fixture:\n%s", b)
	}
}

func TestParseProvenanceStripsAnnotations(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "PROVENANCE.md"),
		"| file | source URL |\n| --- | --- |\n"+
			"| `s/asset.json` | https://h/assets (captured 2026-09-25) |\n"+
			"| `s/stellar.toml.status` | https://h/toml (HTTP 404) |\n")

	srcs, err := fixtures.ParseProvenance(filepath.Join(dir, "PROVENANCE.md"))
	if err != nil {
		t.Fatalf("ParseProvenance: %v", err)
	}
	if len(srcs) != 2 {
		t.Fatalf("expected two sources, got %+v", srcs)
	}
	if srcs[0].URL != "https://h/assets" {
		t.Errorf("capture annotation not stripped: %q", srcs[0].URL)
	}
	if srcs[1].URL != "https://h/toml" {
		t.Errorf("HTTP annotation not stripped: %q", srcs[1].URL)
	}
}
