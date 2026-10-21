package fixtures

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A refresh rewrites manifest.json through updateManifestCaptureDate. It has to
// reproduce the file byte for byte when only the date it already carries is
// written, or every refresh would show a whole-file diff that buries the one
// value that moved.
func TestUpdateManifestCaptureDatePreservesLayout(t *testing.T) {
	src := filepath.Join("..", "mechanics", "testdata", "manifest.json")
	original, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(dst, original, 0o644); err != nil {
		t.Fatal(err)
	}

	// doge-noflags-scam was captured on this date; re-writing it must not move
	// any other byte.
	date := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	if err := updateManifestCaptureDate(dst, "doge-noflags-scam", date); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("manifest layout moved:\n%s", Unified("manifest.json", original, got))
	}
}

func TestUpdateManifestCaptureDateChangesOneSubject(t *testing.T) {
	src := filepath.Join("..", "mechanics", "testdata", "manifest.json")
	original, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(dst, original, 0o644); err != nil {
		t.Fatal(err)
	}

	date := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	if err := updateManifestCaptureDate(dst, "aqua-clear-verified", date); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"fixture": "aqua-clear-verified"`) {
		t.Fatalf("subject fields were lost:\n%s", got)
	}
	// The named subject moved to the new date while the rest are untouched.
	if moved := strings.Count(string(got), `"capture_date": "2026-12-31"`); moved != 1 {
		t.Fatalf("expected exactly one capture_date to move, got %d:\n%s", moved, got)
	}
	if !strings.Contains(string(got), `"capture_date": "2026-08-10"`) {
		t.Fatalf("other capture dates were changed:\n%s", got)
	}
	// A URL carrying "&" must survive the rewrite unescaped.
	if !strings.Contains(string(got), "asset_code=AQUA&asset_issuer=") {
		t.Fatalf("source URL was HTML-escaped:\n%s", got)
	}
}

func TestUpdateManifestCaptureDateRejectsUnknownSubject(t *testing.T) {
	src := filepath.Join("..", "mechanics", "testdata", "manifest.json")
	original, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(dst, original, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := updateManifestCaptureDate(dst, "not-a-subject", time.Now()); err == nil {
		t.Fatal("expected an unknown subject to be an error rather than a no-op")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatal("a rejected update still modified the manifest")
	}
}
