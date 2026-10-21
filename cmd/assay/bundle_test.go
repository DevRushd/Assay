package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/bundle"
)

func writeCLIBundle(t *testing.T) string {
	t.Helper()
	rep := testReport()
	params, err := attest.FromReport(rep)
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := bundle.Write(out, rep, params, ""); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return out
}

// rewriteBundle rebuilds an archive from the files bundle.Open exposes. It
// keeps the manifest untouched, so any change to a body is exactly the kind of
// tampering verifyBundle must detect.
func rewriteBundle(t *testing.T, path string, mutate func(map[string][]byte)) string {
	t.Helper()
	b, err := bundle.Open(path)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	files := make(map[string][]byte, len(b.Files))
	for name, body := range b.Files {
		files[name] = append([]byte(nil), body...)
	}
	mutate(files)

	out := filepath.Join(t.TempDir(), "rewritten.tar.gz")
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(files[name])), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("header %s: %v", name, err)
		}
		if _, err := tw.Write(files[name]); err != nil {
			t.Fatalf("body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return out
}

func TestVerifyBundleOffline(t *testing.T) {
	path := writeCLIBundle(t)
	var out bytes.Buffer
	code, err := verifyBundle(path, false, &out)
	if err != nil {
		t.Fatalf("verifyBundle: %v", err)
	}
	if code != exitSuccess {
		t.Fatalf("exit code = %d, want %d; output:\n%s", code, exitSuccess, out.String())
	}
	if !strings.HasPrefix(out.String(), "OK ") {
		t.Fatalf("output = %q, want an OK verdict", out.String())
	}
	if !strings.Contains(out.String(), attest.ScannerIdentity) {
		t.Errorf("output does not name the scanner: %s", out.String())
	}
}

func TestVerifyBundleJSON(t *testing.T) {
	path := writeCLIBundle(t)
	var out bytes.Buffer
	code, err := verifyBundle(path, true, &out)
	if err != nil {
		t.Fatalf("verifyBundle: %v", err)
	}
	if code != exitSuccess {
		t.Fatalf("exit code = %d, want %d", code, exitSuccess)
	}
	var v bundle.Verification
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if !v.OK || !v.DigestMatch || !v.ReportMatch || !v.ResponsesMatch {
		t.Fatalf("verification = %+v", v)
	}
}

func TestVerifyBundleDetectsTampering(t *testing.T) {
	path := writeCLIBundle(t)
	tampered := rewriteBundle(t, path, func(files map[string][]byte) {
		files[bundle.PreimageName] = append(files[bundle.PreimageName], []byte("extra\n")...)
	})

	var out bytes.Buffer
	code, err := verifyBundle(tampered, false, &out)
	if err != nil {
		t.Fatalf("verifyBundle: %v", err)
	}
	if code != exitMismatch {
		t.Fatalf("exit code = %d, want %d; output:\n%s", code, exitMismatch, out.String())
	}
	if !strings.HasPrefix(out.String(), "MISMATCH ") {
		t.Fatalf("output = %q, want a MISMATCH verdict", out.String())
	}
}

func TestVerifyBundleUnreadableIsNotAMismatch(t *testing.T) {
	var out bytes.Buffer
	code, err := verifyBundle(filepath.Join(t.TempDir(), "missing.tar.gz"), false, &out)
	if err == nil {
		t.Fatal("missing bundle verified without an error")
	}
	if code != exitUnverifiable {
		t.Fatalf("exit code = %d, want %d", code, exitUnverifiable)
	}
	if !strings.Contains(err.Error(), "verify bundle") {
		t.Fatalf("error = %v, want it to name the bundle", err)
	}
}
