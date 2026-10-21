// Package bundle writes and verifies an offline verification bundle: a
// tarball containing the exact source bytes behind one attestation, the
// preimage, the digest and the scanner identity.
//
// A re-scan answers two questions at once and cannot separate them: "was this
// hash honestly computed from that evidence" and "is that evidence still
// current". The first is a fact about the attestation and must remain true
// forever; the second is a fact about the issuer today and legitimately changes.
// A bundle preserves what was actually read, so a verifier can answer the first
// question offline, without a network and without a fresh scan (issue #465).
//
// The bundle is a gzip-compressed tar with a fixed layout:
//
//	manifest.json      format version, digests, scanner identity, response index
//	report.json        the report the attestation was derived from
//	preimage.txt       the exact bytes evidence_hash commits to
//	responses/<sha>.body  one raw upstream response body, named by its digest
//
// Bodies are named by SHA-256, so the same response fetched twice is stored
// once and a manifest entry cannot silently point at different bytes. Failed
// fetches have no response body; the report's attributed evidence records them,
// and the manifest notes that no body exists for them rather than inventing an
// empty one.
package bundle

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/replay"
)

// FormatVersion is the bundle layout version. A reader that does not recognize
// it refuses rather than guessing: a misread bundle is a silently wrong
// verification.
const FormatVersion = 1

// Fixed names inside a bundle.
const (
	ManifestName = "manifest.json"
	ReportName   = "report.json"
	PreimageName = "preimage.txt"
	ResponsesDir = "responses"
)

// maxBundleBytes bounds decompression, so a malicious or corrupt archive cannot
// exhaust memory. A real bundle is a handful of small JSON and HTML bodies.
const maxBundleBytes = 64 << 20

// Manifest is the index of a bundle. It names every file and binds each one by
// digest, so a verifier can tell a missing or altered file from a valid one.
type Manifest struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	// Asset is the CODE-ISSUER the report is about, repeated here so a verifier
	// can report it before parsing anything else.
	Asset string `json:"asset"`
	// Scanner is the identity the preimage binds under v4, or the identity of
	// the scanner that produced this bundle when the report's encoding is older.
	Scanner string `json:"scanner"`
	// Digest is the SHA-256 of preimage.txt, lowercase hex: the evidence_hash an
	// attestation of this bundle carries.
	Digest string `json:"digest"`
	// Preimage and Report are the paths inside the archive.
	Preimage string `json:"preimage"`
	Report   string `json:"report"`
	// ReportSHA256 binds the report document itself.
	ReportSHA256 string `json:"report_sha256"`
	// Responses is one entry per upstream response body that was read. A source
	// that failed has no body and therefore no entry; the report's evidence
	// records the failure.
	Responses []Response `json:"responses"`
	// Notes carries facts a verifier should know that are not failures, such as
	// a bundle with no response bodies because every source failed.
	Notes []string `json:"notes,omitempty"`
}

// Response is one archived upstream response.
type Response struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	RecordedAt  string `json:"recorded_at"`
}

// Write creates outPath from a completed report, the derived attestation
// params, and the replay recording directory the scan populated.
//
// The recording directory is what makes the bundle evidence rather than a
// summary: it is the same directory `assay scan -record` writes, so the bytes
// archived here are the bytes the checks decoded. A bundle with no recording is
// accepted only with an explanatory note; it is still useful as a signed record
// of the derived values, but it cannot prove what the sources said.
func Write(outPath string, rep *mechanics.Report, params attest.Params, recordingDir string) error {
	if outPath == "" {
		return errors.New("bundle: empty output path")
	}
	if rep == nil {
		return errors.New("bundle: nil report")
	}
	if params.Preimage == "" {
		return errors.New("bundle: attestation has no preimage to archive")
	}
	digest, err := attest.NormalizeEvidenceHash(params.EvidenceHash)
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if got := attest.HashPreimage([]byte(params.Preimage)); got != digest {
		return fmt.Errorf("bundle: preimage hashes to %s but the attestation claims %s", got, digest)
	}

	reportBytes, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("bundle: encode report: %w", err)
	}
	reportBytes = append(reportBytes, '\n')

	man := Manifest{
		Version:      FormatVersion,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Asset:        rep.Asset.String(),
		Scanner:      attest.ScannerIdentity,
		Digest:       digest,
		Preimage:     PreimageName,
		Report:       ReportName,
		ReportSHA256: hashBytes(reportBytes),
	}

	files := map[string][]byte{
		ManifestName: nil, // written last, after the response index is complete
		ReportName:   reportBytes,
		PreimageName: []byte(params.Preimage),
	}

	man.Responses, files, err = collectResponses(recordingDir, files, man.Responses)
	if err != nil {
		return err
	}
	if len(man.Responses) == 0 {
		man.Notes = append(man.Notes,
			"no upstream response bodies were archived; the report records fetch failures or the scan was not recorded")
	}

	mb, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return fmt.Errorf("bundle: encode manifest: %w", err)
	}
	files[ManifestName] = append(mb, '\n')

	return writeArchive(outPath, files)
}

// collectResponses copies every recorded body into the bundle under its digest.
// It returns the manifest entries and the augmented file map. Re-recording the
// same URL replaces the earlier entry, matching replay.Recorder's own
// last-write-wins behavior.
func collectResponses(dir string, files map[string][]byte, entries []Response) ([]Response, map[string][]byte, error) {
	if dir == "" {
		return entries, files, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, replay.ManifestName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return entries, files, nil
		}
		return nil, nil, fmt.Errorf("bundle: read recording manifest: %w", err)
	}
	var rec replay.Manifest
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, nil, fmt.Errorf("bundle: decode recording manifest: %w", err)
	}
	if rec.Version != replay.ManifestVersion {
		return nil, nil, fmt.Errorf("bundle: recording version %d, this build reads %d",
			rec.Version, replay.ManifestVersion)
	}

	index := make(map[string]int, len(entries))
	for i, e := range entries {
		index[replayKey(e.Method, e.URL)] = i
	}
	for _, e := range rec.Entries {
		body, err := os.ReadFile(filepath.Join(dir, e.Body))
		if err != nil {
			return nil, nil, fmt.Errorf("bundle: read recorded body for %s %s: %w", e.Method, e.URL, err)
		}
		sum := hashBytes(body)
		path := ResponsesDir + "/" + sum + ".body"
		files[path] = body
		resp := Response{
			Method:      e.Method,
			URL:         e.URL,
			Status:      e.Status,
			ContentType: e.ContentType,
			Path:        path,
			SHA256:      sum,
			RecordedAt:  e.RecordedAt,
		}
		if i, ok := index[replayKey(e.Method, e.URL)]; ok {
			entries[i] = resp
		} else {
			index[replayKey(e.Method, e.URL)] = len(entries)
			entries = append(entries, resp)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].URL != entries[j].URL {
			return entries[i].URL < entries[j].URL
		}
		return entries[i].Method < entries[j].Method
	})
	return entries, files, nil
}

func replayKey(method, url string) string { return method + " " + url }

// writeArchive writes a deterministic tar.gz: files are sorted by name, modes
// and modification times are fixed, and the gzip header carries no filename or
// timestamp. Two bundles made from identical inputs therefore differ only if
// their manifests differ, which makes review diffs meaningful.
func writeArchive(outPath string, files map[string][]byte) error {
	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("bundle: create output directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".assay-bundle-*")
	if err != nil {
		return fmt.Errorf("bundle: create temporary archive: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	gz := gzip.NewWriter(tmp)
	gz.ModTime = time.Unix(0, 0)
	tw := tar.NewWriter(gz)

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b := files[name]
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(b)),
			ModTime:  time.Unix(0, 0),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("bundle: write header for %s: %w", name, err)
		}
		if _, err := tw.Write(b); err != nil {
			return fmt.Errorf("bundle: write %s: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("bundle: close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("bundle: close gzip: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("bundle: close archive: %w", err)
	}
	if err := os.Rename(tmpName, outPath); err != nil {
		return fmt.Errorf("bundle: publish archive: %w", err)
	}
	return nil
}

// Bundle is a parsed archive held in memory.
type Bundle struct {
	Manifest Manifest
	Report   *mechanics.Report
	Preimage []byte
	Files    map[string][]byte
}

// Open reads a bundle. Every manifest-named file must exist; a partial bundle
// is refused rather than half-verified.
func Open(path string) (*Bundle, error) {
	files, err := readArchive(path)
	if err != nil {
		return nil, err
	}
	rawMan, ok := files[ManifestName]
	if !ok {
		return nil, fmt.Errorf("bundle: %s is missing %s", path, ManifestName)
	}
	var man Manifest
	if err := json.Unmarshal(rawMan, &man); err != nil {
		return nil, fmt.Errorf("bundle: decode manifest: %w", err)
	}
	if man.Version != FormatVersion {
		return nil, fmt.Errorf("bundle: manifest version %d, this build reads %d", man.Version, FormatVersion)
	}
	if man.Preimage == "" || man.Report == "" {
		return nil, fmt.Errorf("bundle: manifest does not name both the preimage and the report")
	}
	pre, ok := files[man.Preimage]
	if !ok {
		return nil, fmt.Errorf("bundle: manifest names %s but the archive has no such file", man.Preimage)
	}
	rawReport, ok := files[man.Report]
	if !ok {
		return nil, fmt.Errorf("bundle: manifest names %s but the archive has no such file", man.Report)
	}
	var rep mechanics.Report
	if err := json.Unmarshal(rawReport, &rep); err != nil {
		return nil, fmt.Errorf("bundle: decode report: %w", err)
	}
	return &Bundle{Manifest: man, Report: &rep, Preimage: pre, Files: files}, nil
}

// readArchive loads a tar.gz into memory with a total size bound and refuses
// absolute or parent-relative paths, so extracting a malicious archive cannot
// escape a directory (the verifier never extracts, but the rule is enforced at
// the read boundary rather than at each future caller).
func readArchive(path string) (map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("bundle: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("bundle: %s is not a gzip archive: %w", path, err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)

	files := map[string][]byte{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: read archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.ToSlash(hdr.Name)
		if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
			return nil, fmt.Errorf("bundle: archive contains unsafe path %q", hdr.Name)
		}
		if hdr.Size > maxBundleBytes-total {
			return nil, fmt.Errorf("bundle: archive exceeds %d bytes", maxBundleBytes)
		}
		b, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return nil, fmt.Errorf("bundle: read %s: %w", name, err)
		}
		total += int64(len(b))
		files[name] = b
	}
	return files, nil
}

// Verification is the offline verdict for one bundle.
type Verification struct {
	OK             bool   `json:"ok"`
	Asset          string `json:"asset"`
	Digest         string `json:"digest"`
	ComputedDigest string `json:"computed_digest"`
	DigestMatch    bool   `json:"digest_match"`
	ReportMatch    bool   `json:"report_match"`
	ResponsesMatch bool   `json:"responses_match"`
	Scanner        string `json:"scanner"`
	// Preimage describes the encoding and the fields the archived bytes bind.
	Preimage attest.PreimageInfo `json:"preimage"`
	// Errors names every failed check. Empty means OK.
	Errors []string `json:"errors,omitempty"`
	// Notes are non-failures, such as a v1 preimage that binds no check set.
	Notes []string `json:"notes,omitempty"`
}

// Verify recomputes the digest from the archived preimage and checks every
// file the manifest binds. It touches no network and runs no scan: the bytes
// that produced the hash are in the bundle.
func (b *Bundle) Verify() Verification {
	v := Verification{
		Asset:   b.Manifest.Asset,
		Scanner: b.Manifest.Scanner,
		Digest:  b.Manifest.Digest,
	}
	fail := func(format string, args ...any) {
		v.Errors = append(v.Errors, fmt.Sprintf(format, args...))
	}

	want, err := attest.NormalizeEvidenceHash(b.Manifest.Digest)
	if err != nil {
		fail("manifest digest: %v", err)
	} else {
		v.Digest = want
	}
	v.ComputedDigest = attest.HashPreimage(b.Preimage)
	v.DigestMatch = want != "" && v.ComputedDigest == want
	if !v.DigestMatch {
		fail("preimage hashes to %s, manifest claims %s", v.ComputedDigest, b.Manifest.Digest)
	}

	rawReport, ok := b.Files[b.Manifest.Report]
	if !ok {
		fail("manifest names report %q but the archive has no such file", b.Manifest.Report)
	} else {
		v.ReportMatch = hashBytes(rawReport) == b.Manifest.ReportSHA256
		if !v.ReportMatch {
			fail("report hash does not match the manifest")
		}
	}

	v.ResponsesMatch = true
	for _, r := range b.Manifest.Responses {
		body, ok := b.Files[r.Path]
		if !ok {
			v.ResponsesMatch = false
			fail("response %s %s names %q but the archive has no such file", r.Method, r.URL, r.Path)
			continue
		}
		if got := hashBytes(body); got != r.SHA256 {
			v.ResponsesMatch = false
			fail("response %s %s hashes to %s, manifest claims %s", r.Method, r.URL, got, r.SHA256)
		}
	}

	info, err := attest.ParsePreimage(b.Preimage)
	if err != nil {
		fail("preimage header: %v", err)
	} else {
		v.Preimage = info
		if b.Manifest.Asset != "" && info.Asset != b.Manifest.Asset {
			fail("preimage is for %s, manifest claims %s", info.Asset, b.Manifest.Asset)
		}
		if info.Version == attest.PreimageVersion {
			v.Notes = append(v.Notes,
				"preimage is v1: it binds no check set, so check-set completeness is unknown")
		}
	}

	if b.Report != nil {
		if err := b.checkReportAgainstPreimage(); err != nil {
			fail("report and preimage disagree: %v", err)
		}
	}

	v.OK = len(v.Errors) == 0
	return v
}

// checkReportAgainstPreimage cross-checks the fields both documents carry. The
// digest check alone proves the preimage is intact; this catches a bundle whose
// report was swapped for one describing different evidence while leaving the
// preimage untouched.
func (b *Bundle) checkReportAgainstPreimage() error {
	lines := strings.Split(strings.TrimSuffix(string(b.Preimage), "\n"), "\n")
	fields := map[string]string{}
	for _, line := range lines[1:] {
		key, val, ok := strings.Cut(line, "\t")
		if !ok || key == "evidence" || key == "scanner" {
			continue
		}
		fields[key] = val
	}
	rep := b.Report
	if got := rep.Asset.String(); fields["asset"] != got {
		return fmt.Errorf("asset %q vs %q", got, fields["asset"])
	}
	if got := fmt.Sprintf("%d", uint32(rep.Severity)); fields["severity"] != got {
		return fmt.Errorf("severity %s vs %s", got, fields["severity"])
	}
	if got := fmt.Sprintf("%d", uint32(rep.Base)); fields["base_severity"] != got {
		return fmt.Errorf("base_severity %s vs %s", got, fields["base_severity"])
	}
	if got := string(rep.Accountability); fields["accountability"] != got {
		return fmt.Errorf("accountability %q vs %q", got, fields["accountability"])
	}
	m, err := mechanics.ParseMechanicNames(rep.MechanicNames)
	if err != nil {
		return fmt.Errorf("bundle: manifest mechanics: %w", err)
	}
	if got := fmt.Sprintf("%d", uint32(m)); fields["mechanics"] != got {
		return fmt.Errorf("mechanics %s vs %s", got, fields["mechanics"])
	}
	if _, ok := fields["checks"]; ok {
		checks := append([]string(nil), rep.CheckSet...)
		sort.Strings(checks)
		if got := strings.Join(checks, ","); fields["checks"] != got {
			return fmt.Errorf("checks %q vs %q", got, fields["checks"])
		}
	}
	if _, ok := fields["network"]; ok {
		if got := string(rep.Network); fields["network"] != got {
			return fmt.Errorf("network %q vs %q", got, fields["network"])
		}
	}
	return nil
}

// VerifyFile opens and verifies a bundle in one step.
func VerifyFile(path string) (Verification, error) {
	b, err := Open(path)
	if err != nil {
		return Verification{}, err
	}
	return b.Verify(), nil
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
