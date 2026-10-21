package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/replay"
)

func testReport() *mechanics.Report {
	return &mechanics.Report{
		SchemaVersion:  mechanics.ReportSchemaVersion,
		Asset:          mechanics.Asset{Code: "USDC", Issuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"},
		Severity:       mechanics.Medium,
		Base:           mechanics.Medium,
		Accountability: mechanics.AccountabilityVerified,
		CheckSet:       []string{"capability", "mutability", "reputation", "sep1-domain"},
		Network:        "Test SDF Network ; September 2015",
		ScannerBound:   true,
		Mechanics:      mechanics.MechAuthRevocable | mechanics.MechDomainUnverified,
		MechanicNames:  (mechanics.MechAuthRevocable | mechanics.MechDomainUnverified).Names(),
		Evidence: []mechanics.Evidence{
			{
				Source:      "horizon",
				URL:         "https://horizon.stellar.org/assets?asset_code=USDC",
				Claim:       "issuer flags: auth_required=false auth_revocable=true auth_immutable=false auth_clawback_enabled=false",
				RetrievedAt: mechanics.NewCanonicalTime(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)),
			},
		},
		ScannedAt: mechanics.NewCanonicalTime(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)),
	}
}

// recording builds a replay recording directory with one captured response.
func recording(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	body := []byte(`{"asset_code":"USDC"}`)
	if err := os.WriteFile(filepath.Join(dir, "body0.body"), body, 0o644); err != nil {
		t.Fatalf("write body: %v", err)
	}
	m := replay.Manifest{
		Version:    replay.ManifestVersion,
		RecordedAt: "2026-09-27T12:00:00Z",
		Entries: []replay.Entry{{
			Method:      "GET",
			URL:         "https://horizon.stellar.org/assets?asset_code=USDC",
			Status:      200,
			ContentType: "application/json",
			Body:        "body0.body",
			RecordedAt:  "2026-09-27T12:00:00Z",
		}},
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("encode recording manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, replay.ManifestName), b, 0o644); err != nil {
		t.Fatalf("write recording manifest: %v", err)
	}
	return dir
}

func writeTestBundle(t *testing.T) (string, *mechanics.Report, attest.Params) {
	t.Helper()
	rep := testReport()
	params, err := attest.FromReport(rep)
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	out := filepath.Join(t.TempDir(), "attestation.tar.gz")
	if err := Write(out, rep, params, recording(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return out, rep, params
}

func TestBundleVerifiesOffline(t *testing.T) {
	out, _, params := writeTestBundle(t)

	v, err := VerifyFile(out)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if !v.OK {
		t.Fatalf("bundle did not verify: %v", v.Errors)
	}
	if !v.DigestMatch || v.ComputedDigest != params.EvidenceHash {
		t.Fatalf("digest = %s, want %s", v.ComputedDigest, params.EvidenceHash)
	}
	if !v.ReportMatch || !v.ResponsesMatch {
		t.Fatalf("report/responses did not match: %+v", v)
	}
	if v.Preimage.Version != attest.PreimageVersionScanner {
		t.Errorf("preimage version = %s, want %s", v.Preimage.Version, attest.PreimageVersionScanner)
	}
	if v.Scanner != attest.ScannerIdentity {
		t.Errorf("scanner = %q, want %q", v.Scanner, attest.ScannerIdentity)
	}
}

func TestBundleWithoutRecordingCarriesANote(t *testing.T) {
	rep := testReport()
	params, err := attest.FromReport(rep)
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := Write(out, rep, params, ""); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, err := Open(out)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(b.Manifest.Responses) != 0 {
		t.Fatalf("responses = %d, want 0", len(b.Manifest.Responses))
	}
	if len(b.Manifest.Notes) == 0 {
		t.Fatal("no note explains why the bundle has no response bodies")
	}
	if v := b.Verify(); !v.OK {
		t.Fatalf("bundle did not verify: %v", v.Errors)
	}
}

func TestBundleDetectsTamperedPreimage(t *testing.T) {
	out, _, _ := writeTestBundle(t)
	b, err := Open(out)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	b.Preimage = append([]byte(nil), b.Preimage...)
	b.Preimage = []byte(strings.Replace(string(b.Preimage), "auth_revocable", "auth_required", 1))
	v := b.Verify()
	if v.OK || v.DigestMatch {
		t.Fatalf("tampered preimage verified: %+v", v)
	}
}

func TestBundleDetectsTamperedReport(t *testing.T) {
	out, _, _ := writeTestBundle(t)
	b, err := Open(out)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	b.Files[b.Manifest.Report] = append([]byte(nil), b.Files[b.Manifest.Report]...)
	b.Files[b.Manifest.Report] = []byte(strings.Replace(string(b.Files[b.Manifest.Report]), `"medium"`, `"high"`, 1))
	v := b.Verify()
	if v.OK || v.ReportMatch {
		t.Fatalf("tampered report verified: %+v", v)
	}
}

func TestBundleDetectsTamperedResponseBody(t *testing.T) {
	out, _, _ := writeTestBundle(t)
	b, err := Open(out)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(b.Manifest.Responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(b.Manifest.Responses))
	}
	path := b.Manifest.Responses[0].Path
	b.Files[path] = []byte("different bytes")
	v := b.Verify()
	if v.OK || v.ResponsesMatch {
		t.Fatalf("tampered response verified: %+v", v)
	}
}

func TestBundleRejectsUnknownFormatVersion(t *testing.T) {
	out, rep, params := writeTestBundle(t)
	// Rebuild the archive with a manifest this build must refuse.
	b, err := Open(out)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	b.Manifest.Version = FormatVersion + 1
	mb, err := json.MarshalIndent(b.Manifest, "", "  ")
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	files := map[string][]byte{
		ManifestName: append(mb, '\n'),
		ReportName:   b.Files[ReportName],
		PreimageName: b.Files[PreimageName],
	}
	for k, v := range b.Files {
		if strings.HasPrefix(k, ResponsesDir+"/") {
			files[k] = v
		}
	}
	bad := filepath.Join(t.TempDir(), "bad.tar.gz")
	if err := writeArchive(bad, files); err != nil {
		t.Fatalf("writeArchive: %v", err)
	}
	if _, err := Open(bad); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("Open error = %v, want a version refusal", err)
	}
	_ = rep
	_ = params
}
