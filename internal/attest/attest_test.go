package attest_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/mechanics"
)

// report builds a minimal Report without running the engine, so these tests
// exercise the encoding rather than the classifiers.
func report(mut func(*mechanics.Report)) *mechanics.Report {
	rep := &mechanics.Report{
		Asset:          mechanics.Asset{Code: "AQUA", Issuer: "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"},
		Severity:       mechanics.Clear,
		Base:           mechanics.Clear,
		Accountability: mechanics.AccountabilityVerified,
		ScannedAt:      mechanics.NewCanonicalTime(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)),
		Evidence: []mechanics.Evidence{{
			Source:      "horizon",
			URL:         "https://horizon.stellar.org/assets?asset_code=AQUA",
			Claim:       "issuer flags: auth_required=false",
			RetrievedAt: mechanics.NewCanonicalTime(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)),
		}},
	}
	if mut != nil {
		mut(rep)
	}
	return rep
}

// The encoding in docs/contract-interface.md is a promise to verifiers: the
// hash is only re-derivable if the byte format is exactly what is documented.
// The expected preimage below is assembled from the documented rules rather
// than from the code under test, so any divergence between the documentation
// and the code fails here instead of silently breaking reproducibility for
// everyone who re-scans.
//
// The claim under test carries every escapable byte (backslash, tab, newline,
// CR), and the two evidence lines must come out in sorted order
// ("horizon" < "stellar.expert/directory").
func TestPreimageMatchesTheDocumentedEncoding(t *testing.T) {
	nl, tab, cr, bs := "\n", "\t", "\r", "\\"

	// A claim containing all four escapable bytes.
	raw := strings.Join([]string{
		"issuer flags: auth_required=false",
		"second" + tab + "line" + bs + "with" + bs + "backslash" + cr + "end",
	}, nl)

	// The escaping the documentation specifies, applied by hand rather than by
	// calling into the code under test. Backslash first, then the remaining
	// three — the order matters, or the escapes introduced below would
	// themselves be escaped.
	escaped := strings.ReplaceAll(raw, bs, bs+bs)
	escaped = strings.ReplaceAll(escaped, nl, bs+"n")
	escaped = strings.ReplaceAll(escaped, tab, bs+"t")
	escaped = strings.ReplaceAll(escaped, cr, bs+"r")

	rep := report(nil)
	rep.Evidence = []mechanics.Evidence{
		{
			Source: "stellar.expert/directory",
			URL:    "https://api.stellar.expert/explorer/directory/" + rep.Asset.Issuer,
			Claim:  `listed as "AQUA Issuer" on aqua.network`,
		},
		{
			Source: "horizon",
			URL:    "https://horizon.stellar.org/assets?asset_code=AQUA",
			Claim:  raw,
		},
	}

	params, err := attest.FromReport(rep)
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}

	// Assembled from the format table in docs/contract-interface.md.
	want := strings.Join([]string{
		"assay-evidence-v1",
		"asset\t" + rep.Asset.String(),
		"severity\t0",
		"base_severity\t0",
		"escalated\tfalse",
		"mechanics\t0",
		"accountability\tverified",
		"checks\t",
		// Evidence lines sorted bytewise: horizon before stellar.expert.
		"evidence\thorizon\thttps://horizon.stellar.org/assets?asset_code=AQUA\t" + escaped,
		"evidence\tstellar.expert/directory\thttps://api.stellar.expert/explorer/directory/" + rep.Asset.Issuer + "\t" + `listed as "AQUA Issuer" on aqua.network`,
	}, nl) + nl

	if params.Preimage != want {
		t.Fatalf("preimage diverged from the documented encoding\n got: %q\nwant: %q", params.Preimage, want)
	}

	sum := sha256.Sum256([]byte(want))
	if got := hex.EncodeToString(sum[:]); got != params.EvidenceHash {
		t.Fatalf("evidence_hash is not sha256 of the documented preimage: got %s, want %s", params.EvidenceHash, got)
	}
}

func TestPreimageIsStable(t *testing.T) {
	a, err := attest.FromReport(report(nil))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	b, err := attest.FromReport(report(nil))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	if a.EvidenceHash != b.EvidenceHash {
		t.Fatalf("hash not deterministic: %s != %s", a.EvidenceHash, b.EvidenceHash)
	}
	if len(a.EvidenceHash) != 64 {
		t.Fatalf("evidence hash is not 32 bytes of hex: %q", a.EvidenceHash)
	}
	if !strings.HasPrefix(a.Preimage, attest.PreimageVersion+"\n") {
		t.Fatalf("preimage does not start with the version line: %q", a.Preimage)
	}
}

// Retrieval time is deliberately outside the hash, so re-scanning unchanged
// evidence reproduces the attestation. If that ever stops being true the field
// becomes unverifiable by anyone who was not present for the original fetch.
func TestRetrievalTimeDoesNotChangeTheHash(t *testing.T) {
	base, err := attest.FromReport(report(nil))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	later, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.ScannedAt = mechanics.NewCanonicalTime(r.ScannedAt.Time().Add(72 * time.Hour))
		r.Evidence[0].RetrievedAt = mechanics.NewCanonicalTime(r.Evidence[0].RetrievedAt.Time().Add(72 * time.Hour))
	}))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	if base.EvidenceHash != later.EvidenceHash {
		t.Fatalf("retrieval time changed the hash: %s != %s", base.EvidenceHash, later.EvidenceHash)
	}
}

// Every field that a gate could act on has to move the hash, or the hash does
// not actually commit to the attestation.
func TestMaterialChangesMoveTheHash(t *testing.T) {
	base, err := attest.FromReport(report(nil))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}

	cases := map[string]func(*mechanics.Report){
		"severity": func(r *mechanics.Report) {
			r.Severity, r.Base = mechanics.Medium, mechanics.Medium
		},
		"escalated": func(r *mechanics.Report) {
			r.Severity, r.Escalated = mechanics.Critical, true
		},
		"mechanics": func(r *mechanics.Report) {
			r.Mechanics = mechanics.MechAuthRequired
			r.Severity, r.Base = mechanics.Low, mechanics.Low
		},
		"accountability": func(r *mechanics.Report) {
			r.Accountability = mechanics.AccountabilityUnverified
		},
		"asset": func(r *mechanics.Report) { r.Asset.Code = "AQUA2" },
		"evidence claim": func(r *mechanics.Report) {
			r.Evidence[0].Claim = "issuer flags: auth_required=true"
		},
		"evidence source": func(r *mechanics.Report) { r.Evidence[0].Source = "elsewhere" },
		"extra evidence": func(r *mechanics.Report) {
			r.Evidence = append(r.Evidence, mechanics.Evidence{Source: "stellar.expert", Claim: "listed"})
		},
	}

	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := attest.FromReport(report(mut))
			if err != nil {
				t.Fatalf("FromReport: %v", err)
			}
			if got.EvidenceHash == base.EvidenceHash {
				t.Fatalf("changing %s did not change the hash", name)
			}
		})
	}
}

// Evidence order is an engine detail; two reports carrying the same claims must
// attest to the same bytes.
func TestEvidenceOrderDoesNotChangeTheHash(t *testing.T) {
	second := mechanics.Evidence{Source: "stellar.expert/directory", URL: "https://api.stellar.expert/x", Claim: "listed"}

	forward, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Evidence = append(r.Evidence, second)
	}))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	reversed, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Evidence = append([]mechanics.Evidence{second}, r.Evidence...)
	}))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	if forward.EvidenceHash != reversed.EvidenceHash {
		t.Fatalf("evidence order changed the hash: %s != %s", forward.EvidenceHash, reversed.EvidenceHash)
	}
}

func TestVerifyHashReportsMatchMismatchAndUnknown(t *testing.T) {
	base, err := attest.FromReport(report(nil))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	if got := attest.VerifyHash(report(nil), base.EvidenceHash); got.Status != attest.HashMatched {
		t.Fatalf("VerifyHash: status = %q, want %q", got.Status, attest.HashMatched)
	}

	mutations := map[string]func(*mechanics.Report){
		"severity":  func(r *mechanics.Report) { r.Severity, r.Base = mechanics.Medium, mechanics.Medium },
		"escalated": func(r *mechanics.Report) { r.Severity, r.Escalated = mechanics.Critical, true },
		"mechanics": func(r *mechanics.Report) {
			r.Mechanics = mechanics.MechAuthRequired
			r.Severity, r.Base = mechanics.Low, mechanics.Low
		},
		"accountability": func(r *mechanics.Report) { r.Accountability = mechanics.AccountabilityUnverified },
		"claim":          func(r *mechanics.Report) { r.Evidence[0].Claim = "issuer flags: auth_required=true" },
		"source":         func(r *mechanics.Report) { r.Evidence[0].Source = "elsewhere" },
		"evidence line": func(r *mechanics.Report) {
			r.Evidence = append(r.Evidence, mechanics.Evidence{Source: "stellar.expert", Claim: "listed"})
		},
	}
	for name, mut := range mutations {
		t.Run(name, func(t *testing.T) {
			got := attest.VerifyHash(report(mut), base.EvidenceHash)
			if got.Status != attest.HashMismatch {
				t.Fatalf("VerifyHash: status = %q, want %q for %s", got.Status, attest.HashMismatch, name)
			}
		})
	}

	// Reordered evidence is canonicalised, so it must not be reported as a
	// tampering event.
	second := mechanics.Evidence{Source: "stellar.expert/directory", URL: "https://api.stellar.expert/x", Claim: "listed"}
	forward, err := attest.FromReport(report(func(r *mechanics.Report) { r.Evidence = append(r.Evidence, second) }))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	reversed, err := attest.FromReport(report(func(r *mechanics.Report) { r.Evidence = append([]mechanics.Evidence{second}, r.Evidence...) }))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	if got := attest.VerifyHash(report(func(r *mechanics.Report) { r.Evidence = append(r.Evidence, second) }), forward.EvidenceHash); got.Status != attest.HashMatched {
		t.Fatalf("VerifyHash: reordered evidence should still match: status = %q", got.Status)
	}
	if got := attest.VerifyHash(report(func(r *mechanics.Report) { r.Evidence = append([]mechanics.Evidence{second}, r.Evidence...) }), reversed.EvidenceHash); got.Status != attest.HashMatched {
		t.Fatalf("VerifyHash: reordered evidence should still match: status = %q", got.Status)
	}

	undetermined := report(func(r *mechanics.Report) {
		r.Undetermined = true
		r.UndeterminedChecks = []string{"reputation"}
	})
	if got := attest.VerifyHash(undetermined, base.EvidenceHash); got.Status != attest.HashUnknown {
		t.Fatalf("VerifyHash: undetermined report should be unknown, got %q", got.Status)
	}
}

// A claim carries third-party text, so an issuer controls part of the preimage.
// Without escaping, a crafted directory name could impersonate a separate
// evidence line and forge the preimage of a report that was never produced.
func TestSeparatorsInClaimsCannotForgeALine(t *testing.T) {
	crafted, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Evidence[0].Claim = "benign\nevidence\thorizon\thttps://evil\tissuer flags: none"
	}))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	if strings.Contains(crafted.Preimage, "\nevidence\thorizon\thttps://evil") {
		t.Fatalf("a claim injected a forged evidence line:\n%s", crafted.Preimage)
	}
	// Version, seven header fields, one evidence line: the crafted claim must not
	// have bought itself an extra record.
	if lines := strings.Count(crafted.Preimage, "\n"); lines != 9 {
		t.Fatalf("expected 9 preimage lines, got %d:\n%s", lines, crafted.Preimage)
	}
}

// The contract rejects this at write time. Catching it before submission means
// an engine bug costs a scan rather than a transaction.
func TestConfiscationInvariantIsRefusedBeforeSubmission(t *testing.T) {
	_, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Mechanics = mechanics.MechClawbackEnabled
		r.Severity, r.Base = mechanics.Medium, mechanics.Medium
	}))
	if err == nil {
		t.Fatal("expected an inconsistent attestation to be refused")
	}
}

// The bit positions and severity numbers are contract ABI; a renumbering on the
// Go side would silently write wrong attestations on-chain.
func TestABIValuesMatchTheContract(t *testing.T) {
	params, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Mechanics = mechanics.MechAuthRevocable | mechanics.MechClawbackEnabled
		r.Severity, r.Base = mechanics.High, mechanics.High
	}))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	if params.Severity != 3 {
		t.Fatalf("SEVERITY_HIGH must be 3 on-chain, got %d", params.Severity)
	}
	if params.Flags != 0b110 {
		t.Fatalf("auth_revocable|clawback must be 0b110, got %#b", params.Flags)
	}
}

// A partial scan must not reach the chain. On-chain there is nowhere to put the
// caveat: get_safety returns a severity and a timestamp, so a level derived
// from half the evidence is indistinguishable to every downstream gate from one
// derived from all of it.
func TestUndeterminedReportIsRefused(t *testing.T) {
	_, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Undetermined = true
		r.UndeterminedChecks = []string{"reputation"}
	}))
	if err == nil {
		t.Fatal("expected an undetermined report to be refused")
	}
	if !errors.Is(err, attest.ErrUndetermined) {
		t.Fatalf("expected ErrUndetermined, got %v", err)
	}
	// The error has to say which axis is missing, or an operator cannot tell a
	// transient outage from a misconfiguration.
	if !strings.Contains(err.Error(), "reputation") {
		t.Errorf("error does not name the incomplete check: %v", err)
	}
}

// The regression this whole change exists for.
//
// DOGE-GA22IDJN… is clear on capability and reaches critical only through
// reputation escalation. Before the fix, a StellarExpert outage made it scan
// clear and that report was attestable — publishing "no issuer powers" for a
// known scam, with nothing on-chain to indicate the reputation axis was never
// read.
func TestCapabilityClearWithReputationDownIsNotAttestable(t *testing.T) {
	params, err := attest.FromReport(report(nil))
	if err != nil {
		t.Fatalf("a complete clear scan must still be attestable: %v", err)
	}
	if params.Severity != 0 {
		t.Fatalf("expected severity 0 for the complete scan, got %d", params.Severity)
	}

	if _, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Undetermined = true
		r.UndeterminedChecks = []string{"reputation"}
	})); err == nil {
		t.Fatal("a clear severity reached without reading reputation was attestable")
	}
}

type stubCheck struct {
	id string
}

func (s stubCheck) ID() string       { return s.id }
func (s stubCheck) Describe() string { return s.id }
func (s stubCheck) Run(ctx context.Context, sub *mechanics.Subject) (mechanics.Finding, error) {
	return mechanics.Finding{Check: s.id}, nil
}

func TestCheckIdentityChangesTheHash(t *testing.T) {
	ctx := context.Background()
	sub := &mechanics.Subject{}

	e2 := &mechanics.Engine{Checks: []mechanics.Check{stubCheck{"a"}, stubCheck{"b"}}}
	rep2, _ := e2.Run(ctx, sub)
	// mock unevaluated/undetermined errors by making them valid
	rep2.Severity = mechanics.Clear
	rep2.Base = mechanics.Clear
	rep2.Mechanics = mechanics.MechAuthRequired
	params2, _ := attest.FromReport(rep2)

	e3 := &mechanics.Engine{Checks: []mechanics.Check{stubCheck{"a"}, stubCheck{"b"}, stubCheck{"c"}}}
	rep3, _ := e3.Run(ctx, sub)
	rep3.Severity = mechanics.Clear
	rep3.Base = mechanics.Clear
	rep3.Mechanics = mechanics.MechAuthRequired
	params3, _ := attest.FromReport(rep3)

	if params2.EvidenceHash == params3.EvidenceHash {
		t.Errorf("a two-check engine and a three-check engine produced the same hash: %s", params2.EvidenceHash)
	}

	e2Reordered := &mechanics.Engine{Checks: []mechanics.Check{stubCheck{"b"}, stubCheck{"a"}}}
	rep2Reordered, _ := e2Reordered.Run(ctx, sub)
	rep2Reordered.Severity = mechanics.Clear
	rep2Reordered.Base = mechanics.Clear
	rep2Reordered.Mechanics = mechanics.MechAuthRequired
	params2Reordered, _ := attest.FromReport(rep2Reordered)

	if params2.EvidenceHash != params2Reordered.EvidenceHash {
		t.Errorf("check order affected the hash:\na, b: %s\nb, a: %s", params2.EvidenceHash, params2Reordered.EvidenceHash)
	}
}
