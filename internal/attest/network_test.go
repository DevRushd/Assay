package attest_test

import (
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
)

// These tests cover the network binding added with assay-evidence-v3 (#41).
//
// The problem the binding closes: an asset code and issuer can exist on two
// networks with different flags, and Assay's attestations are written to
// testnet while scanning pubnet. Before this encoding, a pubnet scan and a
// testnet scan of the same identifier produced byte-identical preimages, so an
// on-chain attestation could not prove which ledger its facts came from.
//
// The committed vectors network-bound-pubnet and network-bound-testnet pin the
// bytes themselves; these tests pin the behavior around them.

// twinReports builds two reports that are identical in every field except the
// network the facts were read from. Everything else — severity, mechanics,
// check set, evidence — matches, so any hash difference is attributable to the
// network line alone.
func twinReports(mut func(*mechanics.Report)) (*mechanics.Report, *mechanics.Report) {
	build := func(network horizon.Network) *mechanics.Report {
		return report(func(r *mechanics.Report) {
			r.CheckSet = []string{"capability", "mutability", "reputation", "sep1-domain"}
			r.Network = network
			if mut != nil {
				mut(r)
			}
		})
	}
	return build(horizon.PublicNet), build(horizon.TestNet)
}

// The regression the binding exists for: two scans of the same code+issuer on
// different networks must not hash identically, whatever the rest of the
// report says.
func TestDifferentNetworksProduceDifferentHashes(t *testing.T) {
	pub, test := twinReports(nil)

	pParams, err := attest.FromReport(pub)
	if err != nil {
		t.Fatalf("FromReport pubnet: %v", err)
	}
	tParams, err := attest.FromReport(test)
	if err != nil {
		t.Fatalf("FromReport testnet: %v", err)
	}

	if pParams.EvidenceHash == tParams.EvidenceHash {
		t.Fatal("two scans of the same asset on different networks hashed identically; " +
			"the attestation cannot prove which ledger it describes")
	}

	// The difference must be the network line and nothing else: the pubnet
	// preimage with its network line swapped for the testnet passphrase must
	// be byte-identical to the testnet preimage. If some other field also
	// moved, the divergence is not attributable and these tests prove less
	// than they appear to.
	if got := strings.Replace(pParams.Preimage,
		"network\t"+string(horizon.PublicNet),
		"network\t"+string(horizon.TestNet), 1); got != tParams.Preimage {
		t.Fatalf("network swap did not reproduce the twin preimage\n got: %q\nwant: %q",
			got, tParams.Preimage)
	}
}

// A report that names its network is written under v3, with the full network
// passphrase — not a short name — because the passphrase is the identifier the
// ecosystem already agrees on.
func TestNetworkBoundReportIsV3WithThePassphrase(t *testing.T) {
	pub, _ := twinReports(nil)

	params, err := attest.FromReport(pub)
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	if !strings.HasPrefix(params.Preimage, attest.PreimageVersionNetwork+"\n") {
		t.Fatalf("network-bound report is not v3: %q", firstLine(params.Preimage))
	}
	if params.Network != string(horizon.PublicNet) {
		t.Fatalf("params.Network = %q, want the full pubnet passphrase", params.Network)
	}
	line := "network\t" + string(horizon.PublicNet) + "\n"
	if !strings.Contains(params.Preimage, line) {
		t.Fatalf("preimage does not carry the network line:\n%s", params.Preimage)
	}
	// The line sits after the check set and before the evidence, the position
	// docs/contract-interface.md specifies.
	checksIdx := strings.Index(params.Preimage, "checks\t")
	networkIdx := strings.Index(params.Preimage, line)
	evidenceIdx := strings.Index(params.Preimage, "evidence\t")
	if checksIdx < 0 || networkIdx < 0 || evidenceIdx < 0 ||
		checksIdx >= networkIdx || networkIdx >= evidenceIdx {
		t.Fatalf("network line is not between the checks line and the evidence:\n%s",
			params.Preimage)
	}
}

// The migration rule: reports written before network binding must keep
// reproducing their earlier bytes exactly. Both pre-existing encodings — the
// check-set-bound v2 and the bare v1 — are covered, against a report that
// carries no network.
func TestUnboundReportKeepsItsEarlierEncoding(t *testing.T) {
	v2 := report(func(r *mechanics.Report) {
		r.CheckSet = []string{"capability", "mutability", "reputation", "sep1-domain"}
	})
	params, err := attest.FromReport(v2)
	if err != nil {
		t.Fatalf("FromReport v2: %v", err)
	}
	if !strings.HasPrefix(params.Preimage, attest.PreimageVersionCheckSet+"\n") {
		t.Fatalf("check-set-only report is not v2: %q", firstLine(params.Preimage))
	}
	if strings.Contains(params.Preimage, "network\t") {
		t.Fatalf("a report with no network must not grow a network line:\n%s", params.Preimage)
	}
	if params.Network != "" {
		t.Fatalf("params.Network = %q, want empty for an unbound report", params.Network)
	}

	v1 := report(nil)
	params, err = attest.FromReport(v1)
	if err != nil {
		t.Fatalf("FromReport v1: %v", err)
	}
	if !strings.HasPrefix(params.Preimage, attest.PreimageVersion+"\n") {
		t.Fatalf("bare report is not v1: %q", firstLine(params.Preimage))
	}
}

// The network line is a hashed field like any other, so the claim it commits
// to has to be material: the whole point of #41 is that the hash answers
// "which ledger".
func TestNetworkChangeMovesTheHash(t *testing.T) {
	base, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Network = horizon.PublicNet
	}))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	moved, err := attest.FromReport(report(func(r *mechanics.Report) {
		r.Network = horizon.TestNet
	}))
	if err != nil {
		t.Fatalf("FromReport: %v", err)
	}
	if base.EvidenceHash == moved.EvidenceHash {
		t.Fatal("changing the network did not change the hash")
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
