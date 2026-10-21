package attest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
)

// Committed byte-level vectors for the canonical preimage (#38).
//
// The tests in attest_test.go assert that the code agrees with the documented
// encoding rules; these vectors pin the BYTES themselves. Each vector is a raw
// preimage file plus its SHA-256 digest, and each one is re-derived here from a
// Report built the same way attest_test.go builds reports. Any change to the
// encoding that alters existing vectors therefore fails CI here, forcing a
// deliberate PreimageVersion bump instead of a silent hash break for everyone
// who re-scans.
//
// aqua-mainnet-onchain is the traceability vector: its digest equals the
// evidence_hash of AQUA's testnet attestation for the mainnet asset
// (tx 1b6bafc1226570b2415299f5531256716f4d8dc489a9784fcd6ea347d0f63f5f,
// 688453bd22e9b694b9c70659d37526bdae18944645542642008e9d961461a4a9 — see
// docs/attestation-run.md), so a third-party reimplementation can check itself
// against a hash that is actually on chain, not just against this repo.
//
// The vector bytes were produced by an independent implementation of the
// documented rules, not by calling the Go encoder, so agreement between the two
// is itself the thing under test.

const (
	vecHorizonURL = "https://horizon.stellar.org/assets?asset_code=AQUA&asset_issuer=" +
		"GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"
	vecNoFlags = "issuer flags: auth_required=false auth_revocable=false " +
		"auth_immutable=false auth_clawback_enabled=false"
)

func ev(source, url, claim string) mechanics.Evidence {
	return mechanics.Evidence{Source: source, URL: url, Claim: claim}
}

// vectorReports pairs every committed vector with the Report whose preimage it
// pins. TestEveryVectorFileIsPinned refuses a vector file without an entry
// here, so a fixture cannot be added and then silently stop being checked.
var vectorReports = map[string]func() *mechanics.Report{
	"no-evidence-verified": func() *mechanics.Report {
		return report(func(r *mechanics.Report) { r.Evidence = nil })
	},
	"one-evidence-unverified": func() *mechanics.Report {
		return report(func(r *mechanics.Report) {
			r.Accountability = mechanics.AccountabilityUnverified
			r.Evidence = []mechanics.Evidence{ev("horizon", vecHorizonURL, vecNoFlags)}
		})
	},
	"sorted-multi-evidence": func() *mechanics.Report {
		return report(func(r *mechanics.Report) {
			r.Evidence = []mechanics.Evidence{
				ev("stellar.toml", "https://aqua.network/.well-known/stellar.toml",
					"CURRENCIES claims AQUA-"+
						"GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"),
				ev("horizon", vecHorizonURL, vecNoFlags),
				ev("stellar.expert/blocked-domains",
					"https://api.stellar.expert/explorer/directory/blocked-domains/aqua.network",
					`domain "aqua.network" blocked=false`),
			}
		})
	},
	"escapes-in-claim": func() *mechanics.Report {
		raw := "issuer flags: auth_required=false\nsecond\tline\\with\\backslash\rend"
		return report(func(r *mechanics.Report) {
			r.Evidence = []mechanics.Evidence{
				ev("stellar.expert/directory",
					"https://api.stellar.expert/explorer/directory/"+
						"GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA",
					`listed as "AQUA Issuer" on aqua.network`),
				ev("horizon", vecHorizonURL, raw),
			}
		})
	},
	"accountability-unknown": func() *mechanics.Report {
		return report(func(r *mechanics.Report) {
			r.Asset = mechanics.Asset{
				Code:   "VELO",
				Issuer: "GDM4RQUQQUVSKQA7S6EM7XBZP3FCGH4Q7CL6TABQ7B2BEJ5ERARM2M5M",
			}
			r.Accountability = mechanics.AccountabilityUnknown
			r.Mechanics = mechanics.MechDomainUnverified
			r.Evidence = []mechanics.Evidence{
				ev("stellar.expert/blocked-domains",
					"https://api.stellar.expert/explorer/directory/blocked-domains/velo.org",
					`domain "velo.org" blocked=false`),
			}
		})
	},
	// network-bound-pubnet and network-bound-testnet are the v3 pair: two
	// reports byte-identical except for the network line. Every earlier field,
	// the check set, and the evidence are the same, so the two digests differ
	// only through the ledger the facts were read from — which is exactly what
	// #41 requires an attestation to be able to prove. The evidence URL cites
	// the pubnet Horizon because the AQUA record these claims mirror was
	// captured there; the testnet vector deliberately keeps it, since a
	// verifiable URL is not itself a network claim and the hash must move on
	// the network line alone.
	"network-bound-pubnet": func() *mechanics.Report {
		r := report(func(r *mechanics.Report) {
			r.Mechanics = 0
			r.CheckSet = []string{"capability", "mutability", "reputation", "sep1-domain"}
			r.Network = horizon.PublicNet
			r.Evidence = []mechanics.Evidence{
				ev("horizon", vecHorizonURL, vecNoFlags),
			}
		})
		return r
	},
	"network-bound-testnet": func() *mechanics.Report {
		return report(func(r *mechanics.Report) {
			r.Mechanics = 0
			r.CheckSet = []string{"capability", "mutability", "reputation", "sep1-domain"}
			r.Network = horizon.TestNet
			r.Evidence = []mechanics.Evidence{
				ev("horizon", vecHorizonURL, vecNoFlags),
			}
		})
	},
	"escalated-true-critical": func() *mechanics.Report {
		return report(func(r *mechanics.Report) {
			r.Asset = mechanics.Asset{
				Code:   "DOGE",
				Issuer: "GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P",
			}
			r.Severity, r.Base, r.Escalated = mechanics.Critical, mechanics.Clear, true
			r.Accountability = mechanics.AccountabilityUnverified
			r.Mechanics = mechanics.MechDomainUnverified | mechanics.MechBlocklisted
			r.Evidence = []mechanics.Evidence{
				ev("horizon",
					"https://horizon.stellar.org/assets?asset_code=DOGE&asset_issuer="+
						"GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P",
					vecNoFlags),
				ev("stellar.expert/directory",
					"https://api.stellar.expert/explorer/directory/"+r.Asset.Issuer,
					`listed as "DOGE Scam" (domain "nasdaq.finance", tags: malicious, unsafe)`),
			}
		})
	},
	"escalated-false-high-mechanics": func() *mechanics.Report {
		return report(func(r *mechanics.Report) {
			r.Asset = mechanics.Asset{
				Code:   "USDZ",
				Issuer: "GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR",
			}
			r.Severity, r.Base = mechanics.High, mechanics.High
			r.Mechanics = mechanics.MechAuthRevocable | mechanics.MechClawbackEnabled
			r.Evidence = []mechanics.Evidence{
				ev("horizon",
					"https://horizon.stellar.org/assets?asset_code=USDZ&asset_issuer="+
						"GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR",
					"issuer flags: auth_required=false auth_revocable=true "+
						"auth_immutable=false auth_clawback_enabled=true"),
			}
		})
	},
	// checkset-bound-v2 is the v2 vector: the v1 header plus the checks line,
	// no network. Every tag has at least one committed vector (#270).
	"checkset-bound-v2": func() *mechanics.Report {
		return report(func(r *mechanics.Report) {
			r.CheckSet = []string{"sep1-domain", "capability", "reputation", "mutability"}
			r.Evidence = []mechanics.Evidence{ev("horizon", vecHorizonURL, vecNoFlags)}
		})
	},
	// scanner-network-bound-v4 is the v4 vector: the v3 layout with the
	// scanner line after the version line. Its identity is pinned in
	// vectorIdentity, because the real one depends on how the binary was built.
	"scanner-network-bound-v4": func() *mechanics.Report {
		return report(func(r *mechanics.Report) {
			r.CheckSet = []string{"sep1-domain", "capability", "reputation", "mutability"}
			r.Network = horizon.PublicNet
			r.ScannerBound = true
			r.Evidence = []mechanics.Evidence{ev("horizon", vecHorizonURL, vecNoFlags)}
		})
	},
	// usdc-mainnet-onchain and usdz-mainnet-onchain are traceable to the
	// USDC and USDZ attestations in docs/deployment.md, like
	// aqua-mainnet-onchain. TestOnChainDigestsArePinned holds all three to the
	// on-chain hashes (#269).
	"usdc-mainnet-onchain": func() *mechanics.Report {
		const iss = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
		return report(func(r *mechanics.Report) {
			r.Asset = mechanics.Asset{Code: "USDC", Issuer: iss}
			r.Severity, r.Base = mechanics.Medium, mechanics.Medium
			r.Accountability = mechanics.AccountabilityUnverified
			r.Mechanics = mechanics.MechAuthRevocable | mechanics.MechDomainUnverified
			r.Evidence = []mechanics.Evidence{
				ev("horizon", "https://horizon.stellar.org/assets?asset_code=USDC&asset_issuer="+iss,
					"issuer flags: auth_required=false auth_revocable=true "+
						"auth_immutable=false auth_clawback_enabled=false"),
				ev("stellar.expert/blocked-domains",
					"https://api.stellar.expert/explorer/directory/blocked-domains/circle.com",
					`domain "circle.com" blocked=false`),
				ev("stellar.expert/directory", "https://api.stellar.expert/explorer/directory/"+iss,
					`listed as "Centre" (domain "centre.io", tags: anchor, issuer)`),
				ev("stellar.toml", "https://circle.com/.well-known/stellar.toml",
					"not retrievable: sep1: fetch https://circle.com/.well-known/stellar.toml: status 404"),
			}
		})
	},
	"usdz-mainnet-onchain": func() *mechanics.Report {
		const iss = "GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR"
		return report(func(r *mechanics.Report) {
			r.Asset = mechanics.Asset{Code: "USDZ", Issuer: iss}
			r.Severity, r.Base = mechanics.High, mechanics.High
			r.Mechanics = mechanics.MechAuthRevocable | mechanics.MechClawbackEnabled
			r.Evidence = []mechanics.Evidence{
				ev("horizon", "https://horizon.stellar.org/assets?asset_code=USDZ&asset_issuer="+iss,
					"issuer flags: auth_required=false auth_revocable=true "+
						"auth_immutable=false auth_clawback_enabled=true"),
				ev("stellar.expert/blocked-domains",
					"https://api.stellar.expert/explorer/directory/blocked-domains/zeam.money",
					`domain "zeam.money" blocked=false`),
				ev("stellar.expert/directory", "https://api.stellar.expert/explorer/directory/"+iss,
					`listed as "Zeam.Money" (domain "zeam.money", tags: issuer)`),
				ev("stellar.toml", "https://zeam.money/.well-known/stellar.toml",
					"CURRENCIES claims USDZ-"+iss),
			}
		})
	},
	// Traceable to the testnet attestation for the mainnet asset named above:
	// the digest file equals the evidence_hash recorded in docs/attestation-run.md.
	"aqua-mainnet-onchain": func() *mechanics.Report {
		return report(func(r *mechanics.Report) {
			r.Evidence = []mechanics.Evidence{
				ev("horizon", vecHorizonURL, vecNoFlags),
				ev("stellar.expert/blocked-domains",
					"https://api.stellar.expert/explorer/directory/blocked-domains/aqua.network",
					`domain "aqua.network" blocked=false`),
				ev("stellar.expert/directory",
					"https://api.stellar.expert/explorer/directory/"+
						"GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA",
					`listed as "AQUA Issuer" (domain "aqua.network", tags: anchor, issuer)`),
				ev("stellar.toml", "https://aqua.network/.well-known/stellar.toml",
					"CURRENCIES claims AQUA-"+
						"GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"),
			}
		})
	},
}

// vectorIdentity pins the scanner identity a scanner-bound vector renders.
// The real attest.ScannerIdentity depends on how the binary was built, so a
// v4 vector names the identity it was written with.
var vectorIdentity = map[string]string{
	"scanner-network-bound-v4": "v1.2.3",
}

// pinVectorIdentity sets attest.ScannerIdentity for one vector's subtest.
func pinVectorIdentity(t *testing.T, name string) {
	t.Helper()
	id, ok := vectorIdentity[name]
	if !ok {
		return
	}
	prev := attest.ScannerIdentity
	attest.ScannerIdentity = id
	t.Cleanup(func() { attest.ScannerIdentity = prev })
}

func TestPreimageVectors(t *testing.T) {
	for name, build := range vectorReports {
		t.Run(name, func(t *testing.T) {
			pinVectorIdentity(t, name)
			raw, err := os.ReadFile(filepath.Join("testdata", "vectors", name+".preimage"))
			if err != nil {
				t.Fatalf("read vector: %v", err)
			}
			digestBytes, err := os.ReadFile(filepath.Join("testdata", "vectors", name+".digest"))
			if err != nil {
				t.Fatalf("read digest: %v", err)
			}
			want := strings.TrimSpace(string(digestBytes))

			// The committed bytes hash to the committed digest: anyone — any
			// language, no Go involved — can verify these fixtures.
			sum := sha256.Sum256(raw)
			if got := hex.EncodeToString(sum[:]); got != want {
				t.Fatalf("vector bytes do not hash to the recorded digest: got %s", got)
			}

			// And this implementation derives exactly those bytes from the
			// Report, so an encoding change that moves a vector fails here.
			params, err := attest.FromReport(build())
			if err != nil {
				t.Fatalf("FromReport: %v", err)
			}
			if params.Preimage != string(raw) {
				t.Fatalf("preimage diverged from the committed vector\n got: %q\nwant: %q",
					params.Preimage, string(raw))
			}
			if params.EvidenceHash != want {
				t.Fatalf("evidence_hash diverged from the committed digest: got %s", params.EvidenceHash)
			}
		})
	}
}

// onchainDigests are the full evidence_hashes actually recorded on testnet,
// transcribed from docs/attestation-run.md. They are the external anchor the
// vectors cannot rewrite: a vector regenerated to match whatever the encoder
// emits would stop hashing to the recorded digest and fail here, no matter how
// self-consistent the regenerated fixture is (#269).
var onchainDigests = map[string]string{
	"AQUA": "688453bd22e9b694b9c70659d37526bdae18944645542642008e9d961461a4a9",
	"USDC": "e7fc765d396de672a85c1b7fe76f67b05a17ad0798167748b285df020ed790bd",
	"USDZ": "ca9b13a66f3a0a4b43d66dea29a505658447e08eee200d2bdb5e66aa1065fb4d",
}

// TestOnChainDigestsArePinned ties the committed fixtures back to the chain.
//
// docs/deployment.md records each attested hash truncated to
// `prefix…suffix`; this test refuses a table whose fragments no longer match
// the full on-chain digests, and refuses a vector whose bytes no longer hash
// to them. Together with TestEveryVectorFileIsPinned it means the AQUA vector
// cannot silently be regenerated from the encoder: the regenerated bytes
// would have to keep hashing to the hash AQUA's attestation actually stored.
func TestOnChainDigestsArePinned(t *testing.T) {
	raw, err := os.ReadFile("../../docs/deployment.md")
	if err != nil {
		t.Fatalf("read deployment record: %v", err)
	}

	fragments := map[string]string{}
	versions := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cols := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cols) < 5 {
			continue
		}
		code := strings.Trim(strings.TrimSpace(cols[0]), "`")
		if _, ok := onchainDigests[code]; !ok {
			continue
		}
		fragments[code] = strings.Trim(strings.TrimSpace(cols[3]), "`")
		versions[code] = strings.Trim(strings.TrimSpace(cols[4]), "`")
	}

	for code, full := range onchainDigests {
		frag, ok := fragments[code]
		if !ok {
			t.Errorf("no %s row with a hash and preimage version in docs/deployment.md", code)
			continue
		}
		prefix, suffix, ok := strings.Cut(frag, "…")
		if !ok {
			t.Errorf("%s hash %q is not a prefix…suffix fragment", code, frag)
			continue
		}
		if prefix != full[:len(prefix)] || suffix != full[len(full)-len(suffix):] {
			t.Errorf("%s fragment %q does not match the on-chain digest %s", code, frag, full)
		}
		if versions[code] != "v1" {
			t.Errorf("%s records preimage version %q, want v1: the pinned digest is v1 bytes", code, versions[code])
		}
	}

	// Each on-chain vector's bytes hash to the recorded digest, whatever its
	// .digest file says, and the encoder derives exactly that hash from the
	// vector's Report.
	for code, vector := range map[string]string{
		"AQUA": "aqua-mainnet-onchain",
		"USDC": "usdc-mainnet-onchain",
		"USDZ": "usdz-mainnet-onchain",
	} {
		vectorRaw, err := os.ReadFile(filepath.Join("testdata", "vectors", vector+".preimage"))
		if err != nil {
			t.Fatalf("read on-chain vector: %v", err)
		}
		sum := sha256.Sum256(vectorRaw)
		if got := hex.EncodeToString(sum[:]); got != onchainDigests[code] {
			t.Errorf("%s vector hashes to %s, not the on-chain %s — the vector was regenerated",
				vector, got, onchainDigests[code])
		}
		params, err := attest.FromReport(vectorReports[vector]())
		if err != nil {
			t.Fatalf("FromReport %s: %v", vector, err)
		}
		if params.EvidenceHash != onchainDigests[code] {
			t.Errorf("encoder derives %s for %s, not the on-chain %s", params.EvidenceHash, vector, onchainDigests[code])
		}
	}
}

// A vector file without an entry in vectorReports would pin nothing — the
// fixture would exist while the encoder drifted freely past it.
func TestEveryVectorFileIsPinned(t *testing.T) {
	entries, err := filepath.Glob(filepath.Join("testdata", "vectors", "*.preimage"))
	if err != nil {
		t.Fatalf("glob vectors: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no vector files found under testdata/vectors")
	}
	for _, e := range entries {
		stem := strings.TrimSuffix(filepath.Base(e), ".preimage")
		if _, ok := vectorReports[stem]; !ok {
			t.Errorf("vector %q has no Report pinning it in vectorReports", stem)
		}
		if _, err := os.Stat(filepath.Join("testdata", "vectors", stem+".digest")); err != nil {
			t.Errorf("vector %q has no matching .digest file", stem)
		}
	}
}
