package mechanics_test

import (
	"context"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/mechanics"
)

// loadSubject rebuilds a Subject from captured fixtures, using the same
// decoders the live fetchers use. The loader lives in internal/eval so this
// package and the eval command share one implementation, and neither touches
// the network. See eval.LoadSubject.
func loadSubject(t *testing.T, dir string) *mechanics.Subject {
	t.Helper()
	s, err := eval.LoadSubject("testdata", dir)
	if err != nil {
		t.Fatalf("load %s: %v", dir, err)
	}
	return s
}

// TestEval is the aggregate judgment eval. Detecting a flag is deterministic
// and uninteresting; what these cases measure is whether the severity model
// separates a trap from a legitimate compliance feature, and whether escalation
// fires only on reputation.
//
// The labels live in eval.Corpus so the aggregate and per-check evals cannot
// describe different runs. See docs/eval.md for the labelling rationale.
func TestEval(t *testing.T) {
	cases := []struct {
		dir string
		// why states what this subject is supposed to prove.
		why string

		wantBase      mechanics.Severity
		wantSeverity  mechanics.Severity
		wantEscalated bool
		wantAccount   mechanics.Accountability
	}{
		{
			dir:          "aqua-clear-verified",
			why:          "no auth flags at all: the issuer has no power over holders, and a reciprocal domain confirms who it is",
			wantBase:     mechanics.Clear,
			wantSeverity: mechanics.Clear,
			wantAccount:  mechanics.AccountabilityVerified,
		},
		{
			dir:          "shx-clear-flagslocked",
			why:          "no auth flags AND auth_immutable: the issuer can never add freeze or clawback later",
			wantBase:     mechanics.Clear,
			wantSeverity: mechanics.Clear,
			wantAccount:  mechanics.AccountabilityVerified,
		},
		{
			dir: "xrp-clear-unlocked",
			why: "the unlocked counterpart to SHX: no auth flags, but auth_immutable is UNSET, so the " +
				"issuer may add freeze or clawback later. The mutability finding must report that " +
				"without moving base severity off clear.",
			wantBase:     mechanics.Clear,
			wantSeverity: mechanics.Clear,
			wantAccount:  mechanics.AccountabilityVerified,
		},
		{
			dir: "usdc-revocable-regulated",
			why: "a real regulated stablecoin that legitimately uses auth_revocable. It must report " +
				"freeze-capable (medium) on the strength of the flag alone: not discounted to clear " +
				"because Circle issues it, and not escalated because nothing flags it.",
			wantBase:     mechanics.Medium,
			wantSeverity: mechanics.Medium,
			// circle.com does not serve a stellar.toml, so the reciprocal claim
			// genuinely fails. Reported honestly rather than special-cased.
			wantAccount: mechanics.AccountabilityUnverified,
		},
		{
			dir: "berkshire-clawback-scam",
			why: "impersonation asset with clawback: capability alone puts it at high, and the curated " +
				"malicious tag escalates it to critical",
			wantBase:      mechanics.High,
			wantSeverity:  mechanics.Critical,
			wantEscalated: true,
			wantAccount:   mechanics.AccountabilityUnverified,
		},
		{
			dir: "doge-noflags-scam",
			why: "the case that justifies keeping reputation as a separate upward-only axis: a known " +
				"scam asset carrying NO auth flags. Capability is honestly clear, and escalation is " +
				"the only thing that catches it.",
			wantBase:      mechanics.Clear,
			wantSeverity:  mechanics.Critical,
			wantEscalated: true,
			wantAccount:   mechanics.AccountabilityUnverified,
		},
		{
			dir: "doge-disagreeing-sources",
			why: "two consumed sources disagree about the same issuer (blocked-domains returns blocked=false " +
				"for darkpool.digital while the directory tags the issuer malicious/unsafe): escalation must " +
				"still fire from the source that did flag",
			wantBase:      mechanics.Clear,
			wantSeverity:  mechanics.Critical,
			wantEscalated: true,
			wantAccount:   mechanics.AccountabilityUnverified,
		},
	}

	eng := mechanics.NewEngine()
	for _, tc := range eval.Corpus() {
		t.Run(tc.Dir, func(t *testing.T) {
			rep, err := eng.Run(context.Background(), loadSubject(t, tc.Dir))
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if rep.Base != tc.Base {
				t.Errorf("base severity = %v, want %v\nwhy this case exists: %s",
					rep.Base, tc.Base, tc.Why)
			}
			if rep.Severity != tc.Severity {
				t.Errorf("severity = %v, want %v\nwhy this case exists: %s",
					rep.Severity, tc.Severity, tc.Why)
			}
			if rep.Escalated != tc.Escalated {
				t.Errorf("escalated = %v, want %v", rep.Escalated, tc.Escalated)
			}
			if rep.Accountability != tc.Accountability {
				t.Errorf("accountability = %v, want %v", rep.Accountability, tc.Accountability)
			}
		})
	}
}

// TestEvalPerCheck evaluates each check's output independently (#115).
//
// The aggregate can be right for the wrong reason: a capability check that
// said clear and a reputation escalation that raised the level to critical
// produce a correct report while the capability error stays invisible. This
// compares every finding against its own label, so that cannot happen.
func TestEvalPerCheck(t *testing.T) {
	eng := mechanics.NewEngine()
	for _, tc := range eval.Corpus() {
		t.Run(tc.Dir, func(t *testing.T) {
			rep, err := eng.Run(context.Background(), loadSubject(t, tc.Dir))
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			res := eval.EvaluateChecks(rep, tc)
			if res.Partial {
				t.Fatalf("subject %s is only partially evaluated: labelled checks with no "+
					"finding %v, findings with no label %v", tc.Dir, res.Missing, res.Unlabelled)
			}
			for _, m := range res.Mismatches {
				t.Errorf("check %s disagrees: got %s, want %s", m.Check, m.Got, m.Want)
			}
			t.Logf("per-check agreement for %s: %v", tc.Dir, res.Agreed)
		})
	}
}

// TestEvalPerCheckDetectsWrongExpectation proves the per-check evaluator
// actually fails when a check's output diverges from its label, rather than
// reporting agreement unconditionally.
func TestEvalPerCheckDetectsWrongExpectation(t *testing.T) {
	eng := mechanics.NewEngine()

	var doge eval.Label
	found := false
	for _, tc := range eval.Corpus() {
		if tc.Dir == "doge-noflags-scam" {
			doge, found = tc, true
		}
	}
	if !found {
		t.Fatal("doge-noflags-scam is missing from the corpus")
	}

	// Deliberately wrong: DOGE's capability is honestly clear, and this claims
	// high. A passing evaluator would fail to notice.
	capability := doge.Checks["capability"]
	capability.Severity = mechanics.High
	doge.Checks["capability"] = capability

	rep, err := eng.Run(context.Background(), loadSubject(t, doge.Dir))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	res := eval.EvaluateChecks(rep, doge)
	if len(res.Mismatches) != 1 || res.Mismatches[0].Check != "capability" {
		t.Fatalf("a deliberately wrong per-check expectation was not caught: %+v", res)
	}
}

// TestEvalPerCheckReportsPartialLabels covers the missing state: a subject
// without per-check labels must be visibly partial, not silently passing.
func TestEvalPerCheckReportsPartialLabels(t *testing.T) {
	eng := mechanics.NewEngine()
	rep, err := eng.Run(context.Background(), loadSubject(t, "aqua-clear-verified"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// No per-check labels at all. An evaluator that only looked at the
	// aggregate would call this complete.
	res := eval.EvaluateChecks(rep, eval.Label{Dir: "aqua-clear-verified"})
	if !res.Partial {
		t.Fatal("a subject without per-check labels was reported as fully evaluated")
	}
	if res.OK() {
		t.Fatal("OK() returned true for a partially labelled subject")
	}
	if len(res.Unlabelled) == 0 {
		t.Fatal("findings with no label were not reported as unlabelled")
	}
}

// TestAccountabilityNeverChangesSeverity is the property the whole model rests
// on. Two subjects with identical issuer flags must classify identically no
// matter how well attributed they are, or a contract gating on severity is
// relying on someone's opinion instead of on ledger mechanics.
func TestAccountabilityNeverChangesSeverity(t *testing.T) {
	eng := mechanics.NewEngine()

	verified := loadSubject(t, "aqua-clear-verified")
	anonymous := loadSubject(t, "aqua-clear-verified")
	// Strip every trace of attribution, leaving the flags untouched.
	anonymous.Issuer.HomeDomain = ""
	anonymous.Toml = nil
	anonymous.Directory = nil
	anonymous.Blocked = nil

	repV, err := eng.Run(context.Background(), verified)
	if err != nil {
		t.Fatal(err)
	}
	repA, err := eng.Run(context.Background(), anonymous)
	if err != nil {
		t.Fatal(err)
	}

	if repV.Severity != repA.Severity {
		t.Errorf("attribution changed severity: verified=%v anonymous=%v",
			repV.Severity, repA.Severity)
	}
	if repV.Accountability == repA.Accountability {
		t.Errorf("accountability should differ between the two subjects, both = %v",
			repV.Accountability)
	}
}

// TestNoHomeDomainIsUnknownNotUnverified is the distinction issue #3 asks for,
// asserted against a real capture rather than a stripped copy: VELO's issuer
// account carries no home_domain at all (Horizon omits the field entirely), so
// nobody has claimed the asset. That is a different state from a domain that
// was advertised and failed verification, and it must not move severity either
// — aqua-clear-verified is the same flags with a claim on top.
func TestNoHomeDomainIsUnknownNotUnverified(t *testing.T) {
	eng := mechanics.NewEngine()

	unclaimed, err := eng.Run(context.Background(), loadSubject(t, "velo-no-home-domain"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := eng.Run(context.Background(), loadSubject(t, "aqua-clear-verified"))
	if err != nil {
		t.Fatal(err)
	}

	if unclaimed.Accountability != mechanics.AccountabilityUnknown {
		t.Errorf("accountability = %q, want %q: an issuer with no home_domain has made no "+
			"claim, it has not failed one", unclaimed.Accountability, mechanics.AccountabilityUnknown)
	}
	if claimed.Accountability != mechanics.AccountabilityVerified {
		t.Errorf("control subject accountability = %q, want %q",
			claimed.Accountability, mechanics.AccountabilityVerified)
	}
	if unclaimed.Base != claimed.Base || unclaimed.Severity != claimed.Severity {
		t.Errorf("identical flags classified differently: no home_domain = %v/%v, verified domain = %v/%v",
			unclaimed.Base, unclaimed.Severity, claimed.Base, claimed.Severity)
	}

	var domain *mechanics.Finding
	for i := range unclaimed.Findings {
		if unclaimed.Findings[i].Check == "sep1-domain" {
			domain = &unclaimed.Findings[i]
		}
	}
	if domain == nil {
		t.Fatal("report carries no sep1-domain finding")
	}
	for _, want := range []string{"Nobody has publicly claimed", "not a failed verification"} {
		if !strings.Contains(domain.Reasoning, want) {
			t.Errorf("reasoning must say %q: %s", want, domain.Reasoning)
		}
	}
}

// TestConfiscationImpliesHigh enforces the ABI invariant the contract relies
// on: anything matching ConfiscationMask is at least High.
func TestConfiscationImpliesHigh(t *testing.T) {
	eng := mechanics.NewEngine()
	for _, tc := range eval.Corpus() {
		rep, err := eng.Run(context.Background(), loadSubject(t, tc.Dir))
		if err != nil {
			t.Fatal(err)
		}
		if rep.Mechanics&mechanics.ConfiscationMask != 0 && rep.Base < mechanics.High {
			t.Errorf("%s: confiscation-capable but base severity %v < high", tc.Dir, rep.Base)
		}
	}
}

// TestEvalDegradedSubjectIsUndeterminedNotClear is the eval-side regression
// for #23, expressed from fixtures (#111). The degraded-scan tests above are
// hand-built subjects because the fixture loader used to render an outage as a
// clean absence: a missing directory.json was indistinguishable from a source
// that never answered. With the error-marker convention (directory.err,
// blocked.err) the labelled set can state the difference itself, and this case
// pins it:
//
//   - the reputation finding is undetermined, not clear — the blocklist was
//     consulted and answered 429, so "not listed" was never observed;
//   - the report carries Undetermined and names the reputation check, so a
//     consumer parsing JSON sees a partial answer, not a clean one;
//   - severity stays at the measured capability — never inflated to cover the
//     gap (the failure shape the outage must not be answered with either);
//   - the report is refused at attest.FromReport, because a partial scan must
//     never reach the chain.
func TestEvalDegradedSubjectIsUndeterminedNotClear(t *testing.T) {
	rep, err := mechanics.NewEngine().Run(context.Background(), loadSubject(t, "synthetic-reputation-outage"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if !rep.Undetermined {
		t.Fatal("a degraded scan did not mark the report undetermined")
	}
	if len(rep.UndeterminedChecks) != 1 || rep.UndeterminedChecks[0] != "reputation" {
		t.Fatalf("expected the reputation check named as undetermined, got %v", rep.UndeterminedChecks)
	}
	if rep.Severity != mechanics.Clear || rep.Base != mechanics.Clear {
		t.Fatalf("severity moved to %v (base %v) to compensate for a missing source; "+
			"it must stay at the measured capability", rep.Severity, rep.Base)
	}

	var repF *mechanics.Finding
	for i := range rep.Findings {
		if rep.Findings[i].Check == "reputation" {
			repF = &rep.Findings[i]
			break
		}
	}
	if repF == nil {
		t.Fatal("no reputation finding in the report")
	}
	if !repF.Undetermined {
		t.Fatal("reputation finding is not marked undetermined; an outage rendered as a clean answer")
	}
	if repF.Severity != mechanics.Clear {
		t.Fatalf("reputation finding severity = %v; an undetermined finding makes no severity claim", repF.Severity)
	}

	// The failure has to reach the report as attributed evidence with the
	// underlying status, or the outage is not auditable from the report alone.
	var found bool
	for _, e := range rep.Evidence {
		if e.Source == "stellar.expert/blocked-domains" {
			found = true
			if !strings.Contains(e.Claim, "not retrievable") || !strings.Contains(e.Claim, "429") {
				t.Errorf("blocklist evidence does not carry the failure verbatim: %q", e.Claim)
			}
			if !e.Attempted {
				t.Error("failure evidence is not marked Attempted: an attempt is not an answer")
			}
		}
	}
	if !found {
		t.Fatal("no attributed evidence for the unreachable blocklist")
	}

	// And the whole point of the flag: a degraded report must be refused
	// on-chain rather than attested with the severity it managed to reach.
	if _, err := attest.FromReport(rep); !errors.Is(err, attest.ErrUndetermined) {
		t.Fatalf("a degraded eval subject was attestable (err = %v); want ErrUndetermined", err)
	}
}

// TestEvalLoaderStates pins the fixture-format semantics the degraded subject
// depends on, for all three consumed sources: a payload file means the source
// answered, an error marker means it was consulted and failed, and neither
// means it was not consulted. If the loader loses any of the three states,
// every degraded expectation in the corpus becomes vacuous.
func TestEvalLoaderStates(t *testing.T) {
	const (
		fixtures = "testdata"
		degraded = "synthetic-reputation-outage"
	)

	t.Run("errored sources set the matching Err field", func(t *testing.T) {
		s, err := eval.LoadSubject(fixtures, degraded)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		// Only the blocklist is degraded in this fixture; the directory payload
		// is present, so it must stay an answer.
		if s.BlockedErr == "" {
			t.Error("blocked.err marker present but BlockedErr was not set")
		}
		if !strings.Contains(s.BlockedErr, "429") {
			t.Errorf("BlockedErr = %q, want the marker's text verbatim", s.BlockedErr)
		}
		if s.DirectoryErr != "" {
			t.Errorf("directory.json present but DirectoryErr = %q; a payload and an error marker are mutually exclusive", s.DirectoryErr)
		}
		if s.Directory == nil {
			t.Error("directory.json present but not loaded")
		}
		if s.TomlErr != "" {
			t.Errorf("stellar.toml present but TomlErr = %q; a payload and an error marker are mutually exclusive", s.TomlErr)
		}
		if s.Toml == nil {
			t.Error("stellar.toml present but not loaded")
		}
		// Attempt times are always set (the fetch was attempted whether or not
		// it succeeded); completion times only for answered sources.
		if s.BlockedAttemptedAt.IsZero() {
			t.Error("errored fetch recorded no attempt time")
		}
		if !s.BlockedFetchedAt.IsZero() {
			t.Error("errored fetch recorded a completion time; only answered sources have one")
		}
	})

	// The two other states, exercised per source without adding fixtures:
	// the corpus's clean subjects cover the valid state (payload present, no
	// Err set), and a load from a directory with no files at all covers the
	// missing state, which the loader must represent as no payload AND no
	// error — the exact pair a hand-built "never consulted" subject carries.
	t.Run("valid sources carry a payload and no error", func(t *testing.T) {
		s, err := eval.LoadSubject(fixtures, "aqua-clear-verified")
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		for _, c := range []struct {
			name string
			err  string
		}{
			{"toml", s.TomlErr},
			{"directory", s.DirectoryErr},
			{"blocked", s.BlockedErr},
		} {
			if c.err != "" {
				t.Errorf("%s source errored (%q) in a fixture whose payload is present", c.name, c.err)
			}
		}
		if s.Toml == nil || s.Directory == nil || s.Blocked == nil {
			t.Errorf("clean subject loaded without every payload: toml=%t directory=%t blocked=%t",
				s.Toml != nil, s.Directory != nil, s.Blocked != nil)
		}
	})

	t.Run("missing sources carry neither payload nor error", func(t *testing.T) {
		// LoadSubject treats its second argument as relative to the first, so
		// the scratch corpus goes under a temp root rather than beside the
		// real fixtures.
		root := t.TempDir()
		dir := "scratch-missing-sources"
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		// asset.json and account.json are required; copy them in so the load
		// reaches the reputation sources rather than failing first.
		for _, f := range []string{"asset.json", "account.json"} {
			b, err := os.ReadFile(filepath.Join(fixtures, degraded, f))
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			if err := os.WriteFile(filepath.Join(root, dir, f), b, 0o644); err != nil {
				t.Fatalf("write %s: %v", f, err)
			}
		}
		s, err := eval.LoadSubject(root, dir)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		for _, c := range []struct {
			name    string
			err     string
			present bool
		}{
			{"directory", s.DirectoryErr, s.Directory != nil},
			{"blocked", s.BlockedErr, s.Blocked != nil},
		} {
			if c.err != "" {
				t.Errorf("%s: no fixture and no marker, but Err = %q", c.name, c.err)
			}
			if c.present {
				t.Errorf("%s: no fixture present, but a payload was loaded", c.name)
			}
		}
	})

	t.Run("an empty error marker is not an error state", func(t *testing.T) {
		root := t.TempDir()
		dir := "scratch-blank-marker"
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		for _, f := range []string{"asset.json", "account.json"} {
			b, err := os.ReadFile(filepath.Join(fixtures, degraded, f))
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			if err := os.WriteFile(filepath.Join(root, dir, f), b, 0o644); err != nil {
				t.Fatalf("write %s: %v", f, err)
			}
		}
		// A blank marker must not become an empty-but-present Err, which the
		// checks would read as a failure carrying no reason at all.
		for _, marker := range []string{"directory.err", "blocked.err"} {
			if err := os.WriteFile(filepath.Join(root, dir, marker), []byte(" \n\t"), 0o644); err != nil {
				t.Fatalf("write %s: %v", marker, err)
			}
		}
		s, err := eval.LoadSubject(root, dir)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if s.DirectoryErr != "" || s.BlockedErr != "" {
			t.Errorf("a whitespace-only marker produced Err fields: directory=%q blocked=%q",
				s.DirectoryErr, s.BlockedErr)
		}
	})
}
