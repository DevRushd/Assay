package eval_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/mechanics"
)

// writeMinimalSubject writes the fixtures every subject must have, plus the
// extra files for one test case. The asset and account payloads are enough for
// LoadSubject to assemble a Subject; the fields under test are the source
// markers.
func writeMinimalSubject(t *testing.T, dir string, extra map[string]string) {
	t.Helper()
	files := map[string]string{
		"asset.json":   `{"asset_code":"DOGE","asset_issuer":"GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P"}`,
		"account.json": `{"account_id":"GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P","home_domain":"darkpool.digital"}`,
	}
	for name, body := range extra {
		files[name] = body
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

// TestLoadSubjectDistinguishesAbsentFromErrored is the loader half of #111:
// for each consumed source, a fixture with no file (never consulted), a fixture
// with a payload (answered), and a fixture with an error marker (consulted and
// failed) must produce three different Subjects. Before this, a failed source
// and an unconsulted one were identical, so the regression from #23 could not
// be written as an eval subject.
func TestLoadSubjectDistinguishesAbsentFromErrored(t *testing.T) {
	cases := []struct {
		name  string
		extra map[string]string
		check func(t *testing.T, s *mechanics.Subject)
	}{
		{
			name: "directory absent",
			check: func(t *testing.T, s *mechanics.Subject) {
				if s.Directory != nil || s.DirectoryErr != "" {
					t.Errorf("unconsulted directory = (%+v, %q), want (nil, \"\")",
						s.Directory, s.DirectoryErr)
				}
			},
		},
		{
			name:  "directory answered",
			extra: map[string]string{"directory.json": `{}`},
			check: func(t *testing.T, s *mechanics.Subject) {
				if s.Directory == nil {
					t.Error("directory answered but Directory is nil")
				}
				if s.DirectoryErr != "" {
					t.Errorf("directory answered but DirectoryErr = %q", s.DirectoryErr)
				}
			},
		},
		{
			name:  "directory errored",
			extra: map[string]string{"directory.err": "stellarexpert: get x: status 429\n"},
			check: func(t *testing.T, s *mechanics.Subject) {
				if s.Directory != nil {
					t.Error("directory errored but Directory is non-nil")
				}
				if s.DirectoryErr != "stellarexpert: get x: status 429" {
					t.Errorf("DirectoryErr = %q, want the marker text", s.DirectoryErr)
				}
			},
		},
		{
			name: "blocked absent",
			check: func(t *testing.T, s *mechanics.Subject) {
				if s.Blocked != nil || s.BlockedErr != "" {
					t.Errorf("unconsulted blocklist = (%+v, %q), want (nil, \"\")",
						s.Blocked, s.BlockedErr)
				}
			},
		},
		{
			name:  "blocked answered",
			extra: map[string]string{"blocked.json": `{"domain":"darkpool.digital","blocked":false}`},
			check: func(t *testing.T, s *mechanics.Subject) {
				if s.Blocked == nil {
					t.Error("blocklist answered but Blocked is nil")
				}
				if s.BlockedErr != "" {
					t.Errorf("blocklist answered but BlockedErr = %q", s.BlockedErr)
				}
			},
		},
		{
			name:  "blocked errored",
			extra: map[string]string{"blocked.err": "stellarexpert: get x: status 503\n"},
			check: func(t *testing.T, s *mechanics.Subject) {
				if s.Blocked != nil {
					t.Error("blocklist errored but Blocked is non-nil")
				}
				if s.BlockedErr != "stellarexpert: get x: status 503" {
					t.Errorf("BlockedErr = %q, want the marker text", s.BlockedErr)
				}
			},
		},
		{
			name: "toml absent",
			check: func(t *testing.T, s *mechanics.Subject) {
				if s.Toml != nil || s.TomlErr != "" {
					t.Errorf("unconsulted toml = (%+v, %q), want (nil, \"\")",
						s.Toml, s.TomlErr)
				}
			},
		},
		{
			name:  "toml errored",
			extra: map[string]string{"stellar.toml.status": "404\n"},
			check: func(t *testing.T, s *mechanics.Subject) {
				if s.Toml != nil {
					t.Error("toml errored but Toml is non-nil")
				}
				if s.TomlErr != "status 404" {
					t.Errorf("TomlErr = %q, want %q", s.TomlErr, "status 404")
				}
			},
		},
		{
			name:  "toml transport error",
			extra: map[string]string{"stellar.toml.err": "sep1: fetch https://redirect.example/.well-known/stellar.toml: cross-host redirect from redirect.example to other.example\n"},
			check: func(t *testing.T, s *mechanics.Subject) {
				if s.Toml != nil {
					t.Error("toml errored but Toml is non-nil")
				}
				const want = "sep1: fetch https://redirect.example/.well-known/stellar.toml: cross-host redirect from redirect.example to other.example"
				if s.TomlErr != want {
					t.Errorf("TomlErr = %q, want %q", s.TomlErr, want)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeMinimalSubject(t, dir, tc.extra)
			s, err := eval.LoadSubject(dir, ".")
			if err != nil {
				t.Fatalf("LoadSubject: %v", err)
			}
			tc.check(t, s)
		})
	}
}
