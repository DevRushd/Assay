package fixtures

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// maxBody caps a captured response. Fixtures are kilobytes; the cap stops a
// broken or hostile source from streaming an unbounded body into the repository.
const maxBody = 4 << 20 // 4 MiB

// Refresher re-captures fixture files from the URLs recorded for them.
type Refresher struct {
	// Client performs the fetches. A nil Client uses http.DefaultClient.
	Client *http.Client
	// Now supplies the capture date written back to the metadata. A nil Now
	// uses time.Now.
	Now func() time.Time
}

// Change is one fixture file whose re-captured content differs from what is
// committed, or which does not exist yet.
type Change struct {
	// File is the fixture path relative to the fixture root.
	File string
	// Old is the committed content, nil when the file is new.
	Old []byte
	// New is the re-captured content that will replace it.
	New []byte
}

// Result reports what a refresh found and, when it wrote, what changed.
type Result struct {
	// Subject is the fixture directory that was refreshed.
	Subject string
	// Changed lists the files that differ from their committed content.
	Changed []Change
}

// Refresh re-captures one subject from the URLs recorded in PROVENANCE.md and,
// when write is true, replaces the fixture files and refreshes the capture date
// in PROVENANCE.md and manifest.json.
//
// A fetch that fails aborts before anything is written. A partial or empty
// fixture is worse than a stale one because it silently pins the wrong
// judgement, so an unreachable source never overwrites an existing fixture.
func (r *Refresher) Refresh(ctx context.Context, root, subject string, write bool) (*Result, error) {
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}

	sources, err := ParseProvenance(filepath.Join(root, "PROVENANCE.md"))
	if err != nil {
		return nil, err
	}
	sources = SourcesFor(sources, subject)
	if len(sources) == 0 {
		return nil, fmt.Errorf("subject %q has no recorded sources in %s", subject, filepath.Join(root, "PROVENANCE.md"))
	}

	// Fetch everything first. Only once every source has answered is anything
	// written, so a single outage cannot leave the subject half-captured.
	fetched := make(map[string][]byte, len(sources))
	for _, s := range sources {
		body, err := r.fetch(ctx, client, s)
		if err != nil {
			return nil, err
		}
		fetched[s.File] = body
	}

	res := &Result{Subject: subject}
	for _, s := range sources {
		path := filepath.Join(root, filepath.FromSlash(s.File))
		old, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read %s: %w", s.File, err)
		}
		body := normalizeJSON(fetched[s.File], old)
		if bytes.Equal(old, body) {
			continue
		}
		res.Changed = append(res.Changed, Change{File: s.File, Old: old, New: body})
	}

	if write && len(res.Changed) > 0 {
		if err := writeAll(root, subject, now(), res.Changed); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// fetch retrieves one recorded source.
//
// A ".status" fixture records why an issuer's stellar.toml is absent, so its
// capture is the HTTP status rather than a body. Any other non-200, or a
// transport failure, is returned as an error so the caller writes nothing.
func (r *Refresher) fetch(ctx context.Context, client *http.Client, s Source) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", s.URL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", s.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if strings.HasSuffix(s.File, ".status") {
		if resp.StatusCode == http.StatusOK {
			return nil, fmt.Errorf("%s now serves a stellar.toml (status 200); add the file by hand", s.URL)
		}
		return []byte(strconv.Itoa(resp.StatusCode)), nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", s.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.URL, err)
	}
	return body, nil
}

// writeAll replaces the changed files and then records the capture date.
func writeAll(root, subject string, date time.Time, changes []Change) error {
	for _, c := range changes {
		path := filepath.Join(root, filepath.FromSlash(c.File))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("create directory for %s: %w", c.File, err)
		}
		if err := os.WriteFile(path, c.New, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", c.File, err)
		}
	}

	provPath := filepath.Join(root, "PROVENANCE.md")
	prov, err := os.ReadFile(provPath)
	if err != nil {
		return fmt.Errorf("read provenance: %w", err)
	}
	day := date.Format("2006-01-02")
	if err := os.WriteFile(provPath, []byte(annotateCapture(string(prov), subject, day)), 0o644); err != nil {
		return fmt.Errorf("update provenance: %w", err)
	}
	return updateManifestCaptureDate(filepath.Join(root, "manifest.json"), subject, date)
}

// normalizeJSON lays a captured JSON body out the way the file it replaces was
// laid out, so a re-capture shows a value change rather than a whole-file
// reformat. It returns the committed bytes unchanged when the two are
// semantically identical — the common case, and one that must produce no diff.
//
// Non-JSON fixtures (a stellar.toml, a *.status) are returned verbatim.
func normalizeJSON(newBody, oldBody []byte) []byte {
	if !json.Valid(newBody) {
		return newBody
	}
	if oldBody != nil && json.Valid(oldBody) {
		var nv, ov any
		if decodeJSON(newBody, &nv) == nil && decodeJSON(oldBody, &ov) == nil && reflect.DeepEqual(ov, nv) {
			return oldBody
		}
	}

	var buf bytes.Buffer
	// json.Indent and json.Compact preserve key order and do not HTML-escape,
	// which keeps a URL's "&" intact.
	if isMultiLine(oldBody) {
		if err := json.Indent(&buf, newBody, "", "  "); err != nil {
			return newBody
		}
	} else {
		if err := json.Compact(&buf, newBody); err != nil {
			return newBody
		}
	}
	return append(buf.Bytes(), '\n')
}

// isMultiLine reports whether a committed fixture was written indented. The
// trailing newline every fixture carries is not a line break for this purpose.
func isMultiLine(oldBody []byte) bool {
	if oldBody == nil {
		return true // a new file gets the readable layout
	}
	return bytes.Contains(bytes.TrimRight(oldBody, "\n"), []byte("\n"))
}

func decodeJSON(b []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(out)
}
