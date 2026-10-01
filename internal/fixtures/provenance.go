// Package fixtures re-captures the labelled corpus's fixture files from the
// public sources recorded for them.
//
// Fixtures are point-in-time captures. An issuer changes its flags, a curated
// source changes a listing, and a fixture that has silently drifted from
// reality pins the wrong judgement. Re-capturing by hand is error-prone and
// nobody does it regularly, so this package turns the URLs already recorded in
// PROVENANCE.md into a repeatable command.
package fixtures

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Source is one fixture file and the recorded URL it was captured from.
type Source struct {
	// File is the fixture path relative to the fixture root, for example
	// "aqua-clear-verified/asset.json".
	File string
	// URL is the public source the file was captured from, as recorded in
	// PROVENANCE.md. Any trailing annotation such as "(captured 2026-09-25)"
	// or "(HTTP 404)" is not part of it.
	URL string
}

var (
	// captureAnnotation is the "(captured YYYY-MM-DD)" note the refresh writes
	// onto a source line.
	captureAnnotation = regexp.MustCompile(`\s*\(captured \d{4}-\d{2}-\d{2}\)`)
	// httpAnnotation matches the "(HTTP 404)" note PROVENANCE.md puts next to
	// a source that did not answer 200 at capture time.
	httpAnnotation = regexp.MustCompile(`\s*\(HTTP \d{3}\)`)
)

// ParseProvenance reads the `| file | source URL |` table out of PROVENANCE.md.
//
// PROVENANCE.md is the record of which URL each fixture came from, so it is the
// only input this package needs: parsing it means the tool cannot capture from
// a URL the file does not name.
func ParseProvenance(path string) ([]Source, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read provenance: %w", err)
	}
	var out []Source
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := strings.Split(trimmed, "|")
		if len(cells) < 3 {
			continue
		}
		file := strings.Trim(strings.TrimSpace(cells[1]), "`")
		if !strings.Contains(file, "/") {
			continue // the header row, or a stray table
		}
		url := captureAnnotation.ReplaceAllString(strings.TrimSpace(cells[2]), "")
		url = httpAnnotation.ReplaceAllString(url, "")
		url = strings.TrimSpace(url)
		if !strings.HasPrefix(url, "http") {
			continue
		}
		out = append(out, Source{File: file, URL: url})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no sources parsed from %s", path)
	}
	return out, nil
}

// SourcesFor returns the recorded sources for one subject directory.
func SourcesFor(sources []Source, subject string) []Source {
	prefix := subject + "/"
	var out []Source
	for _, s := range sources {
		if strings.HasPrefix(s.File, prefix) {
			out = append(out, s)
		}
	}
	return out
}

// annotateCapture sets the "(captured DATE)" note on every source line for a
// subject, replacing an older note when one is present. It is how a refresh
// records when the capture it just wrote happened.
func annotateCapture(content, subject, date string) string {
	lines := strings.Split(content, "\n")
	prefix := subject + "/"
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 3 {
			continue
		}
		file := strings.Trim(strings.TrimSpace(cells[1]), "`")
		if !strings.HasPrefix(file, prefix) {
			continue
		}
		src := captureAnnotation.ReplaceAllString(strings.TrimSpace(cells[2]), "")
		src = strings.TrimSpace(src) + " (captured " + date + ")"
		cells[2] = " " + src + " "
		lines[i] = strings.Join(cells, "|")
	}
	return strings.Join(lines, "\n")
}
