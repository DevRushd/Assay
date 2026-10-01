package fixtures

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// captureDateRE matches a subject's capture-date entry. It is applied only
// inside one subject's block, so it can never move another subject's date.
var captureDateRE = regexp.MustCompile(`"capture_date"\s*:\s*"[^"]*"`)

// updateManifestCaptureDate sets one subject's capture date in the fixture
// manifest, in place.
//
// The manifest is hand-formatted (short arrays kept inline), which Go's JSON
// encoder would rearrange, so decoding and re-encoding it would show a
// whole-file diff that buries the one value that moved. Editing the matched
// bytes instead keeps every other byte exactly as it was.
//
// A subject that is not present is an error rather than a silent no-op, so a
// refreshed fixture cannot quietly lose its metadata.
func updateManifestCaptureDate(path, subject string, date time.Time) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	content := string(b)

	marker := `"fixture": "` + subject + `"`
	start := strings.Index(content, marker)
	if start < 0 {
		return fmt.Errorf("manifest %s has no subject %q", path, subject)
	}

	// A subject's fields run up to the next subject's "fixture" key; each
	// object opens with that key, so its next occurrence bounds the block.
	end := len(content)
	if next := strings.Index(content[start+len(marker):], `"fixture"`); next >= 0 {
		end = start + len(marker) + next
	}

	scope := content[start:end]
	loc := captureDateRE.FindStringIndex(scope)
	if loc == nil {
		return fmt.Errorf("subject %q has no capture_date in %s", subject, path)
	}

	replacement := `"capture_date": "` + date.Format("2006-01-02") + `"`
	updated := content[:start] + scope[:loc[0]] + replacement + scope[loc[1]:] + content[end:]

	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}
