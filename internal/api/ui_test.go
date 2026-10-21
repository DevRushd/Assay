package api_test

import (
	"os"
	"strings"
	"testing"
)

// TestUIIndexBuildsDOMWithoutInnerHTML enforces the invariant issue #418
// established: issuer-controlled strings (directory name, domain, toml claims)
// reach the page only through textContent, never through an HTML-parsing sink.
// A regression here is a stored XSS on any page that renders a scan, so it
// fails the build rather than waiting for a manual review.
//
// This is a static check over the single-file UI rather than a headless render
// because the page is the whole surface: with no sink present, hostile input
// can only arrive as text.
func TestUIIndexBuildsDOMWithoutInnerHTML(t *testing.T) {
	src, err := os.ReadFile("ui/index.html")
	if err != nil {
		t.Fatalf("read ui/index.html: %v", err)
	}
	html := string(src)

	for _, sink := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"} {
		if strings.Contains(html, sink) {
			t.Errorf("ui/index.html uses %s; build nodes with textContent so issuer-controlled strings cannot be parsed as markup", sink)
		}
	}

	// The guard is only meaningful if the page renders dynamic text at all;
	// assert the safe sink is the one actually in use.
	if !strings.Contains(html, "textContent") {
		t.Error("ui/index.html has no textContent assignment: the DOM-construction path this test guards is missing")
	}
}
