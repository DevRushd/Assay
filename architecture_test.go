package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// getRepoRoot returns the absolute path to the repository root.
func getRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(thisFile)
}

// getModulePath parses the module declaration from go.mod.
func getModulePath(t *testing.T, repoRoot string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module"))
		}
	}
	t.Fatal("module path not found in go.mod")
	return ""
}

// parseArchitectureMap extracts package paths from the table in docs/architecture.md.
func parseArchitectureMap(t *testing.T, content string) map[string]bool {
	t.Helper()

	// Locate the "## Package map" section.
	const header = "## Package map"
	idx := strings.Index(content, header)
	if idx < 0 {
		t.Fatalf("could not find %q section in architecture doc", header)
	}
	section := content[idx+len(header):]

	// End at the Soroban contracts subsection or next ## section if present.
	if end := strings.Index(section, "The two Soroban contracts:"); end >= 0 {
		section = section[:end]
	} else if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}

	// Match table rows where the first column is a backtick-quoted package path.
	rowRe := regexp.MustCompile(`(?m)^\|\s*` + "`" + `([^` + "`" + `]+)` + "`" + `\s*\|`)
	matches := rowRe.FindAllStringSubmatch(section, -1)

	mapped := make(map[string]bool, len(matches))
	for _, m := range matches {
		mapped[strings.TrimSpace(m[1])] = true
	}
	return mapped
}

// listGoPackages executes `go list ./...` to discover all Go packages in the module.
func listGoPackages(t *testing.T, repoRoot string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "./...")
	cmd.Dir = repoRoot
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go list ./... failed: %v\nstderr: %s", err, stderr.String())
	}

	modulePath := getModulePath(t, repoRoot)
	var pkgs []string
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == modulePath {
			continue // skip empty lines and the module root
		}
		rel := strings.TrimPrefix(line, modulePath+"/")
		pkgs = append(pkgs, rel)
	}
	return pkgs
}

// TestArchitectureMapCoversAllPackages fails when any Go package in this
// module is missing from the package map table in docs/architecture.md (#452).
//
// The architecture map is the single place that shows how the pieces fit
// together and the boundary each package must respect. A package without a row
// in the map is architectural drift that violates the rule the doc states.
func TestArchitectureMapCoversAllPackages(t *testing.T) {
	repoRoot := getRepoRoot(t)
	docPath := filepath.Join(repoRoot, "docs", "architecture.md")
	docBytes, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	mapped := parseArchitectureMap(t, string(docBytes))
	if len(mapped) == 0 {
		t.Fatalf("no package rows found in %s", docPath)
	}

	goPackages := listGoPackages(t, repoRoot)
	if len(goPackages) == 0 {
		t.Fatal("go list ./... returned no packages")
	}

	var missing []string
	for _, pkg := range goPackages {
		if !mapped[pkg] {
			missing = append(missing, pkg)
		}
	}

	if len(missing) > 0 {
		t.Errorf("the following Go packages are missing from docs/architecture.md:\n  %s\n"+
			"Every Go package must have a row in the Package map table stating its responsibility and boundary.",
			strings.Join(missing, "\n  "))
	}
}

// TestArchitectureMapDetectsMissingPackage asserts that parseArchitectureMap
// and package comparison correctly identifies unmapped packages (#452).
func TestArchitectureMapDetectsMissingPackage(t *testing.T) {
	doc := `
## Package map

| Package | Responsibility | Boundary |
| --- | --- | --- |
| ` + "`cmd/assay`" + ` | CLI | Process entry point |
| ` + "`internal/api`" + ` | HTTP API | Inbound HTTP |

The two Soroban contracts:
`
	mapped := parseArchitectureMap(t, doc)
	pkgs := []string{"cmd/assay", "internal/api", "internal/scan"}

	var missing []string
	for _, pkg := range pkgs {
		if !mapped[pkg] {
			missing = append(missing, pkg)
		}
	}

	if len(missing) != 1 || missing[0] != "internal/scan" {
		t.Fatalf("expected missing [internal/scan], got %v", missing)
	}
}
