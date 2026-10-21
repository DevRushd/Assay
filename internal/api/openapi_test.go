package api_test

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/api"
)

// TestOpenAPICoversAllRegisteredRoutes fails when the server's HTTP surface
// and the OpenAPI document drift apart. api.Routes is the list Handler
// registers from, so adding a route without a schema entry leaves the test
// red until openapi.yaml documents it.
func TestOpenAPICoversAllRegisteredRoutes(t *testing.T) {
	documented := parseOpenAPIPaths(t, readOpenAPI(t))

	registered := make(map[string]struct{}, len(api.Routes))
	for _, route := range api.Routes {
		_, path, ok := strings.Cut(route, " ")
		if !ok || path == "" {
			t.Fatalf("registered route %q is not in \"METHOD /path\" form", route)
		}
		registered[path] = struct{}{}
		if _, ok := documented[path]; !ok {
			t.Errorf("route %s is registered by api.Server but missing from openapi.yaml", route)
		}
	}

	for path := range documented {
		if _, ok := registered[path]; !ok {
			t.Errorf("openapi.yaml documents %s, but api.Server does not register it", path)
		}
	}
}

// readOpenAPI returns openapi.yaml from the repository root, located relative
// to this test file so it works regardless of the directory go test runs in.
func readOpenAPI(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "openapi.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// parseOpenAPIPaths extracts the path keys under the top-level paths map. A
// line scan is enough: path keys are the only entries indented exactly two
// spaces whose trimmed text starts with "/" and ends with ":".
func parseOpenAPIPaths(t *testing.T, doc string) map[string]struct{} {
	t.Helper()

	paths := map[string]struct{}{}
	inPaths := false
	scanner := bufio.NewScanner(strings.NewReader(doc))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if !inPaths {
			if trimmed == "paths:" {
				inPaths = true
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// A non-indented key ends the paths map.
		if line[0] != ' ' {
			break
		}
		if len(line)-len(strings.TrimLeft(line, " ")) != 2 {
			continue
		}
		if !strings.HasPrefix(trimmed, "/") || !strings.HasSuffix(trimmed, ":") {
			continue
		}
		paths[strings.TrimSuffix(trimmed, ":")] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan openapi.yaml: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("openapi.yaml has no path keys; the coverage test would pass vacuously")
	}
	return paths
}
