package mechanics_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/mechanics"
)

// TestReportCarriesSchemaVersion is the golden test for issue #44: every
// report the engine produces marshals a schema_version field, and it is the
// first member so a consumer streaming the JSON sees the version before any
// payload. The compatibility rule the version commits to is documented on the
// field and in docs/contract-interface.md; this test pins the value so an
// accidental bump is a visible diff rather than a silent one.
func TestReportCarriesSchemaVersion(t *testing.T) {
	eng := mechanics.NewEngine()
	for _, tc := range eval.Corpus() {
		t.Run(tc.Dir, func(t *testing.T) {
			rep, err := eng.Run(context.Background(), loadSubject(t, tc.Dir))
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if rep.SchemaVersion != mechanics.ReportSchemaVersion {
				t.Fatalf("SchemaVersion = %d, want %d", rep.SchemaVersion, mechanics.ReportSchemaVersion)
			}

			raw, err := json.Marshal(rep)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			v, ok := doc["schema_version"]
			if !ok {
				t.Fatalf("report JSON has no schema_version field")
			}
			var got int
			if err := json.Unmarshal(v, &got); err != nil {
				t.Fatalf("schema_version is not a number: %v", err)
			}
			if got != mechanics.ReportSchemaVersion {
				t.Fatalf("schema_version = %d, want %d", got, mechanics.ReportSchemaVersion)
			}
			if !strings.HasPrefix(string(raw), `{"schema_version":`) {
				t.Fatalf("schema_version is not the first JSON member: %s...", string(raw[:60]))
			}
		})
	}
}
