package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestParamsForE2ESubjects pins the three fixtures the standalone test submits.
// If a fixture or a check changes, this fails before CI spends minutes starting
// a network: the e2e script's expected severities and flags are a contract.
func TestParamsForE2ESubjects(t *testing.T) {
	tests := []struct {
		subject  string
		asset    string
		severity uint32
		flags    uint32
	}{
		{"aqua-clear-verified", "AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA", 0, 0},
		{"usdz-clawback-regulated", "USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR", 3, 6},
		{"doge-noflags-scam", "DOGE-GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P", 4, 48},
	}
	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			params, asset, err := paramsForFixture("../../internal/mechanics/testdata", tt.subject, DefaultNetwork)
			if err != nil {
				t.Fatalf("paramsForFixture: %v", err)
			}
			if got := asset.String(); got != tt.asset {
				t.Fatalf("asset = %s, want %s", got, tt.asset)
			}
			if params.Severity != tt.severity || params.Flags != tt.flags {
				t.Fatalf("severity/flags = %d/%d, want %d/%d",
					params.Severity, params.Flags, tt.severity, tt.flags)
			}
			if !strings.HasPrefix(params.Preimage, "assay-evidence-v4\n") {
				t.Fatalf("preimage version = %q, want v4", strings.SplitN(params.Preimage, "\n", 2)[0])
			}
		})
	}
}

func TestRunPrintsOneTabSeparatedLine(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-subject", "aqua-clear-verified", "-fixtures", "../../internal/mechanics/testdata"}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	fields := strings.Split(strings.TrimRight(out.String(), "\n"), "\t")
	if len(fields) != 4 {
		t.Fatalf("output has %d fields, want 4: %q", len(fields), out.String())
	}
	if fields[0] != "AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA" {
		t.Errorf("asset = %q", fields[0])
	}
	if fields[1] != "0" || fields[2] != "0" {
		t.Errorf("severity/flags = %s/%s, want 0/0", fields[1], fields[2])
	}
	if len(fields[3]) != 64 {
		t.Errorf("digest %q is not 64 hex characters", fields[3])
	}
}
