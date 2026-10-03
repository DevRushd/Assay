package main

import (
	"errors"
	"testing"
)

func TestExitCodesDefined(t *testing.T) {
	if exitCodeForError(nil) != exitSuccess {
		t.Errorf("nil error should give success (0), got %d", exitCodeForError(nil))
	}
	if exitCodeForError(errors.New("unknown command foo")) != exitUsage {
		t.Errorf("usage error should give %d, got %d", exitUsage, exitCodeForError(errors.New("unknown command foo")))
	}
	if exitCodeForError(errors.New("not found asset")) != exitMissing {
		t.Errorf("missing error should give %d, got %d", exitMissing, exitCodeForError(errors.New("not found asset")))
	}
	if exitCodeForError(errors.New("upstream timeout")) != exitUnavailable {
		t.Errorf("unavailable error should give %d, got %d", exitUnavailable, exitCodeForError(errors.New("upstream timeout")))
	}
	if exitCodeForError(errors.New("scan is undetermined")) != exitUnknown {
		t.Errorf("unknown error should give %d, got %d", exitUnknown, exitCodeForError(errors.New("scan is undetermined")))
	}
	if exitCodeForError(errors.New("random failure")) != exitGeneric {
		t.Errorf("generic error should give %d, got %d", exitGeneric, exitCodeForError(errors.New("random failure")))
	}
}

func TestExitCodePathsComprehensive(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"Success nil", nil, exitSuccess},
		{"Usage no command", errors.New("no command given"), exitUsage},
		{"Usage unknown command", errors.New("unknown command foo"), exitUsage},
		{"Usage takes exactly one asset", errors.New("scan takes exactly one asset (CODE-ISSUER)"), exitUsage},
		{"Usage invalid asset", errors.New("invalid asset format"), exitUsage},
		{"Missing not found", errors.New("resource not found"), exitMissing},
		{"Missing does not exist", errors.New("asset does not exist on ledger"), exitMissing},
		{"Unavailable timeout", errors.New("connection timeout"), exitUnavailable},
		{"Unavailable connection refused", errors.New("connection refused by peer"), exitUnavailable},
		{"Unavailable upstream error", errors.New("upstream server failure"), exitUnavailable},
		{"Unknown undetermined", errors.New("attest: scan is undetermined"), exitUnknown},
		{"Unknown unevaluated", errors.New("attest: unevaluated report"), exitUnknown},
		{"Unknown inconsistent", errors.New("attest: inconsistent state"), exitUnknown},
		{"Generic unexpected", errors.New("disk full"), exitGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeForError(tt.err); got != tt.want {
				t.Errorf("exitCodeForError(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
