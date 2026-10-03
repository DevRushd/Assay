// Package version carries the scanner version identity.
//
// The version names the classifier that produced a result, which is what makes
// two eval runs comparable: a diff between runs is only meaningful if each run
// records which version of the checks produced it. It is deliberately separate
// from the outbound fetchers' User-Agent strings so that a version bump in one
// place is a deliberate decision rather than a side effect of the other.
package version

// Version is the scanner version recorded with every eval run.
//
// Bump it whenever a check's judgment changes, so a recorded eval names the
// classifier that produced it and a cross-version comparison can attribute a
// movement to a version. The value tracks the scanner release, not the
// evidence_hash encoding, which carries its own version line.
const Version = "v0.1.0"
