// Package version carries the scanner version identity.
//
// The version names the classifier that produced a result, which is what makes
// two eval runs comparable: a diff between runs is only meaningful if each run
// records which version of the checks produced it. It is deliberately separate
// from the outbound fetchers' User-Agent strings so that a version bump in one
// place is a deliberate decision rather than a side effect of the other.
//
// There is exactly one computation of that identity, here: the module version
// the Go toolchain stamped into the binary (issue #278). A release built with
//
//	go install github.com/use-assay/assay/cmd/assay@v1.2.3
//
// reports "v1.2.3", the same string `go version -m` prints for the module; a
// build from a checkout that has no version stamp reports "devel", the same
// sentinel `go version -m` prints. attest.ScannerIdentity is initialized from
// this variable, so the eval recorder's version and the v4 preimage's
// `scanner` line cannot disagree for a tagged build: both are the tag.
package version

import (
	"regexp"
	"runtime/debug"
	"strings"
)

// Version is the scanner version recorded with every eval run and bound into
// the v4 evidence preimage through attest.ScannerIdentity.
//
// It is read from the main module's version in the binary's build info; see
// the package comment for what a tagged build reports. Release tags are cut
// per CONTRIBUTING.md ("Releasing"), and a check whose judgment changes ships
// in a release with a new tag rather than under an unchanged version.
var Version = moduleVersion()

// moduleVersion reads the main module's version from the build info embedded
// by the Go toolchain. "devel" for unstamped builds mirrors what
// `go version -m` prints for a binary built from source without a version
// flag.
func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}
	return normalize(info.Main.Version)
}

// pseudoVersion matches the timestamp-and-commit tail of a Go pseudo-version,
// e.g. v0.0.0-20261018200841-38b5825719ba or v1.2.4-0.20261018200841-38b5825719ba.
var pseudoVersion = regexp.MustCompile(`(^|[-.])\d{14}-[0-9a-f]{12}(\+|$)`)

// normalize maps everything that is not a release to "devel".
//
// Since Go 1.24, `go build` in a git checkout stamps the main module with a
// pseudo-version built from the commit, plus "+dirty" for a modified tree.
// That is exactly the build-stamped commit the scanner identity rejected
// (attest.ScannerIdentity): it would make every dev build bind a different
// identity for identical evidence. So a pseudo-version, a dirty build, and an
// empty or "(devel)" version all report as "devel"; only a clean release tag
// such as v1.2.3 is passed through. `make build-release` builds with
// -buildvcs=false, which already yields "(devel)".
func normalize(v string) string {
	switch {
	case v == "", v == "(devel)":
		return "devel"
	case strings.HasSuffix(v, "+dirty"), pseudoVersion.MatchString(v):
		return "devel"
	}
	return v
}
