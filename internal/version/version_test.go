package version

import "testing"

// A pseudo-version or a dirty build is not a release, and binding one into the
// scanner identity would give every commit its own hash for identical
// evidence. Only a clean tag passes through.
func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"":                                     "devel",
		"(devel)":                              "devel",
		"v0.0.0-20261018200841-38b5825719ba":   "devel",
		"v1.2.4-0.20261018200841-38b5825719ba": "devel",
		"v1.2.4-rc.1.0.20261018200841-38b5825719ba": "devel",
		"v0.0.0-20261018200841-38b5825719ba+dirty":  "devel",
		"v1.2.3+dirty": "devel",
		"v1.2.3":       "v1.2.3",
		"v0.1.0":       "v0.1.0",
		"v2.0.0-rc.1":  "v2.0.0-rc.1",
	}
	for in, want := range cases {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}
