package main

import (
	"flag"
	"reflect"
	"testing"
)

// The flag is how a deployment says which lists are authoritative for it, so
// both accepted spellings must work: comma-separated in one flag, and the flag
// repeated. And with no flag at all, no list — because shipping a default list
// would hard-code a provider's curation as authoritative.
func TestAssetListFlagParsesBothForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"none", nil, nil},
		{"empty value", []string{"-asset-lists", ""}, nil},
		{"comma separated", []string{"-asset-lists", "a.test/list.json,b.test/list.json"},
			[]string{"a.test/list.json", "b.test/list.json"}},
		{"repeated", []string{"-asset-lists=a.test/list.json", "-asset-lists", "b.test/list.json"},
			[]string{"a.test/list.json", "b.test/list.json"}},
		{"mixed and trimmed", []string{"-asset-lists", " a.test/list.json , b.test/list.json ", "-asset-lists", "c.test/list.json"},
			[]string{"a.test/list.json", "b.test/list.json", "c.test/list.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			get := assetListFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("parse %v: %v", tc.args, err)
			}
			if got := get(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("lists = %q, want %q", got, tc.want)
			}
		})
	}
}

// Configuring lists is the only thing newScanner does beyond scan.New.
func TestNewScannerCarriesAssetLists(t *testing.T) {
	sc := newScanner([]string{"https://a.test/list.json"})
	if len(sc.AssetListURLs) != 1 || sc.AssetListURLs[0] != "https://a.test/list.json" {
		t.Errorf("AssetListURLs = %v", sc.AssetListURLs)
	}
	if sc.Lists == nil {
		t.Error("the list fetcher was not wired; Subject would fall back per call")
	}

	// And with nothing configured, a scanner must not consult any list.
	if lists := newScanner(nil).AssetListURLs; len(lists) != 0 {
		t.Errorf("a scanner with no lists configured holds %v", lists)
	}
}
