package mechanics

import "strings"

// AdverseDirectoryTags is the reviewed set of StellarExpert tags that
// escalate an issuer listing to critical.
var AdverseDirectoryTags = []string{"malicious", "unsafe"}

type directoryTagClass uint8

const (
	directoryTagUnknown directoryTagClass = iota
	directoryTagDescriptive
	directoryTagAdverse
)

var descriptiveDirectoryTags = map[string]struct{}{
	"issuer": {}, "anchor": {}, "exchange": {}, "wallet": {}, "custodian": {},
	"personal": {}, "sdf": {}, "memo-required": {}, "airdrop": {},
	"obsolete-inflation-pool": {},
}

func classifyDirectoryTag(tag string) directoryTagClass {
	tag = strings.ToLower(strings.TrimSpace(tag))
	for _, adverse := range AdverseDirectoryTags {
		if tag == adverse {
			return directoryTagAdverse
		}
	}
	if _, ok := descriptiveDirectoryTags[tag]; ok {
		return directoryTagDescriptive
	}
	return directoryTagUnknown
}
