// Package sep1 fetches and parses an issuer's stellar.toml (SEP-0001).
//
// Assay uses this for one purpose: reciprocal domain verification. An issuer
// account advertises a home_domain; SEP-1 says that domain publishes a
// stellar.toml at /.well-known/stellar.toml. The link is only meaningful in
// both directions — the account points at the domain, and the domain's
// CURRENCIES list points back at the asset. Either half alone proves nothing,
// because anyone can set home_domain to any string.
//
// This is an extraction candidate for a shared ledger-access library.
package sep1

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
)

// version is kept here so every outbound client reports the same tool
// version in its User-Agent. Bump it alongside any scanner-version release;
// the API documents the value in release notes.
const version = "v0.1.0"

// MaxBody caps the stellar.toml read. Real files are a few KB; this stops a
// hostile domain from streaming an unbounded body at the scanner. It is
// exported so the resource-exhaustion tests can assert that a reader is never
// asked for more than this, rather than assuming it.
const MaxBody = 1 << 20 // 1 MiB

// MaxLinkedDocuments bounds how many per-currency TOML links Assay follows for
// a single issuer stellar.toml. SEP-0001 allows a CURRENCIES entry to carry
// `toml="https://DOMAIN/.well-known/CURRENCY.toml"` as its only field, and a
// hostile or merely large issuer can publish thousands of them. The scanner is
// a network client, so the number of follow-up fetches one issuer can make it
// perform has to be finite and small. When the bound is hit the answer is left
// unresolved rather than refuted, because the documents past this point were
// never read.
const MaxLinkedDocuments = 8

// ErrNoDomain reports that the issuer account advertises no home_domain, so
// there is nothing to verify against.
var ErrNoDomain = errors.New("sep1: issuer has no home_domain")

// ErrNonPublicHost reports that home_domain named a host Assay refuses to
// fetch from: loopback, a private or link-local address, the cloud metadata
// address, or a name that cannot be public (localhost, a *.local/*.internal
// name, a bare single-label hostname).
//
// home_domain is attacker-controlled free text that is turned into a URL. When
// Assay runs as a server — which `assay serve` and the deployed API both do —
// fetching it without a check is a request-forgery primitive against whatever
// the server can reach. The refusal is deliberate and is recorded as
// attributed evidence, not smoothed into an ordinary source outage.
var ErrNonPublicHost = errors.New("sep1: home_domain names a non-public host")

// HostRefusedError is returned when a fetch is refused by host policy. It is
// distinguishable from an ordinary fetch failure (errors.Is with
// ErrNonPublicHost, or a type assertion) so a caller can record a refusal as a
// refusal rather than as an outage, and from a timeout by its concrete type.
type HostRefusedError struct {
	// Host is the host that was refused.
	Host string
	// Reason states which property disqualified it.
	Reason string
}

func (e *HostRefusedError) Error() string {
	return fmt.Sprintf("sep1: refusing non-public host %q: %s", e.Host, e.Reason)
}

// Unwrap reports ErrNonPublicHost so errors.Is works through any wrapping.
func (e *HostRefusedError) Unwrap() error { return ErrNonPublicHost }

// ClassifyHost reports whether host may be fetched from, and when it may not,
// why. It decides on the literal host only: a name that is not obviously
// non-public is allowed, and a name that resolves to a non-public address is
// refused later, at connect time, by CheckDialAddress. That split is what keeps
// this function pure and testable without a network while still covering the
// addresses that actually get connected to.
func ClassifyHost(host string) (public bool, reason string) {
	h := strings.TrimSpace(strings.ToLower(host))
	h = strings.Trim(h, "[]") // bracketed IPv6 literal
	if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		// host:port, e.g. an IPv4 literal or a hostname carrying a port.
		h = h[:i]
	}
	if h == "" {
		return false, "empty host"
	}

	if addr, err := netip.ParseAddr(h); err == nil {
		return classifyAddr(addr)
	}

	// Obvious non-public names. These are never resolvable to a public address
	// by a correct resolver, so refusing them costs nothing and names the
	// reason precisely.
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return false, "loopback hostname"
	}
	for _, suffix := range []string{".local", ".localdomain", ".internal", ".home.arpa", ".lan", ".corp"} {
		if strings.HasSuffix(h, suffix) {
			return false, "non-public name suffix " + suffix
		}
	}
	if !strings.Contains(h, ".") {
		return false, "single-label hostname"
	}
	return true, ""
}

// metadataAddr is the cloud instance metadata endpoint most providers expose.
var metadataAddr = netip.AddrFrom4([4]byte{169, 254, 169, 254})

// classifyAddr applies the non-public-address policy to one IP literal.
func classifyAddr(addr netip.Addr) (bool, string) {
	a := addr.Unmap()
	switch {
	case a == metadataAddr:
		return false, "cloud metadata address 169.254.169.254"
	case a.IsLoopback():
		return false, "loopback address"
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return false, "link-local address"
	case a.IsPrivate():
		return false, "private address (RFC 1918 / RFC 4193)"
	case a.IsUnspecified():
		return false, "unspecified address"
	case a.IsMulticast():
		return false, "multicast address"
	}
	if a.Is4() {
		b := a.As4()
		switch {
		case b[0] == 0:
			return false, "reserved IPv4 range 0.0.0.0/8"
		case b[0] == 100 && b[1] >= 64 && b[1] <= 127:
			return false, "shared address space 100.64.0.0/10 (RFC 6598)"
		case b[0] == 192 && b[1] == 0 && b[2] == 0:
			return false, "reserved IPv4 range 192.0.0.0/24"
		case b[0] == 198 && (b[1] == 18 || b[1] == 19):
			return false, "benchmarking range 198.18.0.0/15"
		case b[0] >= 240:
			return false, "reserved IPv4 range 240.0.0.0/4"
		}
	}
	return true, ""
}

// CheckDialAddress is the guard installed on the default fetcher's dialer. It
// runs on the concrete address a connection is about to use, so a hostname
// that resolves to a non-public address is refused — including one whose
// answer changes between the resolve and the connect that follows it (DNS
// rebinding), because there is no resolve-then-connect window to exploit here.
//
// It is exported so the guard can be tested against literal addresses without
// a network. The policy is only as complete as the callers that install it:
// a caller that replaces Fetcher.HTTP.Transport replaces this guard too.
func CheckDialAddress(address string) error {
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	if public, reason := ClassifyHost(host); !public {
		return &HostRefusedError{Host: host, Reason: reason}
	}
	return nil
}

// Currency is one [[CURRENCIES]] entry.
type Currency struct {
	Code   string `toml:"code"`
	Issuer string `toml:"issuer"`
	Name   string `toml:"name"`
	Status string `toml:"status"`
	// Toml is set when the entry links to another stellar.toml. SEP-0001 does
	// not require such an entry to be link-only: it may also carry a code and
	// issuer, and both fields are then meaningful.
	Toml string `toml:"toml"`
}

// Doc is the subset of stellar.toml that Assay reads.
type Doc struct {
	Currencies []Currency `toml:"CURRENCIES"`
	// URL is the location the document was actually fetched from, after
	// redirects. It can differ from the requested URL.
	URL string `toml:"-"`
	// FetchedAt records when this document was retrieved.
	FetchedAt time.Time `toml:"-"`
}

// matches reports whether this entry declares the given asset inline.
//
// It is the single implementation of the matching rule so that "an entry that
// matches" means exactly the same thing to Claims and to LinkedCurrencies:
// code AND issuer, never code alone. If the two ever disagreed, an entry could
// be counted as an unresolved link at the same time as it satisfies Claims,
// and the domain check would hedge on an asset it had already verified.
func (c Currency) matches(code, issuer string) bool {
	return strings.EqualFold(c.Code, code) && strings.EqualFold(c.Issuer, issuer)
}

// Claims reports whether the document declares the given asset, matching on
// both code and issuer. Matching on code alone would let any domain claim any
// asset code, which is the exact failure this check exists to prevent.
func (d *Doc) Claims(code, issuer string) bool {
	if d == nil {
		return false
	}
	for _, c := range d.Currencies {
		if c.matches(code, issuer) {
			return true
		}
	}
	return false
}

// LinkedCurrencies counts entries that delegate to a separate per-currency
// TOML file — entries carrying a `toml` link — and that do not themselves
// already declare this asset inline.
//
// SEP-0001 lets a currency entry carry
// `toml="https://DOMAIN/.well-known/CURRENCY.toml"`, and does not require that
// link to be the entry's only field: one entry may carry the link alongside a
// code and issuer. What matters here is not the shape of the entry but whether
// the link is a claim Assay has not read: an entry that already matches inline
// is a claim we did see and needs no hedge, while an entry that does not match
// inline may be pointing at a document that does claim the asset. Because
// Assay does not follow those links yet, a non-zero count is the difference
// between "this domain did not claim the asset" and "this domain may have
// claimed it in a document we did not read". Those must never be reported the
// same way, so the count must not depend on the entry happening to also carry
// a code.
func (d *Doc) LinkedCurrencies(code, issuer string) int {
	if d == nil {
		return 0
	}
	n := 0
	for _, c := range d.Currencies {
		if c.Toml == "" {
			continue
		}
		// Already claimed inline: the link cannot make this asset any more
		// claimed than it already is, so it is not an unresolved delegation.
		if c.matches(code, issuer) {
			continue
		}
		n++
	}
	return n
}

// LinkedDoc is the outcome of following one per-currency TOML link.
type LinkedDoc struct {
	// URL is the link that was followed.
	URL string
	// Doc is the parsed document, when the link resolved.
	Doc *Doc
	// Err records why the link did not resolve, verbatim. It is empty on
	// success.
	Err string
	// Refused reports that Err is a host-policy refusal rather than an
	// ordinary fetch failure. It is the programmatic form of the distinction
	// HostRefusedError carries.
	Refused bool
}

// LinkedResolution is the outcome of following the per-currency TOML links in
// a stellar.toml. A nil resolution means links were not followed at all, which
// is deliberately distinct from an empty one.
type LinkedResolution struct {
	// Attempted is how many links were followed.
	Attempted int
	// Deferred is how many links were left unfollowed because
	// MaxLinkedDocuments was reached.
	Deferred int
	// Claimed reports that a followed document names the asset.
	Claimed bool
	// ClaimedURL is the URL of the document that claimed the asset, when
	// Claimed is set.
	ClaimedURL string
	// Docs records each followed document and its outcome, in link order.
	Docs []LinkedDoc
}

// ResolveLinked follows up to MaxLinkedDocuments per-currency TOML links from
// d and reports whether any of them claims code/issuer.
//
// It performs at most one hop: a linked document's own links are not followed,
// so a cycle cannot make the scanner fetch forever. Every fetch goes through
// the same host policy, size cap, timeout and scheme rule as the main document.
// A link that cannot be read is recorded and left unresolved rather than being
// treated as a document that did not claim the asset.
func (f *Fetcher) ResolveLinked(ctx context.Context, d *Doc, code, issuer string) *LinkedResolution {
	res := &LinkedResolution{Docs: []LinkedDoc{}}
	if d == nil {
		return res
	}

	links := make([]string, 0, len(d.Currencies))
	for _, c := range d.Currencies {
		if c.Toml != "" && c.Code == "" && c.Issuer == "" {
			links = append(links, c.Toml)
		}
	}
	if len(links) > MaxLinkedDocuments {
		res.Deferred = len(links) - MaxLinkedDocuments
		links = links[:MaxLinkedDocuments]
	}

	for _, link := range links {
		res.Attempted++
		doc, err := f.fetch(ctx, link)
		if err != nil {
			ld := LinkedDoc{URL: link, Err: err.Error(), Refused: errors.Is(err, ErrNonPublicHost)}
			res.Docs = append(res.Docs, ld)
			continue
		}
		res.Docs = append(res.Docs, LinkedDoc{URL: link, Doc: doc})
		if doc.Claims(code, issuer) {
			res.Claimed = true
			res.ClaimedURL = link
			return res
		}
	}
	return res
}

// Fetcher retrieves stellar.toml documents.
type Fetcher struct {
	HTTP      *http.Client
	UserAgent string
}

// NewFetcher returns a Fetcher with a bounded timeout and the host policy
// installed on its default transport.
//
// The transport deliberately does not use http.DefaultTransport: the default
// honours HTTP_PROXY/HTTPS_PROXY and would let a proxy make the connection the
// guard exists to forbid. It also carries a dial-time guard so a home_domain
// that resolves to a private address is refused at connect time.
func NewFetcher() *Fetcher {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return CheckDialAddress(address)
		},
	}
	return &Fetcher{
		HTTP: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext:       dialer.DialContext,
				ForceAttemptHTTP2: true,
			},
		},
		UserAgent: "assay/" + version + " (+https://github.com/use-assay/Assay)",
	}
}

// CheckRedirect is the redirect policy every Fetcher installs. It does two
// things, both deliberate:
//
//   - It bounds the chain at MaxRedirects rather than following whatever the
//     client's default is.
//   - It refuses a redirect that leaves the requested host's namespace. A
//     stellar.toml is a claim made by the domain in home_domain; if a redirect
//     could relocate the fetch to an unrelated host, that host's document would
//     be recorded as this domain's claim, and home_domain is attacker-
//     controlled free text. The final host is named in the error so a reader can
//     see where the fetch was being sent.
//
// The policy test is one-directional: the target must be the requested host or
// a subdomain of it. That admits the common apex-to-www move (circle.com →
// www.circle.com) while refusing a hop from a subdomain up to a parent domain,
// which may be a shared host whose content another party controls. See
// docs/checks.md for the reasoning.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= MaxRedirects {
		return fmt.Errorf("stopped after %d redirects", MaxRedirects)
	}
	// net/http always supplies the chain so far; refuse rather than index an
	// empty slice if this is ever called directly.
	if len(via) == 0 {
		return fmt.Errorf("redirect with no preceding request")
	}
	origin := via[0].URL.Hostname()
	final := req.URL.Hostname()
	if !withinRequestedSite(origin, final) {
		return fmt.Errorf("cross-host redirect from %s to %s", origin, final)
	}
	return nil
}

// withinRequestedSite reports whether final is origin itself or a subdomain of
// it, comparing labels case-insensitively and ignoring the root-trailing dot.
func withinRequestedSite(origin, final string) bool {
	origin = normalizeHost(origin)
	final = normalizeHost(final)
	if origin == "" || final == "" {
		return false
	}
	return final == origin || strings.HasSuffix(final, "."+origin)
}

// normalizeHost lowercases a host and strips a single trailing root dot, so
// "Circle.COM." and "circle.com" compare equal.
func normalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// URLFor returns the SEP-1 well-known location for a domain.
func URLFor(domain string) string {
	return "https://" + strings.TrimSuffix(domain, "/") + "/.well-known/stellar.toml"
}

// Fetch retrieves and parses the stellar.toml for domain.
//
// It refuses a domain that names a non-public host before making any request,
// returning a *HostRefusedError. The in-flight check for a hostname that
// resolves to a non-public address lives on the default transport (see
// NewFetcher); when the caller supplies its own client the literal check here
// still applies, and the caller owns the rest of the policy.
func (f *Fetcher) Fetch(ctx context.Context, domain string) (*Doc, error) {
	if domain == "" {
		return nil, ErrNoDomain
	}
	return f.fetch(ctx, URLFor(domain))
}

// fetch retrieves and parses a stellar.toml at an absolute URL. It is the
// single request path for both the main document and the per-currency links
// SEP-0001 permits, so both are subject to the same host, scheme, size and
// timeout bounds.
func (f *Fetcher) fetch(ctx context.Context, target string) (*Doc, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("sep1: parse %s: %w", target, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("sep1: refusing non-https document %q", target)
	}
	if public, reason := ClassifyHost(u.Hostname()); !public {
		return nil, &HostRefusedError{Host: u.Hostname(), Reason: reason}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.UserAgent)

	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sep1: fetch %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sep1: fetch %s: status %d", target, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return nil, fmt.Errorf("sep1: read %s: %w", target, err)
	}

	doc, err := Parse(body)
	if err != nil {
		return nil, fmt.Errorf("sep1: parse %s: %w", target, err)
	}
	doc.URL = resp.Request.URL.String()
	doc.FetchedAt = time.Now().UTC()
	return doc, nil
}

// Parse decodes stellar.toml bytes.
func Parse(b []byte) (*Doc, error) {
	var d Doc
	if err := toml.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}
