// Package scan assembles a mechanics.Subject from live sources and runs the
// engine over it.
//
// This is the only place in Assay that performs network I/O for a scan. It
// exists so that the checks never do: every fetch happens here, once, and the
// result is handed to pure classifiers. That split is what makes the checks
// testable without a network and keeps each fetcher independently extractable.
package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/use-assay/assay/internal/assetlist"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/sep1"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// DefaultFetchTimeout is the maximum duration allocated to any single source fetch.
// Five total fetches (two sequential ledger fetches and three concurrent post-account fetches)
// at 6s each sum to 30s, matching the outer context budget in main.go and api.go.
const DefaultFetchTimeout = 6 * time.Second

// issuerRE matches a Stellar ed25519 public key.
var issuerRE = regexp.MustCompile(`^G[A-Z2-7]{55}$`)

// codeRE matches a valid classic asset code (1-12 alphanumeric).
var codeRE = regexp.MustCompile(`^[A-Za-z0-9]{1,12}$`)

// ErrBadAsset reports an unparseable asset identifier.
var ErrBadAsset = errors.New("scan: invalid asset")

// ErrBadHolder reports an invalid holder account ID.
var ErrBadHolder = errors.New("scan: invalid holder account ID")

// ValidateHolder checks that id is a valid Stellar ed25519 public key suitable
// for use as a holder account ID.
func ValidateHolder(id string) error {
	if !issuerRE.MatchString(id) {
		return fmt.Errorf("%w: %q", ErrBadHolder, id)
	}
	return nil
}

// ParseAsset accepts the canonical CODE-ISSUER form and validates both halves.
func ParseAsset(s string) (mechanics.Asset, error) {
	s = strings.TrimSpace(s)
	code, issuer, ok := strings.Cut(s, "-")
	if !ok {
		return mechanics.Asset{}, fmt.Errorf("%w: expected CODE-ISSUER, got %q", ErrBadAsset, s)
	}
	// Trailing "-1"/"-2" suffixes appear in some explorer asset identifiers.
	if i := strings.Index(issuer, "-"); i >= 0 {
		issuer = issuer[:i]
	}
	if !codeRE.MatchString(code) {
		return mechanics.Asset{}, fmt.Errorf("%w: bad asset code %q", ErrBadAsset, code)
	}
	if !issuerRE.MatchString(issuer) {
		return mechanics.Asset{}, fmt.Errorf("%w: bad issuer %q", ErrBadAsset, issuer)
	}
	return mechanics.Asset{Code: code, Issuer: issuer}, nil
}

// Scanner fetches subject state and classifies it.
type Scanner struct {
	Horizon *horizon.Client
	Toml    *sep1.Fetcher
	Expert  *stellarexpert.Client
	Engine  *mechanics.Engine
	// Lists fetches the configured SEP-0042 Stellar Asset Lists.
	Lists *assetlist.Client

	// FetchTimeout bounds any single source fetch. Zero means DefaultFetchTimeout.
	FetchTimeout time.Duration

	// Network is the Stellar network the scan claims to read, named by the
	// full network passphrase. It is stamped onto every Subject and bound
	// into the evidence preimage from v3 on.
	//
	// Subject assembly cross-checks the claim against the Horizon base URL
	// and fails closed when they contradict or when neither can name the
	// network: the same CODE-ISSUER can exist on two networks with different
	// flags (#41), so a wrong or guessed network name is not a cosmetic
	// mistake, it is a false attestation.
	Network horizon.Network

	// AssetListURLs are the curated lists consulted for every scan, in order.
	//
	// It is empty by default, deliberately: no list is shipped as
	// authoritative, and shipping a default one would also add evidence to
	// every report — which changes every evidence_hash, including for assets
	// already attested. Configure it explicitly (or with -asset-lists) and each
	// list is attributed separately by name and URL.
	AssetListURLs []string
}

// Options configures a Scanner.
//
// The cache options exist because every scan consumes a free, third-party
// service, and the cost of not re-reading it is staleness. Which way to trade
// is a deployment's to make, not a constant's: a one-shot CLI scan can afford
// to re-fetch everything, while a long-lived server answering repeated scans of
// the same issuer should not rebuild them from scratch each time. The default
// is the conservative one documented in docs/caching.md.
//
// Ledger lookups are deliberately NOT covered here. See NewWithOptions.
type Options struct {
	// ReputationDirectoryTTL and ReputationBlocklistTTL bound how long a
	// curated StellarExpert answer may be reused, measured from the fetch that
	// produced it. A zero TTL disables caching of that source.
	ReputationDirectoryTTL time.Duration
	ReputationBlocklistTTL time.Duration

	// NoReputationCache disables the reputation cache outright: every scan
	// re-fetches both curated sources. Use it when a stale answer would be
	// unacceptable and the extra requests are affordable.
	NoReputationCache bool
}

// DefaultOptions returns the production cache policy.
func DefaultOptions() Options {
	return Options{
		ReputationDirectoryTTL: stellarexpert.DefaultDirectoryTTL,
		ReputationBlocklistTTL: stellarexpert.DefaultBlocklistTTL,
	}
}

// New returns a Scanner wired to the public production sources with the
// default cache policy. The default Horizon endpoint is SDF pubnet, so the
// scanner declares pubnet; a scan pointed elsewhere must set Network
// explicitly or Subject fails rather than guessing.
func New() *Scanner {
	return NewWithOptions(DefaultOptions())
}

// NewWithOptions returns a Scanner wired to the public production sources with
// the given cache policy.
//
// Two environment variables override the upstream endpoints, to let the
// reproducibility job (and anyone debugging it) point a source at an
// unreachable address and exercise the undetermined path without editing
// code:
//
//	ASSAY_HORIZON_URL        overrides Horizon's base URL
//	ASSAY_STELLAREXPERT_URL  overrides StellarExpert's API root
//
// Empty means the public default. Anything else is used verbatim, so
// pointing one at http://127.0.0.1:1 makes that source fail and the scan
// report undetermined (or fail, for Horizon) rather than succeed.
//
// Only the reputation lookups are cached. Horizon is left uncached on purpose:
// issuer authorization flags are the capability axis severity is derived from,
// they can change in one ledger close (~5 s), and there is no retrieved-at
// field in an attestation that could carry the age of a stale flag read. A TTL
// short enough to be honest about the ledger would not save a request; a TTL
// long enough to save one would misstate the issuer's power. See
// docs/caching.md.
func NewWithOptions(opts Options) *Scanner {
	return &Scanner{
		Horizon: horizon.New(os.Getenv("ASSAY_HORIZON_URL")),
		Toml:    sep1.NewFetcher(),
		Expert:  stellarexpert.NewWithOptions(os.Getenv("ASSAY_STELLAREXPERT_URL"), expertOptions(opts)),
		Engine:  mechanics.NewEngine(),
		Lists:   assetlist.New(),
		Network: horizon.PublicNet,
	}
}

// expertOptions maps a Scanner's cache policy onto the StellarExpert client's.
func expertOptions(opts Options) stellarexpert.Options {
	o := stellarexpert.DefaultOptions()
	o.DirectoryTTL = opts.ReputationDirectoryTTL
	o.BlocklistTTL = opts.ReputationBlocklistTTL
	if opts.NoReputationCache {
		o.DirectoryTTL = 0
		o.BlocklistTTL = 0
	}
	return o
}

// resolveNetwork decides which network a scan is on.
//
// The declared network and the Horizon endpoint must agree, and every
// combination that cannot name exactly one network is an error rather than a
// default. A guessed network name would enter the evidence_hash, and the same
// code+issuer can exist on two networks with different flags (#41).
func (s *Scanner) resolveNetwork() (horizon.Network, error) {
	derived, deriveErr := s.Horizon.Network()
	switch {
	case deriveErr == nil:
		if s.Network != "" && s.Network != derived {
			return "", fmt.Errorf("scan: network declared %q but Horizon at %s serves %q",
				s.Network, s.Horizon.BaseURL, derived)
		}
		return derived, nil
	case s.Network != "":
		return s.Network, nil
	default:
		return "", fmt.Errorf("scan: %w; set Scanner.Network to the passphrase of the ledger Horizon at %s serves",
			deriveErr, s.Horizon.BaseURL)
	}
}

func (s *Scanner) fetchTimeout() time.Duration {
	if s.FetchTimeout > 0 {
		return s.FetchTimeout
	}
	return DefaultFetchTimeout
}

// Subject fetches everything the checks need for one asset.
//
// Only the ledger lookups are fatal: without issuer flags there is no
// classification to make. Every consumed signal is best-effort, because a
// third-party outage must not be able to turn a dangerous asset into an error
// page. When a source is unreachable the failure is recorded verbatim and
// surfaced, never smoothed into a false negative.
func (s *Scanner) Subject(ctx context.Context, a mechanics.Asset) (*mechanics.Subject, error) {
	network, err := s.resolveNetwork()
	if err != nil {
		return nil, err
	}
	sub := &mechanics.Subject{Asset: a, ScannedAt: time.Now().UTC(), Network: network}
	timeout := s.fetchTimeout()

	statCtx, cancelStat := context.WithTimeout(ctx, timeout)
	stat, err := s.Horizon.Asset(statCtx, a.Code, a.Issuer)
	cancelStat()
	if err != nil {
		return nil, err
	}
	sub.Stat = stat
	// Each fetch stamps its own completion time. Later temporal statements —
	// how stale one source's answer was relative to another's — are only
	// honest if the times were recorded per source, not reused from the scan
	// start.
	sub.StatFetchedAt = time.Now().UTC()

	acctCtx, cancelAcct := context.WithTimeout(ctx, timeout)
	issuer, err := s.Horizon.Account(acctCtx, a.Issuer)
	cancelAcct()
	if err != nil {
		return nil, err
	}
	sub.Issuer = issuer
	sub.IssuerFetchedAt = time.Now().UTC()

	var (
		wg sync.WaitGroup

		tomlDoc         *sep1.Doc
		tomlErr         string
		tomlRefused     bool
		tomlAttemptedAt time.Time
		tomlURL         string

		blockedVal       stellarexpert.Answer[stellarexpert.BlockedDomain]
		blockedErr       string
		blockedFetchedAt time.Time
		blockedAttAt     time.Time
		blockedURL       string

		dirVal       stellarexpert.Answer[stellarexpert.DirectoryEntry]
		dirErr       string
		dirFetchedAt time.Time
		dirAttAt     time.Time
		dirURL       string
	)

	if domain := issuer.HomeDomain; domain != "" {
		tomlURL = sep1.URLFor(domain)
		wg.Add(1)
		go func() {
			defer wg.Done()
			tomlCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			attempted := time.Now().UTC()
			doc, err := s.Toml.Fetch(tomlCtx, domain)
			if err != nil {
				tomlErr = sep1.CanonicalFailure(err)
				// A host-policy refusal is a decision, not an outage. It is
				// recorded as such so the domain check can report a refusal
				// rather than a source that failed to answer.
				tomlRefused = errors.Is(err, sep1.ErrNonPublicHost)
				// A failed fetch has no completion time, so the attempt time is
				// what failure evidence carries — explicitly labelled as an attempt
				// by Evidence.Attempted.
				tomlAttemptedAt = attempted
			} else {
				tomlDoc = doc
			}
		}()

		blockedURL = s.Expert.BlockedDomainURL(domain)
		wg.Add(1)
		go func() {
			defer wg.Done()
			blockedCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			attempted := time.Now().UTC()
			blocked, err := s.Expert.BlockedDomain(blockedCtx, domain)
			blockedAttAt = attempted
			if err != nil {
				blockedErr = sep1.CanonicalFailure(err)
			} else {
				blockedVal = blocked
				// The source's OWN completion time, which on a cache hit is
				// the instant the answer was originally fetched. Stamping the
				// lookup time here instead is the one thing the cache must
				// never cause: Evidence.RetrievedAt would then claim a
				// freshness the data does not have, in the report and in the
				// preimage a verifier re-derives.
				blockedFetchedAt = blocked.FetchedAt
			}
		}()
	}

	dirURL = s.Expert.DirectoryURL(a.Issuer)
	wg.Add(1)
	go func() {
		defer wg.Done()
		dirCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		attempted := time.Now().UTC()
		entry, err := s.Expert.Directory(dirCtx, a.Issuer)
		dirAttAt = attempted
		if err != nil {
			dirErr = sep1.CanonicalFailure(err)
		} else {
			dirVal = entry
			// As above: the directory answer's own fetch time, not this scan's.
			dirFetchedAt = entry.FetchedAt
		}
	}()

	wg.Wait()

	sub.TomlURL = tomlURL
	sub.Toml = tomlDoc
	sub.TomlErr = tomlErr
	sub.TomlRefused = tomlRefused
	sub.TomlAttemptedAt = tomlAttemptedAt
	// SEP-0001 lets a currency entry delegate to a separate per-currency
	// document. Follow those links — one hop, bounded by
	// sep1.MaxLinkedDocuments and subject to the same host policy — but
	// only when the asset was not already claimed inline, which keeps the
	// common case at one fetch, and only once the fetch it depends on has
	// returned.
	if tomlDoc != nil && tomlDoc.LinkedCurrencies(a.Code, a.Issuer) > 0 && !tomlDoc.Claims(a.Code, a.Issuer) {
		sub.TomlLinked = s.Toml.ResolveLinked(ctx, tomlDoc, a.Code, a.Issuer)
	}

	if issuer.HomeDomain != "" {
		sub.BlockedURL = blockedURL
		sub.Blocked = blockedVal.Value
		sub.BlockedErr = blockedErr
		sub.BlockedFetchedAt = blockedFetchedAt
		sub.BlockedAttemptedAt = blockedAttAt
	} else {
		// The blocklist is keyed on a domain, and there is none: the question
		// cannot be put at all. Record that explicitly rather than leaving the
		// fields empty, because an empty Blocked with no error reads downstream
		// as "the lookup ran and found no entry" — and a blocklist hit
		// escalates severity, so that silently-dropped lookup is a risk this
		// report would understate.
		sub.BlockedSkipped = "the issuer advertises no home_domain to key the lookup on"
	}

	sub.DirectoryURL = dirURL
	sub.Directory = dirVal.Value
	sub.DirectoryErr = dirErr
	sub.DirectoryFetchedAt = dirFetchedAt
	sub.DirectoryAttemptedAt = dirAttAt

	// SEP-0042 asset lists, one signal each, in configuration order. Each is
	// best-effort for the same reason every other consumed signal is: a list
	// that is down must not turn a dangerous asset into an error page. The
	// failure is recorded per list, so one bad URL cannot be read as another
	// provider's silence, and an unreadable list is recorded as a failure
	// rather than as an absence.
	if len(s.AssetListURLs) > 0 {
		lists := s.Lists
		if lists == nil {
			lists = assetlist.New()
		}
		for _, listURL := range s.AssetListURLs {
			attempted := time.Now().UTC()
			list, err := lists.Fetch(ctx, listURL)
			if err != nil {
				sub.AssetLists = append(sub.AssetLists, mechanics.AssetListSignal{
					URL:         listURL,
					AttemptedAt: attempted,
					Err:         sep1.CanonicalFailure(err),
				})
				continue
			}
			sig := mechanics.AssetListSignal{
				Name:        list.Name,
				Provider:    list.Provider,
				URL:         list.URL,
				Version:     list.Version,
				Network:     list.Network,
				FetchedAt:   list.FetchedAt,
				AttemptedAt: attempted,
			}
			// Match on the classic pair, and on the asset's contract address as
			// a second key: a list may publish either, and Horizon reports the
			// SAC on the asset record we already hold.
			if e, ok := list.Lookup(a.Code, a.Issuer, stat.ContractID); ok {
				sig.Entry = &e
				sig.Listed = true
			}
			sub.AssetLists = append(sub.AssetLists, sig)
		}
	}

	return sub, nil
}

// Scan fetches and classifies an asset.
func (s *Scanner) Scan(ctx context.Context, a mechanics.Asset) (*mechanics.Report, error) {
	sub, err := s.Subject(ctx, a)
	if err != nil {
		return nil, err
	}
	return s.Engine.Run(ctx, sub)
}

// SubjectWithHolder fetches everything Subject does, then additionally fetches
// the trustline state for holder if non-empty. When holder is empty the result
// is identical to calling Subject.
func (s *Scanner) SubjectWithHolder(ctx context.Context, a mechanics.Asset, holder string) (*mechanics.Subject, error) {
	sub, err := s.Subject(ctx, a)
	if err != nil {
		return nil, err
	}
	if holder == "" {
		return sub, nil
	}
	sub.Holder = holder
	tlCtx, cancel := context.WithTimeout(ctx, s.fetchTimeout())
	defer cancel()
	tl, err := s.Horizon.Trustline(tlCtx, holder, a.Code, a.Issuer)
	if errors.Is(err, horizon.ErrNotFound) {
		// Holder does not hold the asset; HolderTrustline stays nil with no
		// error. The source did answer — "not listed" — so this records a
		// completion time, not an attempt time.
		sub.HolderFetchedAt = time.Now().UTC()
	} else if err != nil {
		sub.HolderTrustlineErr = sep1.CanonicalFailure(err)
		sub.HolderAttemptedAt = time.Now().UTC()
	} else {
		sub.HolderTrustline = tl
		sub.HolderFetchedAt = time.Now().UTC()
	}
	return sub, nil
}

// ScanWithHolder fetches and classifies an asset, optionally adding per-holder
// trustline analysis when holder is non-empty. When holder is empty the result
// is byte-identical to Scan.
func (s *Scanner) ScanWithHolder(ctx context.Context, a mechanics.Asset, holder string) (*mechanics.Report, error) {
	sub, err := s.SubjectWithHolder(ctx, a, holder)
	if err != nil {
		return nil, err
	}
	eng := s.Engine
	if holder != "" {
		eng = &mechanics.Engine{Checks: append([]mechanics.Check{}, s.Engine.Checks...)}
		eng.Checks = append(eng.Checks, mechanics.TrustlineCheck{})
	}
	return eng.Run(ctx, sub)
}
