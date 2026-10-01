package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/sep1"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// fixtureTime is the capture instant used for fixture replay. A live scan
// records a separate completion time per source; a replay has no latency, so
// every source answers at the same instant — which is what the capture itself
// looked like. It is excluded from evidence_hash, so the exact value does not
// affect any recorded hash.
var fixtureTime = time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)

// LoadSubject rebuilds a mechanics.Subject from captured fixtures, using the
// same decoders the live fetchers use. Nothing here touches the network.
//
// This is the single loader for the labelled corpus: the eval tests and the
// eval command both call it, so a fixture that parses for one parses for the
// other, and a result cannot drift because a third-party API had a bad day.
//
// Each consumed source has three expressible states, and the fixture format
// must be able to state all three:
//
//   - valid      — the payload file is present (stellar.toml, directory.json,
//     blocked.json): the source answered.
//   - missing    — no payload file and no error marker: the source was not
//     consulted. In a fixture set every source is always consulted, so this
//     state exists only where the live scanner itself skips a fetch (a
//     blocklist lookup needs a home_domain).
//   - unavailable — an error marker is present (stellar.toml.status,
//     directory.err, blocked.err): the source was consulted and failed, and
//     the loader sets the matching *Err field. The marker's trimmed text is
//     what the live fetcher would have recorded verbatim — an HTTP status
//     number for a status failure, or any error text for a transport failure.
//
// The unavailable state is the one that matters for the corpus (#111): without
// it, a subject whose reputation source was unreachable is indistinguishable
// from one whose fixture was simply never captured, so the degraded-scan
// behaviour the engine must have cannot be exercised from the labelled set.
func LoadSubject(fixturesDir, dir string) (*mechanics.Subject, error) {
	base := filepath.Join(fixturesDir, dir)

	var stat horizon.AssetStat
	if err := readJSON(filepath.Join(base, "asset.json"), &stat); err != nil {
		return nil, err
	}
	var acct horizon.Account
	if err := readJSON(filepath.Join(base, "account.json"), &acct); err != nil {
		return nil, err
	}

	s := &mechanics.Subject{
		Asset:           mechanics.Asset{Code: stat.AssetCode, Issuer: stat.AssetIssuer},
		Stat:            &stat,
		StatFetchedAt:   fixtureTime,
		Issuer:          &acct,
		IssuerFetchedAt: fixtureTime,
		ScannedAt:       fixtureTime,
	}

	if acct.HomeDomain != "" {
		s.TomlURL = sep1.URLFor(acct.HomeDomain)
		s.TomlAttemptedAt = fixtureTime
	}
	if b, err := os.ReadFile(filepath.Join(base, "stellar.toml")); err == nil {
		doc, err := sep1.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("parse %s stellar.toml: %w", dir, err)
		}
		doc.URL = s.TomlURL
		s.Toml = doc
	} else if msg, ok := readErrMarker(filepath.Join(base, "stellar.toml.status")); ok {
		s.TomlErr = "status " + msg
	}

	s.DirectoryURL = "https://api.stellar.expert/explorer/directory/" + stat.AssetIssuer
	s.DirectoryAttemptedAt = fixtureTime
	if _, err := os.Stat(filepath.Join(base, "directory.json")); err == nil {
		var e stellarexpert.DirectoryEntry
		if err := readJSON(filepath.Join(base, "directory.json"), &e); err != nil {
			return nil, err
		}
		s.Directory = &e
		s.DirectoryFetchedAt = fixtureTime
	} else if msg, ok := readErrMarker(filepath.Join(base, "directory.err")); ok {
		s.DirectoryErr = msg
	}
	s.BlockedURL = "https://api.stellar.expert/explorer/directory/blocked-domains/"
	if acct.HomeDomain != "" {
		s.BlockedURL += acct.HomeDomain
	} else {
		// No domain to key the blocklist on: mirror the live scanner so a
		// no-home_domain fixture exercises the same path production does.
		s.BlockedSkipped = "the issuer advertises no home_domain to key the lookup on"
	}
	s.BlockedAttemptedAt = fixtureTime
	if _, err := os.Stat(filepath.Join(base, "blocked.json")); err == nil {
		var b stellarexpert.BlockedDomain
		if err := readJSON(filepath.Join(base, "blocked.json"), &b); err != nil {
			return nil, err
		}
		s.Blocked = &b
		s.BlockedFetchedAt = fixtureTime
	} else if msg, ok := readErrMarker(filepath.Join(base, "blocked.err")); ok {
		s.BlockedErr = msg
	}
	return s, nil
}

// readErrMarker reads a source's error marker file. An empty or whitespace
// marker is treated as absent rather than as an empty error: an error with no
// text cannot be recorded verbatim, and silently producing an empty *Err would
// be indistinguishable from "answered, not listed" — the exact collapse this
// format exists to prevent.
func readErrMarker(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	msg := strings.TrimSpace(string(b))
	if msg == "" {
		return "", false
	}
	return msg, true
}

func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
