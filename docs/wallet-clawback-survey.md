# Wallet warnings for clawback-enabled assets

**Surveyed 2026-10-20.** What Freighter, LOBSTR, xBull, StellarX and Albedo
show a user before adding a trustline to a clawback-enabled or revocable
asset, and what data source each one uses. This is the off-chain half of the
consumer comparison in [#153](https://github.com/use-assay/Assay/issues/153);
on-chain consumers are compared in
[multi-attestor.md](multi-attestor.md#why-153s-consumer-research-does-not-change-this).

Method: public documentation, public asset pages, and — where the wallet is
open source — the source itself. Pages were fetched on the date above; wallet
UIs change, so every claim below names what was fetched. Where a wallet's
behaviour could not be observed without installing it, that is stated rather
than guessed. This repository does not display a value it did not fetch, and
that rule applies to a survey the same as to a scan.

## Summary

| Wallet | Warns about clawback before adding a trustline? | What it shows | Data source |
| --- | --- | --- | --- |
| LOBSTR | **Yes** — on the asset page, before "Add Asset" | Explicit `Revocable asset` and `Clawbacks enabled` Yes/No flags with explanatory popups, including a "Be careful!" warning | Horizon (ledger flags); page states "loaded from the Stellar network" |
| Freighter | **No clawback-specific warning found** | Verified/Unverified badge from curated lists; Blockaid scan can flag the asset as suspicious | stellar.expert search, curated asset lists, Blockaid |
| xBull | **No warning found**; it signs clawback operations | Signs `Clawback`, `ClawbackClaimableBalance`, `SetTrustLineFlags` like any other operation | Not documented publicly; docs site unreachable at survey time |
| StellarX | **No warning found** in the add/trade flow | Public FAQ page explains clawback exists; a user-reported 2022 scam used it undetected | Not documented; asset data from the network |
| Albedo | **No** — cannot, by construction | Trustline confirmation shows the `changeTrust` operation only | None; the `trust` intent builds the operation from code+issuer parameters alone |

Four wallets surveyed, plus a fifth for contrast; every row dated 2026-10-20.

## LOBSTR

The only surveyed wallet that surfaces the flags at the moment of decision.
Every asset page (`lobstr.co/assets/CODE:ISSUER`) carries an **Authorization
flags** section. Fetched verbatim on 2026-10-20, for a clawback-enabled asset
(`XRP:GCCAQ4KWIU4I6LISLWBWFD27DYM5JCPD2QP7FP5TVAG64OYP7E37W6IQ`):

> **Revocable asset** — Yes
> **Clawbacks enabled** — Yes

and for a non-clawback asset (`TRX:GD3L7TRQ5TSXSHHGOUGCQ272BKS5WC5PEB46XP5LT2EZKQUWSDVHCOUS`):

> **Revocable asset** — No
> **Clawbacks enabled** — No

Each flag has a help popup. The clawback popup reads, verbatim:

> Clawback transactions allow an asset issuer to burn a specific amount of a
> clawback-enabled asset, effectively destroying and removing it from your
> wallet balance or pending payment on your wallet. Clawbacks were designed to
> allow trustworthy asset issuers to meet securities regulations or recover
> assets that have been fraudulently obtained
>
> **Be careful!** Fraudulent asset issuers may take advantage of asset
> clawbacks to freeze or burn any amount of asset on your wallet without your
> explicit approval.

The page footer states the provenance: "The asset information is loaded from
the Stellar network and was not manually verified by the LOBSTR team." So the
data source is the ledger itself — the issuer's `AUTH_CLAWBACK_ENABLED` and
`AUTH_REVOCABLE` account flags and the trustline's
`TRUSTLINE_CLAWBACK_ENABLED` flag, which is what a Horizon account lookup
returns. No third-party rating is involved. LOBSTR additionally runs a
Blockaid scan for malicious-asset warnings on transactions — a separate,
heuristic layer, visible in the same page's transaction-warning modal.

One caveat, stated rather than assumed: this is the public asset page, which
is where the "Add Asset" button lives. Whether the mobile app's in-flow
confirmation repeats the flag was not verified here — it needs an install,
and this survey does not claim what it did not observe.

LOBSTR is also a *consumer* of curated lists in its own right: its
help-center article on managing assets recommends "only using the LOBSTR
Curated and Featured (Top assets) list" and disclaims that listings are not
endorsements — the same line [asset-lists.md](asset-lists.md) draws.

## Freighter

The "Add a token" help article
([help.freighter.app](https://help.freighter.app/article/p3fdg4vwkd-add-a-token),
fetched 2026-10-20) documents the flow:

> Freighter uses stellar.expert for token search capabilities, and filters
> results against lists curated by trusted members of the ecosystem such as
> Palta Labs or UltraStellar. Results that match an entry in these lists are
> displayed as "Verified" while those that don't are displayed as "Unverified".
> … As an additional security measure, tokens are scanned by Blockaid and can
> be flagged as suspicious or malicious.

No clawback-specific warning appears anywhere in the documented flow. The
signals a Freighter user sees before approving a trustline are: curated-list
membership (a curation opinion, not a mechanic) and a Blockaid risk scan (a
heuristic, not a ledger fact). Neither is derived from
`AUTH_CLAWBACK_ENABLED`. The help article on Stellar assets and contract
tokens likewise discusses trustlines, base reserves, and the trustline
requirement — not clawback.

## xBull

The wallet is open source
([Creit-Tech/xBull-Wallet](https://github.com/Creit-Tech/xBull-Wallet),
fetched 2026-10-20). Its README lists the operations it handles, including:

> - [x] Clawback
> - [x] Clawback Claimable Balance
> - [X] Set Trust Line Flags

So the wallet can sign the operations that *perform* clawback, but nothing in
the repository — README, operation list, or source — documents a warning shown
before establishing a trustline to a clawback-enabled asset. The public docs
site (`xbull.app`) was unreachable from this survey environment at survey
time (connection failure), and the older `docs.xbull.app` host did not
resolve. No claim is made beyond what the repository shows: operation
support, no documented warning.

## StellarX

`stellarx.com/clawback` is a JavaScript application; it does not render
server-side, so its FAQ text could not be re-fetched verbatim for this survey
and is not quoted. What is on record: the page exists as StellarX's public
explanation of clawback, and the add/trade flow documents no clawback gate.
The real-world consequence is documented in a user report from 2022
([r/Stellar](https://www.reddit.com/r/Stellar/comments/yjdbzu/), fetched
2026-10-20): a user traded an asset whose issuer clawed back every purchase —
the first reply, from a community helper, is the entire mitigation:

> Tokens can be clawback enabled. It's important to check the issuer and what
> flags they have enabled. If you are trading a malicious token (a scam) that
> has clawback, they can take back your asset and burn it.

That is the survey's finding in one sentence: on the largest DEX interface,
checking the issuer's flags is left to the user.

## Albedo (contrast case)

Albedo is not a wallet a user installs; it is a web-based signer. Its source
([stellar-expert/albedo](https://github.com/stellar-expert/albedo), fetched
2026-10-20) shows the `trust` intent builds the operation from parameters
alone (`frontend/src/actions/tx-actions.js`):

```js
case 'trust': {
    const {asset_code, asset_issuer, limit = '922337203685.4775807'} = intentParams
    return [Operation.changeTrust({asset: new Asset(asset_code, asset_issuer), limit})]
}
```

A search of the repository for `clawback` returns zero matches. By
construction Albedo cannot warn: the initiating website hands it a code and
issuer, and it shows the operation for signature. This is the boundary case
that sharpens the others — the flag is on the public ledger, an account
lookup away, and a signer that never looks up the account never sees it.

## What the comparison shows

1. **The ledger data wallets need is already public and cheap.** LOBSTR
   renders both flags from the network with no intermediary. The
   distinguishing feature of LOBSTR is not a data advantage; it is the
   decision to render the flags at all.
2. **The default is silence.** Three of the five surveyed surfaces show
   nothing clawback-specific before the user commits. The failure mode is
   documented, not hypothetical: the 2022 StellarX report above.
3. **The warnings that do exist are either raw flags or heuristics.**
   LOBSTR shows the ledger fact with static explanatory text. Freighter and
   LOBSTR both layer Blockaid, a third-party heuristic, on top. No surveyed
   wallet shows a *judgment* — whether this particular issuer's clawback flag
   is a legitimate regulatory instrument or a confiscation mechanism in
   waiting. That judgment is exactly what Assay's severity model encodes.
4. **Wallets consume curated lists as curation, and say so.** LOBSTR's help
   center and Freighter's Verified badge both treat list membership as "what
   exists, curated" — matching [asset-lists.md](asset-lists.md)'s rule that
   listing is never a safety signal.

## Implications for Assay's API

- **The flags are not the product; the judgment is.** Any wallet can read
  `auth_clawback_enabled` from Horizon, as LOBSTR does. What no surveyed
  wallet provides — and what a wallet integrating Assay would get — is the
  severity level, the accountability record, and the attestation age for the
  same asset, in one response. A clawback flag on a `CRITICAL` asset reads
  differently from the same flag on a `LOW` asset; the raw flag alone cannot
  say which.
- **The API already carries the wallet-relevant bits.** `flags` in the
  report includes `auth_clawback_enabled` and `auth_revocable`; `severity`
  and the per-check results give the judgment layer. A wallet's add-asset
  confirmation could render `GET /api/v1/{code}/{issuer}` verbatim and match
  LOBSTR's presentation on day one, with severity as the addition. No new
  endpoint or field is implied by this survey.
- **Attribution matters to this audience.** LOBSTR's page says "loaded from
  the Stellar network and was not manually verified"; Freighter says "scanned
  by Blockaid." Both name their source, and a wallet integrating Assay would
  need to do the same with Assay's inputs — which is why
  [trust.md](trust.md)'s provenance separation is load-bearing here, not
  cosmetic.
- **The API's consumers are wallets, but wallets are not the gate.** Nothing
  in this survey suggests a wallet would *refuse* a clawback-enabled asset;
  the realistic integration is display-before-confirm. Assay's output format
  — a single JSON verdict with flags, severity, and reasoning — fits that
  slot without redesign.

## What was not surveyed

Mobile-app in-flow confirmations that require an install (LOBSTR app,
Freighter app, xBull extension) beyond their public documentation; wallet
backends' internal data plumbing; SEP-8 regulated-asset flows, which are a
different approval path from a plain trustline. Anything not named above is
out of scope for this document.
