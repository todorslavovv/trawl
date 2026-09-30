# trawl

> **Try it live here:** https://todorslavov.vercel.app/go/trawl

**A public registry of phishing domains that impersonate Bulgarian brands** - couriers,
banks, state e-services, road tolls and vignettes - built on independent collection,
explainable scoring and correlation of public Certificate Transparency data.

> Independent portfolio / research project. Not an official system of, and not affiliated
> with or endorsed by, ГДБОП (GDBOP) or any other authority. A listed domain is an
> **automated lead** for checking, not a confirmation of phishing. Nothing it outputs
> identifies a person.

## The problem

Phishing against Bulgarian users imitates a small set of trusted brands: Econt, Speedy,
Bulgarian Posts, TollPass / e-vignette, МВР e-services, the large banks. A site that
wants the browser padlock needs a TLS certificate, and every publicly trusted
certificate is published in Certificate Transparency (CT) logs - usually before the site
is used. trawl watches that public record for look-alike names, explains why each one
was flagged, groups names that appear to share infrastructure, and keeps a history of
whether they still answer.

## What you get

**Public registry** (the home page, for ordinary visitors)

* A search box that takes a domain or a whole URL (`https://example.com/login` is
  reduced to `example.com`) and answers from the database only - trawl never connects
  to what a visitor types.
* A result: status (likely / potential phishing, or needs review), first observed, last
  checked, last confirmed reachable and the state at that check.
* "Not found in the registry" always adds: *this does not mean the domain is safe*.
* A paginated table of listed domains and the time of the last update.

**Analysis** (one click away, for investigators)

* Per domain: every scoring signal with its points, certificates, DNS history,
  availability history, related names with the evidence for and against each link, and
  the exact source records it came from.
* Campaign hypotheses with a relationship graph, shared indicators and an issuance
  timeline; a timeline of events; sources and collection health; methodology.

**Language:** Bulgarian by default, English as the alternative (🇧🇬 Български /
🇬🇧 English switch, remembered in the browser). Data - domain names, certificate
fields, hashes, identifiers - is never translated.

## How it works

```
crt.sh (index of CT logs) ──► collect ──► source_records   verbatim, hashed, append-only
                                   │
                                   ▼ normalise
                     domains · certificates · names          deterministic index
                                   │
host DNS resolver ◄── DNS re-check ┤                         append-only observations
                                   ▼
                     analyze: explainable scoring (rules r3)
                              → indicators → relationships → campaign hypotheses
                              → dataset SHA-256 + results SHA-256 (provenance)
                                   │
                                   ├──► snapshot ──► verify / replay on another machine
                                   │
registry domains ──► availability check: DNS → TCP → TLS → one GET /
                                   │                         append-only history
                                   ▼
                     read-only web server on 127.0.0.1 ──► public registry + analysis
```

* **Collection** - keyword queries to crt.sh for 17 tracked brands, unexpired
  certificates only. Every response is stored verbatim with its query, run, HTTP
  status, attempts and SHA-256; a failed, abandoned or truncated query is recorded as
  such, never as "no results".
* **Scoring** - named rules (brand token, high-abuse TLD, lure wording, shared
  platforms, generated labels, certificate patterns). A score is the capped sum of its
  signals and a brand name alone never flags a domain. Matching uses whole tokens and
  complete word segmentations, never substrings.
* **Correlation** - shared indicators weighted by rarity; a link needs a strong
  identifier (same registrable domain, same certificate) or several independent kinds
  of evidence. Campaigns are hypotheses, labelled strong / corroborated / chained.
* **Availability** - about once a day per registry domain: one DNS lookup, a TCP
  connection to a vetted public address, verified TLS and one `GET /`. Redirects are
  recorded, never followed; nothing is rendered or stored; bot-protection challenges
  are recorded, never bypassed. Every check is kept, so the registry can say when a
  domain was last checked and last confirmed reachable. Availability is never an input
  of detection.
* **Provenance** - each analysis records its input cut-offs, rules version,
  configuration and the SHA-256 of its dataset and results. A snapshot of the dataset
  can be verified and replayed elsewhere to the same results fingerprint.

### What a result means - and does not

| The registry says | It means | It does not mean |
|---|---|---|
| Likely / potential phishing | the name and its certificates match impersonation patterns | that a phishing page was confirmed |
| Reachable | the domain's infrastructure answered trawl's last check (any HTTP answer, incl. 403 or a Cloudflare challenge) | that phishing content was seen |
| Unreachable | at that check the name did not exist in DNS, pointed only to non-public addresses, or refused connections | that the site is gone for good |
| Undetermined | the check gave no clear answer (timeout, TLS or server error) | anything about the site |
| Not in the registry | trawl has not listed this name | that the domain is safe |

## Technology

* Python 3.11+ **standard library only** - no runtime dependencies to install or audit
* SQLite (WAL) - one database; the web process opens it read-only
* Plain JavaScript / CSS front end served same-origin; no frameworks, CDNs, fonts or
  analytics (enforced by a Content-Security-Policy)
* systemd user units for the service, the 6-hourly cycle and the tunnel
* `cloudflared` Quick Tunnel for the public demo
* `pytest` for the offline test suite

## Run it locally

```bash
python3 -m trawl cycle          # collect -> DNS re-check -> analyze -> availability -> snapshot (if due)
python3 -m trawl serve          # http://127.0.0.1:8790/
python3 -m trawl stats
python3 -m pytest tests -q      # offline: crt.sh, DNS and the availability checks are faked
```

A first collection takes around 20-30 minutes, because crt.sh is slow and queries are
paced. Every step is also available on its own: `collect`, `dnscheck`, `analyze`,
`availability`, `snapshot`, `verify`, `replay`, `report`.

## Configuration

Defaults live in `trawl/config.py`; override any subset with one JSON file
(`--config FILE` or `TRAWL_CONFIG`). Unknown keys and wrong types are rejected rather
than ignored. Main sections: `collection` (pacing, timeouts, retries, minimum interval
between crt.sh runs), `dns`, `availability` (schedule, per-phase timeouts, read limits),
`correlation` (recorded and fingerprinted in every analysis), `snapshots`. Full table:
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## Deployment

* Linux with systemd (user units) and Python 3.11+; tested on Ubuntu (Python 3.12) and
  SteamOS 3.8 on a Steam Deck (Python 3.13).
* `deploy/` has the units: `trawl-web` (read-only server bound to 127.0.0.1:8790),
  `trawl-cycle` + timer (every 6 h), `trawl-tunnel` (optional public demo).
* The public demo runs `cloudflared tunnel --no-autoupdate --url http://127.0.0.1:8790`.
  This is a Cloudflare **Quick Tunnel**: a random `trycloudflare.com` hostname that
  **changes whenever the tunnel process restarts**, no uptime guarantee, intended for
  testing and demos. Cloudflare terminates TLS. For anything lasting, use a named,
  managed tunnel with access policies.

## Security

* The web server is read-only, bound to loopback, GET/HEAD only, with validated
  parameters, fixed error bodies and a strict Content-Security-Policy. It opens no
  outbound connection; the public search is a database query.
* Outbound traffic comes only from the collector (crt.sh over verified TLS, redirects
  refused) and the availability checker, which contacts only globally routable
  addresses (loopback, private, CGNAT, link-local / cloud metadata and IPv6 local
  ranges are refused), resolves once, never follows redirects and bounds every read and
  wait.
* systemd sandboxing, private data files, no secrets of any kind.
* An HTTP audit script (`deploy/audit_http.py`) checks a running instance.

Details and the dated audit record: [docs/SECURITY.md](docs/SECURITY.md).

## Limitations

* **crt.sh coverage.** crt.sh abandons most expensive "contains" searches, so coverage
  is mostly by keyword prefix: a name with the brand in the middle of a label can be
  missed. Only unexpired certificates are collected, crt.sh lags the CT logs, and a
  wildcard certificate hides the subdomains under it. No certificate, no detection.
* **One vantage point.** DNS and availability are checked from the deployment host
  only, about daily; nothing is known between checks, and operators can see and block
  the checks.
* **Automated leads.** Accuracy on real data is not measured - no labelled Bulgarian
  dataset exists. Legitimate integrations that carry a brand name under someone else's
  domain can be listed. Correlation is measured only on synthetic ground truth.
* **Quick Tunnel.** The public URL is temporary and changes on restart.

More in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Independence

trawl collects all of its data itself - crt.sh and DNS for detection, its own
availability checks for the registry. It uses no third-party phishing feed, seed list,
AI classification or external scoring. Its predecessors (`cobweb`, `certwatch`) relied
on the public *detectopod* feed; that dependency does not exist here.

## Project status

Version 2.2.1, feature-frozen. The offline test suite (518 tests) passed on the
development PC and on the Steam Deck on 2026-09-26. Not implemented, possible future
versions: direct CT log streaming, RDAP registration data, other public sources as
separately labelled observations.

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | components, data flow, storage layers, process model |
| [DATA_SOURCES](docs/DATA_SOURCES.md) | every source, what it provides, failure modes, sources deliberately not used |
| [METHODOLOGY](docs/METHODOLOGY.md) | the pipeline end to end; observation / signal / relationship / hypothesis |
| [SCORING](docs/SCORING.md) | every rule, weight, threshold, brand and allow-list entry |
| [CORRELATION](docs/CORRELATION.md) | indicators, weighting, acceptance rules, tiers, measured evaluation |
| [AVAILABILITY](docs/AVAILABILITY.md) | availability checks: method, schedule, classification, history, semantics |
| [PROVENANCE](docs/PROVENANCE.md) | what is recorded, fingerprints, snapshots, how to reproduce an analysis |
| [OPERATIONS](docs/OPERATIONS.md) | configuration, commands, systemd units, deployment, tunnel |
| [SECURITY](docs/SECURITY.md) | threat model, controls, audit record |
| [LIMITATIONS](docs/LIMITATIONS.md) | what it cannot see or establish |

## Layout

```
trawl/            package: config, db, names, rules, scoring, correlate, collect,
                  analysis, availability, snapshot, server, cli,
                  sources/{crtsh,dns,probe}.py, web/ (UI, translations)
tests/            offline test suite
docs/             the documents above
deploy/           systemd units, Deck config, deploy and audit scripts
```
