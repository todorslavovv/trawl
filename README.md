# trawl

**A public registry of phishing domains that impersonate Bulgarian brands** -
couriers, state e-services, toll payment and banks - built on independent collection,
explainable scoring and correlation of public Certificate Transparency data.

> Independent portfolio / research demonstration. Not an official system of, and not
> affiliated with or endorsed by, ГДБОП (GDBOP) or any other authority. Not affiliated
> with the author of any third-party phishing feed. Nothing it outputs identifies a
> person. Outputs are **leads** - observations, signals and campaign *hypotheses* - not
> findings.

```
PUBLIC INTERNET
  │  Certificate Transparency logs ──► crt.sh index            (primary source)
  │  host DNS resolver                                          (liveness re-check)
  ▼
collect ─► source_records (verbatim, hashed, append-only) + per-query outcomes
  ▼
normalize ─► domains · certificates · cert_names             (deterministic index)
  ▼
analyze ─► decisions + signals        (explainable scoring, rules r3)
        ─► indicators → relationships → campaign hypotheses   (corroborated correlation)
        ─► dataset SHA-256 + results SHA-256 + cut-offs       (provenance)
  ▼
snapshot ─► portable dataset + manifest ─► verify / replay reproduce the analysis
  ▼
availability ─► registry domains only: DNS → TCP → TLS → one GET /   (append-only history)
  ▼
serve ─► read-only JSON API + UI on 127.0.0.1:
         public registry (default page) · analysis views (one click away)
```

## Two layers

* **Public registry** (the home page). For ordinary visitors: a search box that
  takes a domain or a whole URL, a simple table of listed domains (domain, brand,
  status, date detected, last check and the state it found), pagination and the time
  of the last update. A result says whether the domain is in the registry, when it was
  first observed, when trawl last checked it and when it was last confirmed reachable.
  "Not in the registry" is never presented as "safe". The search is a database lookup:
  trawl never connects to what a visitor types.
* **Analysis** (the "Анализ / Analysis" section). For investigators: the domain view
  with scoring signals, certificates, DNS and availability history, relationships and
  provenance; campaigns with their graph and evidence; timeline; sources; collection
  health; methodology, snapshots and replay.

## What it does

1. **Collects** unexpired-certificate records from crt.sh by keyword for 17 tracked brands.
   Every response is stored verbatim with its query, run, HTTP status, attempt count
   and SHA-256. Partial collection is normal and recorded: a failed, timed-out or
   abandoned query is never counted as "no results".
2. **Scores** every name with named rules (brand token, high-abuse TLD, lure wording,
   shared platform, generated labels, certificate patterns...). A score is the capped
   sum of its signals; a brand alone never flags a name. Matching works on whole tokens
   and complete segmentations - never on substrings.
3. **Re-checks** flagged names in DNS and appends each result, so appearance and
   disappearance are both kept.
4. **Correlates** flagged names into campaign hypotheses from shared indicators,
   weighted by rarity, requiring either a strong identifier or corroboration by several
   independent kinds of evidence.
5. **Checks availability** of the registry domains about once a day - DNS, TCP, TLS
   and one `GET /` to public addresses only, redirects recorded but never followed,
   nothing rendered, bot protection never bypassed - and keeps every check. "Reachable"
   means the infrastructure answered, not that phishing content was seen. See
   [docs/AVAILABILITY.md](docs/AVAILABILITY.md).
6. **Records provenance** for everything: which record, query and run; which rule
   version and correlation settings; which exact dataset (SHA-256) produced a result.
   A snapshot of that dataset replays to the same results fingerprint.

## Interface language

The UI is **Bulgarian by default**, with **English** as the alternative (the
"🇧🇬 Български / 🇬🇧 English" switch in the header; the choice is remembered in the
browser). Labels, explanations, errors and evidence sentences are translated; data -
domain names, certificate fields, hashes, identifiers, timestamps - is shown as
collected. The API, the stored evidence and these documents are in English.

## Quick start

Python 3.11+ standard library only - no packages to install. Tests use `pytest`.

```bash
python3 -m trawl cycle          # collect -> DNS re-check -> analyze -> snapshot (if due)
python3 -m trawl serve          # http://127.0.0.1:8790/
python3 -m trawl stats
python3 -m pytest tests -q      # offline; nothing touches the network
```

Everything is also available step by step: `collect`, `dnscheck`, `analyze`,
`availability`, `snapshot`, `verify`, `replay`, `report`. See
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | components, data flow, storage layers, process model |
| [DATA_SOURCES](docs/DATA_SOURCES.md) | every source, what it provides, failure modes, sources deliberately not used |
| [METHODOLOGY](docs/METHODOLOGY.md) | the pipeline end to end; observation / signal / relationship / hypothesis |
| [SCORING](docs/SCORING.md) | every rule, weight, threshold, brand and allow-list entry |
| [CORRELATION](docs/CORRELATION.md) | indicators, weighting, acceptance rules, tiers, measured evaluation |
| [AVAILABILITY](docs/AVAILABILITY.md) | availability checks: method, classification, history, semantics, safety |
| [PROVENANCE](docs/PROVENANCE.md) | what is recorded, fingerprints, snapshots, how to reproduce an analysis |
| [OPERATIONS](docs/OPERATIONS.md) | configuration, commands, systemd units, deployment, tunnel |
| [SECURITY](docs/SECURITY.md) | threat model, controls, audit results, network behaviour |
| [LIMITATIONS](docs/LIMITATIONS.md) | what it cannot see or establish |

## Independence

The system collects all of its data itself: crt.sh and DNS for detection, and its own
availability checks of registry domains. It uses no third-party phishing feed, seed list, AI classification or external
scoring, at any stage. The beta tools this project grew out of (`cobweb`, `certwatch`)
depended on the public *detectopod* feed; that dependency does not exist here.

## Layout

```
trawl/            package: config, db, names, rules, scoring, correlate, collect,
                  analysis, availability, snapshot, server, cli,
                  sources/{crtsh,dns,probe}.py, web/
tests/            offline test suite (fakes for crt.sh and DNS)
docs/             the documents listed above
deploy/           systemd units, Deck config, deploy script
```
