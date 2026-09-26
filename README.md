# trawl

**Independent collection, explainable scoring and correlation of phishing
infrastructure that impersonates Bulgarian brands** - couriers, state e-services,
toll payment and banks - built from public Certificate Transparency data.

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
serve ─► read-only JSON API + dark investigation UI on 127.0.0.1
```

## What it does

1. **Collects** unexpired-certificate records from crt.sh by keyword for 17 tracked brands.
   Every response is stored verbatim with its query, run, HTTP status, attempt count
   and SHA-256. Partial collection is normal and recorded: a failed, timed-out or
   abandoned query is never counted as "no results".
2. **Scores** every name with named rules (brand token, high-abuse TLD, lure wording,
   shared platform, generated labels, certificate patterns...). A score is the capped
   sum of its signals; a brand alone never flags a name. Matching works on whole tokens
   and complete segmentations - never on substrings.
3. **Re-checks** flagged names in DNS (lookup only - it never visits a site) and
   appends each result, so appearance and disappearance are both kept.
4. **Correlates** flagged names into campaign hypotheses from shared indicators,
   weighted by rarity, requiring either a strong identifier or corroboration by several
   independent kinds of evidence.
5. **Records provenance** for everything: which record, query and run; which rule
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
`snapshot`, `verify`, `replay`, `report`. See [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | components, data flow, storage layers, process model |
| [DATA_SOURCES](docs/DATA_SOURCES.md) | every source, what it provides, failure modes, sources deliberately not used |
| [METHODOLOGY](docs/METHODOLOGY.md) | the pipeline end to end; observation / signal / relationship / hypothesis |
| [SCORING](docs/SCORING.md) | every rule, weight, threshold, brand and allow-list entry |
| [CORRELATION](docs/CORRELATION.md) | indicators, weighting, acceptance rules, tiers, measured evaluation |
| [PROVENANCE](docs/PROVENANCE.md) | what is recorded, fingerprints, snapshots, how to reproduce an analysis |
| [OPERATIONS](docs/OPERATIONS.md) | configuration, commands, systemd units, deployment, tunnel |
| [SECURITY](docs/SECURITY.md) | threat model, controls, audit results, network behaviour |
| [LIMITATIONS](docs/LIMITATIONS.md) | what it cannot see or establish |

## Independence

The system collects all of its data itself, from primary public sources (crt.sh and
DNS). It uses no third-party phishing feed, seed list, AI classification or external
scoring, at any stage. The beta tools this project grew out of (`cobweb`, `certwatch`)
depended on the public *detectopod* feed; that dependency does not exist here.

## Layout

```
trawl/            package: config, db, names, rules, scoring, correlate, collect,
                  analysis, snapshot, server, cli, sources/{crtsh,dns}.py, web/
tests/            offline test suite (fakes for crt.sh and DNS)
docs/             the documents listed above
deploy/           systemd units, Deck config, deploy script
```
