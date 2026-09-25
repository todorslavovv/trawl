# Architecture

## Principles

* **Standard library only.** No third-party runtime dependency: nothing to audit
  beyond CPython, nothing to download at deploy time. Tests use `pytest`.
* **Observations are append-only; everything else is derived.** Anything computed can
  be recomputed from what was observed, so a past result can always be checked.
* **Failures are data.** Every request ends in a classified outcome; a run's
  completeness is recorded, never inferred.
* **The application is not an attack surface.** The web process is read-only, bound to
  loopback, and has no write endpoint. Collectors contact exactly two things: crt.sh
  and the host's DNS resolver.

## Components

| Module | Role |
|---|---|
| `trawl/config.py` | defaults + one optional JSON override; unknown keys and wrong types are rejected; `canonical()`/`sha256_of()` used for every fingerprint |
| `trawl/db.py` | SQLite schema (WAL), read-only connections, the single-writer lock, recovery of runs left `running` by a killed process |
| `trawl/sources/crtsh.py` | crt.sh adapter: paced, retrying HTTPS client with classified outcomes; the only HTTP client in the code |
| `trawl/sources/dns.py` | DNS adapter: `getaddrinfo` through the host resolver, concurrent, with a wall-clock timeout and classified outcomes |
| `trawl/collect.py` | collection runs (crt.sh query plan, abandoned-scan detection, coverage, run status), DNS re-check runs, normalisation into the index |
| `trawl/names.py` | DNS-name validation, public/platform suffixes, tokenisation, complete word segmentation, one-edit comparison |
| `trawl/rules.py` | the rule set as data (brands, allow-list, namesakes, TLD tiers, lure words, points, thresholds) and `RULES_VERSION` |
| `trawl/scoring.py` | per-name brand detection, signals, verdict; kit-shape fingerprints |
| `trawl/correlate.py` | indicator weighting, relationship acceptance, campaign components and tiers - pure functions |
| `trawl/analysis.py` | one analysis run: load facts at fixed cut-offs, score, extract indicators, correlate, write results, fingerprint |
| `trawl/snapshot.py` | canonical dataset serialisation, dataset fingerprint, portable snapshot export, verify, import, replay |
| `trawl/server.py` | read-only JSON API and static UI, strict headers, validated parameters |
| `trawl/web/` | `index.html`, `app.css`, `app.js` - the investigation UI, no external assets |
| `trawl/cli.py` | commands (`collect`, `dnscheck`, `analyze`, `cycle`, `snapshot`, `verify`, `replay`, `report`, `stats`, `serve`) |

Source adapters are modules exposing a `SOURCE` description (stored in the `sources`
table) and a fetch function returning classified outcomes. A new source is a new
module plus a collector step; scoring, correlation and the UI read normalised tables
and do not change.

## Data flow

```
crt.sh ──► collect_crtsh ──► collection_runs, queries, source_records   (observations)
                                     │
                                     ▼ normalize (deterministic, idempotent)
                     domains, certificates, cert_records, cert_names    (index)
                                     │
resolver ◄── dnscheck ◄── flagged_by_priority (current rules, in memory)
    └──────► dns_observations                                           (observations)
                                     │
                                     ▼ run_analysis(cut-offs, as_of, config)
      analysis_runs ─ decisions, signals, indicators, domain_indicators,
                      relationships, relationship_evidence, campaigns,
                      campaign_members                                   (derived)
                                     │
                                     ├─► snapshot export ─► *.jsonl.gz + manifest
                                     └─► server (read-only) ─► UI
```

## Storage layers

1. **Observations** - `collection_runs`, `queries`, `source_records`,
   `dns_observations`. Written once by the run that produced them; never updated after
   that run finishes, never deleted. `source_records.payload` is the crt.sh JSON
   record in canonical form, with its SHA-256.
2. **Index** - `domains`, `certificates`, `cert_records`, `cert_names`. Derived from
   `source_records` in id order; `normalize` is idempotent and replay rebuilds it
   identically. Precertificate and final certificate (same issuer + serial) become one
   certificate with two crt.sh records.
3. **Analyses** - one `analysis_runs` row per analysis records cut-offs, `as_of`,
   versions, configuration and fingerprints; derived rows are keyed by analysis id.
   Derived rows of older analyses are pruned (`analysis.keep_derived`, default 4); the
   metadata row is kept forever and `trawl report --analysis N` regenerates the full
   result from observations.

The schema is in `trawl/db.py`. The important entities map onto the brief as follows:
domains → `domains`; certificates → `certificates` (+ `cert_records`); observations →
`source_records`, `cert_names`, `dns_observations`; brands → `rules.BRANDS` (versioned
data, recorded per analysis via `rules_version`); signals → `signals`; scoring
decisions → `decisions`; indicators → `indicators` + `domain_indicators`;
relationships/edges → `relationships` + `relationship_evidence`; campaigns →
`campaigns` + `campaign_members`; collection runs → `collection_runs` + `queries`;
sources → `sources`; provenance → `analysis_runs` + `snapshots` + the columns above.

## Process model

| Process | Trigger | Network | Database |
|---|---|---|---|
| `trawl cycle` | systemd timer, every 6 h (also enforced in code: `collection.min_interval_hours`) | crt.sh (HTTPS), DNS resolver | read/write, under an exclusive lock |
| `trawl serve` | long-running service, `127.0.0.1:8790` | listens on loopback only; no outbound connections | read-only (`mode=ro`, `query_only`) |
| `cloudflared` Quick Tunnel | optional service, demo only | Cloudflare edge | none |

Only one writer runs at a time (`fcntl` lock next to the database). Readers use WAL
and are never blocked by a collection.
