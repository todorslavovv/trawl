# Provenance and reproducibility

Every result can be traced to the records that produced it, and every analysis can be
reproduced from a stored dataset.

## What is recorded

| For | Recorded |
|---|---|
| Each collection run | source, start/end, software version, full configuration (JSON), per-outcome query counts, records received/new, status `complete`/`partial`/`failed`/`interrupted`, per-keyword coverage |
| Each crt.sh query | keyword, role, pattern, times, duration, outcome, HTTP status, attempts, bytes, response SHA-256, records received/new/invalid, error |
| Each source record | verbatim canonical payload, payload SHA-256, crt.sh id, the run and query that first returned it, fetch time |
| Each DNS observation | name, time, resolver description, outcome, sorted addresses, error, run |
| Each availability check | name, time, run, source and checker version, duration, DNS result and addresses, address and port contacted, TCP / TLS / HTTP results, status, redirect target, bot protection, state, reason, error - not part of any analysis dataset |
| Each analysis | `as_of`, software version, rules version, correlation configuration and its SHA-256, input cut-offs (run, record, DNS), dataset SHA-256, results SHA-256, counts, duration |
| Each decision / signal | score, verdict, brands, rule id, points, the matched text |
| Each relationship | weight, kinds, accepted or not, strength, reason, and every indicator with its df and weight |
| Each campaign | members, links, density, cohesion, weakest link, tier |
| Each snapshot | file name, file SHA-256, dataset SHA-256, analysis, size |

In the UI, a domain page shows its source records (crt.sh id, query, run, payload
hash); every page shows the current analysis id, `as_of`, rules version and dataset
fingerprint in the header and sidebar.

## Cut-offs and fingerprints

An analysis reads only observations up to three cut-offs: the last finished collection
run, the last source record and the last DNS observation at the time it started.
Because observations are append-only, those cut-offs select the same rows forever.

* **Dataset SHA-256** - SHA-256 of the canonical serialisation of those rows: source
  ids, runs, queries, source records, DNS observations, each as one line of canonical
  JSON (sorted keys, no whitespace), in a fixed order. Only the analysis sources
  (`crtsh`, `dns`) and their runs are included; the availability probe's source row and
  runs are not, so availability checks can never change a fingerprint - the first
  production snapshot still replays to its recorded fingerprints after the probe was
  added.
* **Results SHA-256** - SHA-256 of the canonical results document: every non-`none`
  decision with its signals, suppressed indicators, accepted relationships with
  evidence, and campaigns - all sorted, weights rounded to 4 decimals.
* **Correlation SHA-256** - SHA-256 of the correlation configuration used.

Time-dependent rules use the analysis `as_of`, never the wall clock, so re-running an
analysis later gives the same results.

## Snapshots

`trawl snapshot [--analysis N]` exports an analysis' dataset as
`trawl-aNNNNN-<dataset12>.jsonl.gz` plus `...manifest.json`. The gzip stream has a
fixed header (mtime 0, no file name), so the same dataset always produces the same
bytes. Export refuses to write if the rows no longer hash to the recorded fingerprint
(i.e. if observations were altered after the analysis). The manifest records the
dataset and file SHA-256, row counts, cut-offs, `as_of`, software and rules versions,
the correlation configuration and SHA-256, the results SHA-256, and the collection runs
included by status. The cycle exports one snapshot per `snapshots.interval_hours`
(24 h) and keeps the newest `snapshots.keep` (14) files; the database itself remains
the complete archive.

## Reproducing an analysis

```bash
python3 -m trawl verify  data/snapshots/trawl-a00012-....manifest.json   # hashes
python3 -m trawl replay  data/snapshots/trawl-a00012-....manifest.json   # re-run
python3 -m trawl report  --analysis 12 -o report-12.json                 # from the live DB
```

`replay` checks both hashes, loads the observations into a fresh temporary database,
rebuilds the index, re-runs the analysis with the manifest's `as_of`, cut-offs and
correlation configuration, and reports `"reproduced": true` only if both the dataset
and results fingerprints match. With a different rules version it says so: results are
then expected to differ. `report` regenerates a full deterministic report of any past
analysis (including ones whose derived rows were pruned) and states whether it matches
the recorded results fingerprint.

## What cannot be reproduced

The collection itself: crt.sh's answers change over time and it abandons queries
non-deterministically. That is why every response is stored verbatim - reproducibility
starts at the stored observations, not at the live source.
