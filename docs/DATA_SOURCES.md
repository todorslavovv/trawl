# Data sources

Every observation comes from one of the three sources below, collected by this
system itself. The first two are the input of detection; the third is an availability
history for the public registry and is never an input of detection. Each source is described in the `sources` table and on the Sources
page, with its health.

## 1. crt.sh (primary) - Certificate Transparency

**What it is.** A public search index over Certificate Transparency (CT) logs,
operated by Sectigo. Every publicly trusted TLS certificate must be logged in CT, so
a phishing site that wants the browser padlock announces its name publicly, usually
before it is used.

**Why an index and not the logs.** Following a single CT log in full is about
27 GB/day (measured in the beta at ~5.5 kB per entry). crt.sh has already indexed the
same logs, so a keyword query costs bandwidth proportional to matches.

**How it is queried.** `GET https://crt.sh/?q=<pattern>&output=json&exclude=expired` -
the only HTTP destination in the code (`trawl/sources/crtsh.py`). Only certificates
that have **not expired** are requested (`collection.exclude_expired`, default on): a
live phishing site needs a valid certificate, and full-history answers are capped by
crt.sh (see below). Names are kept forever once collected, so history accumulates from
the first sighting. For each keyword in `rules.query_keywords()`:

| Role | Pattern | Notes |
|---|---|---|
| prefix | `{k}%` | uses crt.sh's index; fast and reliable |
| contains | `%{k}%` | superset of prefix; a full scan that crt.sh often abandons |
| dotted | `%.{k}%` | fallback, only if `contains` did not answer credibly |

**What a record contains.** `id`, `issuer_ca_id`, `issuer_name`, `common_name`,
`name_value`, `not_before`, `not_after`, `serial_number`, `result_count`.
`name_value` lists **only the identities that matched the query**, not every name on
the certificate, so the same certificate id can come back with different contents for
different queries. Records are therefore keyed by `crt.sh id + payload SHA-256`, and
both versions are kept. The `common_name` is also recorded as a name (`via =
common_name`). Organisation names and e-mail addresses in identities are discarded.

**Failure modes, and how each is handled.**

| Behaviour (observed) | Handling |
|---|---|
| Slow answers: 30-70 s for an ordinary prefix query | `request_timeout_s` 150 s (the beta's 45 s turned slow answers into failures) |
| HTTP 404 for a valid search that succeeds minutes later; instant 502s | retried like any 5xx; only 400/414 are not retried; a non-200 answer is never read as "no results" |
| HTTP 200 with `[]` when a scan is abandoned | an empty `%k%` or `%.k%` answer is accepted only if `k%` was verifiably empty; otherwise `abandoned` |
| HTTP 200 with a truncated list | a `%k%` answer smaller than `k%` (its own subset) is `abandoned`; its records are still kept |
| **Large answers capped to the oldest rows** (measured 2026-09-26 without `exclude=expired`: `econt%` returned 5,103 records whose newest certificate dated from 2018; `speedy%` stopped at 2016, `dpd%` at 2017, `mvr%` at 2018) | query unexpired certificates only (`econt%` then returned 4,336 records spanning 2025-08-27 to 2026-09-11); an answer of ≥ `truncation_min_records` (1,000) whose newest certificate is older than `truncation_stale_days` (45) is recorded as `abandoned` (truncated), records kept |
| HTML error page with status 200 | `parse_error` |
| 429 / Retry-After | honoured, capped at `backoff_max_s` |
| Very large answers | refused above `max_response_mb` (`too_large`) |

Politeness: at least `pace_s` (6 s) between any two requests, exponential backoff with
jitter, a run-time budget (`max_run_minutes`) after which remaining queries are
recorded as `skipped`, and a minimum interval between runs enforced in code. No API
key or account is used. The User-Agent identifies the tool.

crt.sh also lags the CT logs: its newest certificates are often days to weeks old.
That delay is between issuance and our first sighting, and it shows in the
difference between a name's first certificate date and its "collected" date.

**Provenance stored per response:** run id, keyword, role, pattern, start/finish time,
duration, outcome, HTTP status, attempts, bytes, response SHA-256, record counts
(received, new, invalid), error text. Per record: canonical payload, payload SHA-256,
the query and run that first returned it, and the fetch time.

**Coverage per keyword** is `full` (contains answered), `partial` (only prefix/dotted
answered) or `none`; a run is `complete` only if every keyword is `full`, `failed` if
none answered, otherwise `partial`.

## 2. DNS re-check (secondary) - host resolver

**What it provides.** Whether a flagged name resolves now, and to which A/AAAA
addresses. It never connects to the addresses (the separate availability probe in §3
does, for registry domains only).

**How.** `getaddrinfo()` through the deployment host's resolver (on the Steam Deck:
systemd-resolved at 127.0.0.53, forwarding to its configured upstream). The resolver
description from `/etc/resolv.conf` is stored with every observation. Up to
`dns.max_per_run` names per cycle, highest score first, skipping names checked within
`dns.recheck_hours`.

**Outcomes:** `resolved`, `nxdomain`, `no_address`, `temporary_failure`, `failure`,
`timeout` - a failed lookup is never recorded as "gone".

**Visibility.** A lookup is visible to the name's authoritative DNS operator (via the
recursive resolver). That is the only trace the system leaves on suspect
infrastructure.

**Use in analysis.** The latest observation within the analysis cut-off supplies the
`shared_ip` indicator; addresses that are not globally routable (sinkholes such as
127.0.0.1, private ranges) and Cloudflare's published anycast ranges are excluded,
because they are shared by unrelated sites.

## 3. Availability probe - registry domains only

**What it provides.** Whether the infrastructure behind each domain in the public
registry answered when trawl checked it: DNS result, the address and port contacted,
TCP, TLS and HTTP results, status code, redirect target (not followed), detected bot
protection, and a classification with its reason. About once a day per registry
domain; never for raw certificate names; never because a visitor searched.

**How.** `trawl/sources/probe.py`: one DNS lookup, public addresses only, TCP to that
exact address (443, else 80), verified TLS with SNI, one `GET /`; at most 16 KiB of
headers and body read, then discarded. Full method, classification and semantics:
[AVAILABILITY](AVAILABILITY.md).

**Provenance stored per check:** run, `source_id` and checker version (the method),
time, duration, every result above, state and reason. Checks are appended, never
overwritten. The probe's runs and source row are excluded from the analysis dataset,
so they cannot change a detection or a fingerprint.

**Visibility.** The domain's operator sees the checking host's IP address and the
User-Agent `trawl-availability/1`.

## Sources deliberately not used

| Candidate | Why not (now) |
|---|---|
| detectopod feed | A third-party feed. The goal of this system is independence from it. Its collector reads only the newest 500 entries of each CT log, weekly; its yield is effectively urlscan.io. |
| Direct CT log tailing | ~27 GB/day per log on a home connection. Upgrade path: a CT stream consumer for live entries, with crt.sh kept for backfill; records are keyed so sources can be mixed. |
| crt.sh PostgreSQL interface | Would allow "logged since" incremental queries (large bandwidth saving), but needs a PostgreSQL client library - a new dependency. Best next step for collection efficiency. |
| urlscan.io search | Useful scan metadata, but leading-wildcard search needs an account/API key; adds a credential and a third-party dependency. |
| External availability services (uptime monitors, URL scanners) | Not needed for trawl's own history; if ever added, a separately labelled source, never merged into trawl's checks. |
| Passive DNS | No free, openly licensed source with adequate coverage for this corpus. |
| RDAP / WHOIS | Registration dates and registrars would be strong temporal/registrar indicators; left out of v2 to keep network surface small. Candidate for the next adapter. |
| Rendering or crawling the sites (favicons, analytics IDs, wallets, screenshots) | Would turn the system into a visitor of hostile infrastructure. Out of scope by design: the availability probe reads only the status line and a few headers of `/`, never follows links or redirects and never executes anything. Indicators are generic `(kind, value)` pairs, so a future, isolated capture step would add a kind to `correlation.kinds` and an extractor - none exists today. |
