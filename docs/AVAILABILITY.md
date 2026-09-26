# Availability

The public registry answers one more question about each listed domain: **did its
infrastructure respond when trawl checked it?** This document is the model behind the
"Last checked", "Last confirmed reachable" and "State at the last check" fields, and
what those fields do and do not mean.

## What is checked, and how often

* **Scope: the registry only** - the flagged names (`likely`, `possible`, `lead`) of the
  latest complete analysis, a few hundred names. The many thousands of raw
  certificate names are never checked.
* **When:** as a step of the 6-hourly cycle (`collect → DNS re-check → analyze →
  availability → snapshot`), and with `trawl availability [--force]`. A name is
  *due* when its last check is older than `availability.recheck_hours` (20 h), so with
  6-hourly cycles every registry name is checked about **once a day**. Names never
  checked go first, then the longest-unchecked.
* **Tier:** a name whose last `unreachable_after` (3) checks were all `unreachable`
  waits `unreachable_recheck_hours` (68 h, about three days) between checks. Upgrade
  path if the registry grows: more tiers (e.g. newly listed / recently reachable
  more often), still configured in `availability.*`.
* **Load:** at most `max_per_run` (500) names per run, `workers` (6) in parallel, one
  TCP connection and one HTTP request per name, a hard time limit per check and a
  run budget (`max_run_minutes`, 45); names not started within the budget are recorded
  as skipped, not guessed.

A visitor's search **never** triggers a check: `/api/lookup` is a database query in the
read-only web process, which opens no outbound connection at all (tested).

## One check

`trawl/sources/probe.py`, standard library only, no browser:

1. **Name.** Re-validated as a DNS name; IP literals, URLs, ports and anything else are
   not checked (`invalid_name`).
2. **DNS.** One `getaddrinfo` through the host resolver (8 s limit). Every answer is
   filtered: only globally routable unicast addresses are kept - loopback, RFC 1918,
   CGNAT (including the tailnet), link-local (including `169.254.169.254`), multicast,
   reserved, IPv6 ULA / link-local and every IPv4-in-IPv6 form (mapped, NAT64, 6to4,
   Teredo) are refused. A name that resolves only to such addresses is recorded as
   `non_public` and **not contacted**.
3. **TCP.** To the vetted address itself - there is no second lookup, so a DNS
   rebinding answer cannot redirect the connection. Port 443 first; port 80 only if
   443 could not be connected. IPv4 before IPv6, at most 2 addresses per port, 6 s each.
4. **TLS** (port 443). Verified against the system trust store, SNI = the name, 8 s.
   An invalid certificate stops the check: nothing is sent over an unverified channel.
5. **HTTP.** One `GET / HTTP/1.1` with `Host: <name>`, `Connection: close`, no cookies,
   no credentials, User-Agent `Mozilla/5.0 (compatible; trawl-availability/1;
   research)`. Kept: status code, `Location` (truncated, **never followed**), `Server`,
   whether a bot-protection challenge was served. At most 16 KiB of headers and 16 KiB
   of body are read; the body is only scanned for challenge markers and discarded.
   Nothing is rendered, executed or stored.

Every wait on the socket is bounded (non-blocking I/O with `poll`), and each whole
check has a hard limit (`total_timeout_s`, 30 s), so a server that drips bytes cannot
hold the checker.

## Classification

Each check ends in one **reason** (stored), which fixes its **state** (stored) and the
**public state** shown to visitors. Reasons are explained in both UI languages.

| Reason | State | Public | Meaning |
|---|---|---|---|
| `http_2xx` | reachable | Reachable | answered 2xx |
| `http_3xx` | reachable | Reachable | answered with a redirect; recorded, not followed |
| `http_denied` | reachable | Reachable | 401 / 403 / 407 |
| `http_429` | reachable | Reachable | rate-limited the check |
| `http_4xx` | reachable | Reachable | another 4xx, e.g. 404 - the server answered; the page was not confirmed |
| `challenge` | reachable | Reachable | a bot-protection challenge (Cloudflare `cf-mitigated: challenge`, or a 403/429/503 challenge page) |
| `http_5xx` | server_error | Undetermined | a server answered with 5xx - often a proxy whose origin is down (Cloudflare 52x) |
| `http_other` | unknown | Undetermined | an unexpected status (e.g. 1xx) |
| `http_malformed` | dns_only | Undetermined | the connection was accepted but the answer was not valid HTTP |
| `no_response` | dns_only | Undetermined | accepted, then closed without an answer |
| `http_timeout` | timeout | Undetermined | no HTTP answer in time |
| `tls_cert_invalid` | tls_error | Undetermined | certificate not valid for the name (expired, self-signed, other name) |
| `tls_failed` | tls_error | Undetermined | handshake failed |
| `tls_timeout` | timeout | Undetermined | handshake did not finish in time |
| `refused` | unreachable | Unreachable | every connection on 443 and 80 was refused |
| `tcp_timeout` | timeout | Undetermined | no connection in time |
| `network_error` | unknown | Undetermined | no route from the checker (e.g. an IPv6-only host) |
| `nxdomain` | unreachable | Unreachable | the name does not exist in DNS |
| `no_address` | unreachable | Unreachable | the name has no A/AAAA record |
| `non_public` | unreachable | Unreachable | only non-public addresses (sinkhole); not contacted |
| `dns_failure` | unknown | Undetermined | the lookup failed (SERVFAIL, resolver unavailable) |
| `dns_timeout` | timeout | Undetermined | no DNS answer in time |
| `invalid_name`, `deadline`, `error` | unknown / timeout | Undetermined | not checkable, overall time limit, unexpected failure |

Rules behind the table: only a response proves reachability; only DNS non-existence,
a sinkhole or refused connections count as unreachable; a timeout, a TLS problem or a
5xx is *undetermined* - it is not called "down". 4xx is not "down" either: the
infrastructure answered.

**Bot protection.** A Cloudflare (or DDoS-Guard, Sucuri, Akamai) front is recorded
from the response headers. A challenge is **recorded, never solved or bypassed**. It
counts as reachable - the infrastructure answered - and never as confirmation of the
page behind it.

## History and the public fields

`availability_observations` (in the same SQLite database) holds one row per check:
`run_id`, `source_id` (`availability`) and `checker` (`probe/1`) - the method -,
`domain`, `checked_at`, `duration_ms`, the DNS result and all addresses, the address and
port contacted, the TCP, TLS and HTTP results, `http_status`, `location`, `server`,
`protection`, `challenge`, `body_bytes`, `truncated`, `state`, `reason`, `error`. Rows
are appended and never updated or deleted. Each run is also a `collection_runs` row
with the counts per state.

From a domain's observations alone (`trawl/availability.py:summarize`):

| Field | Definition |
|---|---|
| Last checked | time of the latest check |
| Last confirmed reachable | time of the latest check whose state was `reachable` |
| Previously confirmed reachable | the one before that |
| State at the last check | public state of the latest check; `Not checked` if there is none |
| Checks / reachable / not confirmed | counts |

**A missing observation is never evidence.** If a domain was reachable on 25 Sep, not
checked on 26 Sep and reachable on 27 Sep, trawl shows "last confirmed reachable 27
Sep, previously 25 Sep" and nothing at all for 26 Sep. The UI says so next to the
history.

If a whole run could not resolve anything (three or more names, none answered - the
checker's own network was down), the run is marked `failed`; its rows are kept and
shown with a mark, but summaries ignore them.

## What availability is not

* **Reachable ≠ phishing content verified.** The page is never rendered or read.
* **Unreachable ≠ permanently gone.** It is one failed check from one place at one
  time; the domain may come back, or answer other networks.
* **A Cloudflare challenge ≠ offline**, and ≠ confirmation of the page behind it.
* **DNS failure ≠ deletion.** NXDOMAIN is reported as such; a failed lookup is
  undetermined.
* **Not a detection input.** Availability never changes scores, verdicts, campaigns,
  snapshots or any fingerprint; the analysis dataset excludes the probe's source and
  runs (tested, and the production snapshot still replays to its recorded
  fingerprints).

## Visibility

A check is visible to the domain's operator: the TCP connection comes from the checking
host's public IP address and the request carries the User-Agent above. That is the
cost of an availability history and the reason checks are daily, single-request and
limited to the registry. No other availability provider is used; if one is ever added
it will be a separate source with its own `source_id`, never merged into trawl's own
checks.

## Configuration

`availability.*` in `trawl/config.py` (validated; see [OPERATIONS](OPERATIONS.md)):
`enabled`, `recheck_hours`, `unreachable_after`, `unreachable_recheck_hours`,
`max_per_run`, `workers`, `max_run_minutes`, `dns_timeout_s`, `connect_timeout_s`,
`tls_timeout_s`, `response_timeout_s`, `total_timeout_s`, `max_addresses`,
`max_header_bytes`, `max_body_bytes`.
