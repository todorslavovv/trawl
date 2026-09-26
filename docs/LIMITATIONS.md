# Limitations

Stated plainly, so that nothing on the site or in a report is read as more than it is.

## What it cannot see

* **No certificate, no detection.** Phishing served over plain HTTP, or from a
  compromised legitimate site, never appears in certificate search.
* **Wildcard certificates hide subdomains.** `*.korak-paketa.cyou` is visible;
  `econt.korak-paketa.cyou` served under it is not. The parent can still surface as a
  `lead` if it carries Bulgarian lure wording on high-abuse infrastructure.
* **Keyword collection.** Only names containing a tracked crt.sh keyword are
  collected. Look-alikes without the keyword (`ekont`, `tolpass`), homoglyph IDNs
  (`есоnt` with Cyrillic letters, stored as `xn--...`), and brands not on the list are
  not searched for. Look-alike rules only apply to names that arrive through another
  keyword.
* **crt.sh is a single, unreliable free dependency.** It abandons expensive scans
  (answering `[]` or a truncated list), returns spurious 404s, and is slow. The system
  records every such outcome and marks runs `partial`, but a partial run *is*
  incomplete coverage. On the first production run (2026-09-25, 18 keywords) crt.sh
  abandoned 17 of the 18 `%keyword%` scans and 11 of the 17 `%.keyword%` fallbacks, and
  one prefix query still failed (HTTP 502) after retries: coverage was `full` for 1
  keyword and `partial` for 17. For those, coverage rests on the prefix query
  (`keyword%`) and, where it answered, the dotted fallback (keyword at the start of a
  label) - a name with the keyword in the middle of a label (`my-econt-pay.top`) is then
  missed.
* **Only unexpired certificates are collected**, because crt.sh caps large full-history
  answers to their oldest rows (measured: `econt%` stopped at 2018). A certificate that
  was issued and expired between two collection runs - rare with 6-hourly runs and
  90-day certificates - is not seen. History accumulates from the first run onwards.
* **crt.sh lags the CT logs**, often by days, so "first collected" trails issuance.
* **crt.sh lists only matching identities**, so the certificate view shows the names
  we queried for, not necessarily every name on a certificate.
* **DNS from one vantage point.** Answers come from the host's resolver at one moment;
  geo- or client-dependent answers and fast-flux are not captured. `getaddrinfo` gives
  no TTLs, CNAME chains or raw response codes.

## What it cannot establish

* **Maliciousness.** The system never renders a site; the availability check records
  only whether and how `/` answered. A certificate for a look-alike name is a signal;
  it is not proof that a phishing page was ever served.
* **Operators or people.** A campaign is a hypothesis about shared infrastructure.
  Shared registrable domains and certificates indicate common *control*; shared
  addresses and naming patterns are weaker. None of it identifies anyone.
* **Real-world accuracy.** Scoring is tested against known real examples and every
  false positive found in the beta tools; correlation is measured against synthetic
  ground truth (precision 1.00, recall 0.78). No labelled Bulgarian dataset exists to
  measure either on real data.

## Availability semantics

* **Reachable means "something answered"** at the domain's address - a normal page, a
  redirect, a 403, a 404, a rate limit or a bot-protection challenge. It never means
  the phishing content was seen, and a challenge is never bypassed.
* **Unreachable is one failed check from one place.** NXDOMAIN, no address, a sinkhole
  or refused connections at that moment; the site may return or answer other networks.
* **Undetermined is common and honest.** Timeouts, TLS problems (expired or wrong
  certificates) and 5xx answers - e.g. Cloudflare 521 "origin down" - are not called
  reachable or unreachable. On the first production run (2026-09-26, 335 domains):
  204 reachable, 35 unreachable, 96 undetermined (30 timeouts, 37 TLS errors,
  28 server errors, 1 network error).
* **One vantage point, once a day.** Checks come from the deployment host only, at
  most about daily per domain; geo-, time- or client-dependent behaviour is not seen,
  and nothing is known between checks.
* **Visible to operators.** Each check reveals the checking host's IP address and a
  research User-Agent; an operator can block or cloak it, which shows up as a 403,
  challenge or timeout.
* **Port 443, then 80 only.** Services on other ports are not considered.

## Known weaknesses of the rules

* The allow-list of official domains is an engineering list, not confirmed with each
  brand; a missing official domain would be scored like any other name.
* Ambiguous brands (Speedy, DPD, МВР, Postbank, Paysera, BOX NOW...) need Bulgarian
  context in the name. A campaign against them that uses no Bulgarian wording and no
  high-abuse exact-label squat is scored `weak` or `none` (false negative by design,
  traded for far fewer false positives).
* Legitimate integrations, staging systems and SaaS tenants that carry a brand name
  under someone else's domain (`bulbank.<vendor>-staging.app`, an Econt module on a
  shared platform) can score `possible`/`likely`. Curated lists (`TENANT_HOSTS`,
  `NAMESAKES`) cover the cases seen so far; others appear as leads to review.
* The public suffix handling is a curated subset plus a generic ccTLD second-level rule
  (`com.XX`, `co.XX`, ...), not the full Public Suffix List.
* Components chain; the `chained` tier and density make this visible but do not split
  a component.
* Rarity weights are relative to the flagged population of one analysis; below ~30
  flagged names they are not meaningful (a warning is logged).

## Operational

* The public demo URL is a Cloudflare Quick Tunnel: random hostname, changes on
  restart, no uptime guarantee, not for production. Cloudflare terminates TLS and can
  see the traffic it relays.
* The Deck's user services stop if the `deck` session ends (`Linger=no`).
* Two collectors query crt.sh from the Deck: this system (every 6 h) and the older
  `certwatch` beta (hourly, left untouched).
