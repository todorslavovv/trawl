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
  incomplete coverage. On the first live run most `%keyword%` scans were abandoned, so
  coverage for those keywords rests on the prefix query (`keyword%`) - names where the
  keyword is not at the start of the name (`my-econt-pay.top`) are then missed.
* **crt.sh lists only matching identities**, so the certificate view shows the names
  we queried for, not necessarily every name on a certificate.
* **DNS from one vantage point.** Answers come from the host's resolver at one moment;
  geo- or client-dependent answers and fast-flux are not captured. `getaddrinfo` gives
  no TTLs, CNAME chains or raw response codes.

## What it cannot establish

* **Maliciousness.** The system never visits a site. A certificate for a look-alike
  name is a signal; it is not proof that a phishing page was ever served.
* **Operators or people.** A campaign is a hypothesis about shared infrastructure.
  Shared registrable domains and certificates indicate common *control*; shared
  addresses and naming patterns are weaker. None of it identifies anyone.
* **Real-world accuracy.** Scoring is tested against known real examples and every
  false positive found in the beta tools; correlation is measured against synthetic
  ground truth (precision 1.00, recall 0.78). No labelled Bulgarian dataset exists to
  measure either on real data.

## Known weaknesses of the rules

* The allow-list of official domains is an engineering list, not confirmed with each
  brand; a missing official domain would be scored like any other name.
* Ambiguous brands (Speedy, DPD, МВР, Postbank, Paysera, BOX NOW...) need Bulgarian
  context in the name. A campaign against them that uses no Bulgarian wording and no
  high-abuse exact-label squat is scored `weak` or `none` (false negative by design,
  traded for far fewer false positives).
* The public suffix handling is a curated subset, not the full Public Suffix List.
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
