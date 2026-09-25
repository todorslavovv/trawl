# Methodology

## What the system detects

Domain names that appear in publicly logged TLS certificates and look like they
impersonate one of the tracked Bulgarian brands (couriers, МВР e-services, TollPass /
e-vignette, banks, Paysera), plus "leads": names with Bulgarian lure wording on
high-abuse infrastructure but no brand. It then proposes which of those names appear
to share infrastructure.

## Levels of claim

The system keeps five levels distinct, in code, API and UI:

| Level | Meaning | Example |
|---|---|---|
| **Observation** | A recorded fact about a public record, with its source and time | crt.sh returned certificate 29522075310 listing `econt-pay.top` in run 4; the resolver answered NXDOMAIN at 2026-09-27 03:10 UTC |
| **Signal** | A named rule that fired on a name, with points and the text it matched | `tld_high +20 (.top)` |
| **Relationship** | Two flagged names sharing indicators; accepted only under the corroboration rules | `kit_shape B.X4.cam + issuance_day 2026-07-28` |
| **Campaign hypothesis** | A connected group of accepted relationships | `C-1f0e...`, tier `corroborated` |
| **Verified fact** | Not produced by this system | confirmation needs content capture, registrar/hosting records or legal process |

Nothing here identifies a person, and campaign membership is never presented as proof
of common ownership.

## Pipeline

1. **Collect** (`collect`). For each tracked keyword, query crt.sh for **unexpired**
   certificates with a prefix pattern and a contains pattern (and a dotted fallback
   when needed); crt.sh caps full-history answers to their oldest rows, so current
   certificates are what can be collected completely. Classify every
   outcome; detect abandoned and truncated scans; store every record verbatim; record
   per-keyword coverage and the run status. See [DATA_SOURCES](DATA_SOURCES.md).
2. **Normalise.** Split each record's identities into names (dropping non-DNS
   identities), merge precertificate and final certificate, and index which
   certificate lists which name, as wildcard or not, as SAN match or common name.
3. **DNS re-check** (`dnscheck`). Resolve the currently flagged names (highest score
   first), append one observation per name.
4. **Analyse** (`analyze`). Fix the input by cut-offs (last finished run, last record,
   last DNS observation) and a time reference `as_of`; score every name
   ([SCORING](SCORING.md)); build indicators for flagged names and correlate them
   ([CORRELATION](CORRELATION.md)); write results; record the dataset and results
   fingerprints ([PROVENANCE](PROVENANCE.md)).
5. **Snapshot** (`snapshot`, daily in the cycle). Export the exact input dataset of an
   analysis, with a manifest that a third party can verify and replay.

## What it cannot establish

See [LIMITATIONS](LIMITATIONS.md). In short: that a site is malicious (it is never
visited), who operates anything, completeness of coverage (certificate search misses
HTTP-only phishing, compromised sites and wildcard-hidden subdomains, and crt.sh
abandons some queries), and real-world accuracy (no labelled Bulgarian ground truth
exists; the rules are tested on known examples and synthetic campaigns).

## Language

The docs, API and UI use: *observation*, *signal*, *lead*, *relationship*, *potential
campaign* / *campaign hypothesis*. They do not say "identifies criminal groups",
"attributes", or "confirms".
