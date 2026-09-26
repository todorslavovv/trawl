# Correlation

Correlation proposes which flagged names (`likely`, `possible`, `lead`) appear to
share infrastructure. Its output is a **campaign hypothesis** - a lead for an
investigator, never proof of common ownership and never attribution to a person.

## Indicators

Each flagged name carries indicators - `(kind, value)` pairs - built in
`trawl/analysis.py:indicators_for` from the analysis' fixed input:

| Kind | Class | Base | max_df | Value | Source |
|---|---|---:|---:|---|---|
| `same_registrable` | strong | 10.0 | 150 | registrable domain (platform-aware: `x.pages.dev`) | name |
| `shared_certificate` | strong | 8.0 | 40 | certificate key (issuer CA id + serial) | crt.sh |
| `shared_ip` | medium | 2.5 | 15 | A/AAAA address from the latest DNS observation | DNS |
| `kit_shape` | medium | 2.5 | 40 | naming fingerprint, e.g. `B.X4.cam`, `B-H7.sbs` | name |
| `issuance_day` | weak | 1.0 | 25 | first certificate's date + issuing CA | crt.sh |
| `brand` | weak | 1.0 | 25 | brand counted by scoring | scoring |
| `lure` | weak | 0.8 | 25 | each lure word | name |
| `platform` | weak | 0.4 | 8 | shared platform | name |
| `tld` | weak | 0.3 | 8 | top-level domain (when not on a platform) | name |

(`Class`, `Base` and `max_df` are the defaults in `config.DEFAULTS["correlation"]`;
every analysis stores the configuration it used and its SHA-256.)

Excluded before they become indicators:
* **Multi-tenant certificates** - CDN certificates issued for many unrelated customers
  (`*.cloudflaressl.com` and similar common names).
* **Shared or meaningless addresses** - Cloudflare's published anycast ranges, and
  any address that is not globally routable (sinkholes like 127.0.0.1, private
  ranges).

**Why these are strong.** Every name under one registrable domain is controlled by its
registrant. A domain-validated certificate is issued to whoever demonstrated control of
every name on it. Both are about control of infrastructure, not about coincidence.
They are still suppressed if a single value spans more than `max_df` flagged names,
which would indicate a platform the suffix list does not yet know.

**Kit shapes** reduce a name to its structure: brand words → `B`, lure words → `L`,
context markers → `M`, neutral words → `W`, hex runs → `H<len>`, digit runs →
`N<len>`, consonant soup → `R<len>`, a single random label between a brand subdomain
and the TLD → `X<len>`, other words → `A<len>`, plus the suffix. Only machine-looking
shapes count (containing H/N/R/X, or 3+ tokens): "brand + one word" is how people name
domains and is not a fingerprint.

## Weighting and suppression

For medium and weak kinds: `weight = base × ln(N / df)`, where N is the number of
flagged names in the analysis and df the number carrying that exact value. A value
carried by more than `max_df` names describes the ecosystem, not an actor, and is
**suppressed**; a value carried by one name is a singleton. Strong kinds have a fixed
weight. Suppressed values are listed in every analysis so the step is auditable.

## Accepting a relationship

Two names sharing active indicators form a candidate relationship with the summed
weight of their shared evidence. It is **accepted** if:

* it shares any **strong** indicator (`strength = strong`), or
* its weight ≥ `min_edge` (2.0), **and** its evidence spans ≥ `min_kinds` (2) different
  kinds, **and** (`require_non_weak`, new in v2) at least one of them is medium or
  strong (`strength = corroborated`).

Everything else is kept as a **rejected candidate** with the reason, and shown in the
UI ("did not meet the corroboration rules"), so a weak hypothesis is visible as weak.

Why `require_non_weak`: in the beta (cobweb), the largest campaign rested on "same
brand + reported on the same day" - two weak coincidences. Two weak kinds can no
longer link on their own. A single shared IP (shared hosting) or a single shared shape
also cannot link on its own.

## Campaign hypotheses and tiers

Campaigns are the connected components of accepted relationships (size ≥ 2). IDs are
derived from the member list (`C-` + 10 hex of its SHA-256), so the same group gets the
same id in every analysis and in a replay. Each campaign records size, links, density
(links / possible links), cohesion (mean link weight), weakest link, brands, and first/
last issuance.

| Tier | Meaning |
|---|---|
| `strong` | the strong relationships alone connect every member |
| `corroborated` | connected by corroborated relationships, not sparse |
| `chained` | 4+ members and density below `chained_density` (0.34): held together through intermediaries - review before relying on it |

Components chain (A-B and B-C put A and C together). The tier and the density are how
that is made visible instead of hidden.

## Measured evaluation (synthetic ground truth)

`tests/test_correlation.py` builds a corpus with known membership (322 names): 8 kit
campaigns deployed over two days with partly shared addresses, each with one
*partial-signature* member that shares only the naming shape; 4 shared-hosting
campaigns; 4 same-registrable pairs; 4 shared-certificate pairs; two **sibling
operations** (same brand, TLD and day, different kits) that must not merge; 24
coincidental names sharing brand + day + TLD; 200 background names. Pairwise scores,
measured 2026-09-26 on seeds 7, 11, 23, 42 and 99:

| Rule set | Precision | Recall |
|---|---:|---:|
| v2 (defaults) | **1.000** (all seeds) | 0.782 (all seeds) |
| beta-like (`require_non_weak = false`) | 0.994-1.000 | 0.782 |
| naive (any shared attribute links) | 0.040-0.126 | 1.000 |

The missed pairs are exactly the partial-signature members, which share only one kind
of evidence and are skipped by design. The v2 rule never merged the sibling operations.
These figures are against synthetic data: real-world precision and recall are not
measured, because no labelled Bulgarian campaign dataset exists.
