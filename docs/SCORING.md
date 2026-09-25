# Scoring

Rule set **`r1-2026-09-26`** (`trawl/rules.py`, recorded in every analysis). This
document is checked against the code by `tests/test_docs_and_claims.py`.

## Principle

A score is the **capped sum (max 100) of named signals**. Every signal stores the text
it matched, so "why was this flagged" is always answerable by reading the signals.
There is no model and no hidden weight.

A brand token on its own never flags a name: partners, resellers, integrations and
unrelated namesakes carry brand names all the time. A name becomes *possible* or
*likely* only when a **corroborating** signal - hostile context - accompanies the brand.

## Matching: tokens, not substrings

1. A name is split into labels, the public or platform suffix is removed
   (`tollpass.pages.dev` → label `tollpass`, platform `pages.dev`).
2. Each label is split into tokens on `-`/`_` and at letter/digit boundaries. Hex runs
   (`7fa3b2c`) stay whole.
3. A token is a word if it is in the vocabulary (brand phrases, lure words, context
   markers, neutral filler words). Otherwise it is **segmented completely** into
   vocabulary words, fewest words first (`bgposttrack` → `bgpost` + `track`). If no
   complete segmentation exists, the token stays opaque and matches nothing.
4. Brands match as **phrases**: contiguous word sequences (`bgpost`, `bg`+`post`,
   `e`+`uslugi`).

This is what keeps the beta tools' false positives out: `econtainer` is not Econt,
`girowillkommenspaket` has no "paket", `paysera` has no "pay", the Polish
`pocztoweuslugi` has no "uslugi".

**Distinctive vs ambiguous brands.** Distinctive brands count on sight. Ambiguous
brands (a common word, or the brand exists abroad) count only with **Bulgarian
context** in the same name - the `.bg` TLD, a marker such as `bg`/`bulgaria`, or
Bulgarian lure wording - or as an **exact-label squat** on a high-abuse TLD
(`vinetka.top`). Otherwise they are recorded as `brand_ignored` (0 points) so that a
non-detection is explainable too.

**Look-alikes** of distinctive single-word brands of 5+ letters: the brand followed by
1-3 extra letters (`tollpasss`), or, for brands of 6+ letters, one edit away
(`tolpass`). Only tokens that did not segment are considered.

## Rules

| Rule | Points | Corroborating | Meaning |
|---|---:|:---:|---|
| `brand` | 40 | – | Distinctive brand token or phrase |
| `brand_contextual` | 35 | – | Ambiguous brand token with Bulgarian context in the same name |
| `brand_lookalike` | 30 | – | Look-alike of a distinctive brand (one edit, or 1-3 extra letters) |
| `brand_exact_squat` | 25 | – | Ambiguous brand as the entire registrable label on a high-abuse TLD |
| `tld_high` | 20 | yes | High-abuse top-level domain |
| `tld_moderate` | 10 | – | Moderate-abuse top-level domain |
| `platform` | 20 | yes | Hosted under a shared hosting/tunnelling platform |
| `lure_bg` | 20 | yes | Bulgarian-language lure wording (whole words only) |
| `lure_en` | 15 | yes | English lure wording (whole words only) |
| `multi_brand_certificate` | 15 | yes | A certificate listing this name also lists a name impersonating a different brand |
| `brand_subdomain` | 10 | – | Brand appears only in a subdomain of an unrelated registrable domain |
| `generated_label` | 10 | – | Machine-generated label (hex/digit run, or random letters between brand and TLD) |
| `wildcard_certificate` | 10 | – | Wildcard certificate on a high/moderate-abuse TLD (hides subdomains from CT) |
| `recent_issuance` | 5 | – | First certificate issued within 7 days of the analysis time (triage priority) |
| `allowlisted` | 0 | – | Registrable domain is on the legitimate-domain allow-list |
| `brand_ignored` | 0 | – | Ambiguous brand token seen but not counted (no Bulgarian context) - recorded to explain non-detections |

Only the strongest brand signal counts (the detail lists every brand matched).
`recent_issuance` is measured against the analysis `as_of`, never the wall clock, so
re-running an old analysis gives the same answer. Infrastructure relationships are
**not** added to the score - that would make scoring and correlation reinforce each
other circularly; they are shown alongside it.

## Verdicts

| Verdict | Condition |
|---|---|
| `likely` | a brand signal, at least one corroborating signal, score ≥ 60 |
| `possible` | a brand signal, at least one corroborating signal, score 45-59 |
| `lead` | no brand; Bulgarian lure wording on a high-abuse TLD or shared platform |
| `weak` | a brand signal without enough hostile context |
| `none` | nothing matched |
| `legitimate` | the name or its registrable domain is allow-listed |

`likely`, `possible` and `lead` are "flagged": they are DNS-checked and correlated.

## Brands

| Brand | Sector | Match | Phrases | crt.sh keywords | Allow-listed |
|---|---|---|---|---|---|
| Econt Express | courier | distinctive | `econt`, `ekont` | `econt` | econt.com, econt.bg |
| Speedy | courier | ambiguous | `speedy` | `speedy` | speedy.bg |
| Bulgarian Posts | courier | distinctive | `bgpost`, `bgposta`, `bulgariapost`, `bg-post`, `bulgaria-post`, `bgposhta` | `bgpost`, `bulgariapost` | bgpost.bg |
| BOX NOW | courier | ambiguous | `boxnow`, `box-now` | `boxnow` | boxnow.bg |
| City Express | courier | ambiguous | `cityexpress`, `city-express` | `cityexpress` | cityexpress.bg |
| Express One | courier | ambiguous | `expressone`, `express-one` | `expressone` | expressone.bg |
| DPD | courier | ambiguous | `dpd` | `dpd` | dpd.bg, dpd.com |
| Sameday | courier | ambiguous | `sameday` | `sameday` | sameday.bg |
| Ministry of Interior (МВР) | state | ambiguous | `mvr` | `mvr` | mvr.bg |
| МВР e-services | state | distinctive | `euslugi`, `e-uslugi`, `eusluga` | `euslugi` | mvr.bg, egov.bg |
| TollPass | state | distinctive | `tollpass`, `toll-pass` | `tollpass` | tollpass.bg, bgtoll.bg |
| e-vignette (винетки) | state | ambiguous | `vinetka`, `vinetki`, `evinetka`, `evinetki` | `vinetk` | vinetki.bg, bgtoll.bg |
| UniCredit Bulbank | bank | distinctive | `bulbank`, `unicreditbulbank`, `unicredit-bulbank` | `bulbank` | unicreditbulbank.bg, bulbank.bg, bulbankonline.bg |
| DSK Bank | bank | distinctive | `dskbank`, `dsk-bank`, `dskdirect` | `dskbank` | dskbank.bg, dskdirect.bg |
| Fibank | bank | distinctive | `fibank` | `fibank` | fibank.bg |
| Postbank (Bulgaria) | bank | ambiguous | `postbank` | `postbank` | postbank.bg |
| Paysera | payments | ambiguous | `paysera` | `paysera` | paysera.bg, paysera.com, paysera.lt |

Phrases are matched in any collected name; **collection** only finds names containing
a crt.sh keyword. A phrase such as `ekont`, `bg-post` or `dskdirect` is therefore
recognised when it arrives on a certificate found by another keyword, not searched for
on its own.

The allow-list is an engineering list of domains believed to be official; it has not
been independently confirmed with each brand. Namesakes - legitimate, unrelated
organisations that carry a tracked token (`postbank.de`, `mvr.gov.mk`, `boxnow.gr`,
...) - are listed in `rules.NAMESAKES` and treated as `legitimate`. Names under a
shared platform are never allow-listed.

## Worked examples

| Name | Signals | Score | Verdict |
|---|---|---:|---|
| `bgpost-item-track.top` (wildcard cert) | brand 40, tld_high 20, lure_en 15 (`track`), wildcard_certificate 10 | 85 | likely |
| `tollpass.dvhl.cam` | brand 40, tld_high 20, brand_subdomain 10, generated_label 10 (`dvhl`) | 80 | likely |
| `speedy-bg-dostavka.top` | brand_contextual 35, lure_bg 20, tld_high 20 | 75 | likely |
| `vinetka.top` | brand_exact_squat 25, tld_high 20 | 45 | possible |
| `unicreditbulbank-bg.com` | brand 40 | 40 | weak (no hostile context) |
| `korak-paketa.cyou` | lure_bg 20 (`paketa`), tld_high 20 | 40 | lead |
| `speedypaydayloan.co.uk` | – | 0 | none (does not segment) |
| `girowillkommenspaket.postbank.de` | allowlisted (namesake) | 0 | legitimate |

## Regression list

Every false positive found by running the beta tools on live data is a test in
`tests/test_scoring.py`: `econtainer-gar.ml`, `econtrack.co.uk`,
`speedypaydayloan.co.uk`, `mvr-coin.ga`, `postbank-datenverifizierung.xyz`,
`vinetki-dlya-vypusknikov.tk`, `pocztoweuslugi278995449.cfd`,
`girowillkommenspaket.postbank.de`, `www.paysera.bg`, and others.
