"""Detection rules as data. Change anything here -> bump RULES_VERSION.

Every analysis records RULES_VERSION, and the Methodology page and docs/SCORING.md
are checked against this module by tests, so the published rules cannot drift from
the ones that ran.
"""
from __future__ import annotations

RULES_VERSION = "r3-2026-09-26"

# -- brands ---------------------------------------------------------------------
# distinctive: a match is almost certainly about this brand.
# ambiguous:   the token is also a common word, or the brand exists abroad
#              (German Postbank, Lithuanian Paysera, Greek BOX NOW, North
#              Macedonia's own МВР). Counts only with Bulgarian context in the name,
#              or as an exact-label squat on a high-abuse TLD.
# phrases:     token sequences that spell the brand; each phrase is matched as a
#              contiguous run of words (so "bg-post" and "bgpost" both match).
# official:    registrable domains believed to be the brand's own. Names under
#              them are 'legitimate' and never flagged.
BRANDS: dict[str, dict] = {
    "econt": {"label": "Econt Express", "sector": "courier", "ambiguous": False,
              "phrases": [["econt"], ["ekont"]],
              "query_keys": ["econt"], "official": ["econt.com", "econt.bg"]},
    "speedy": {"label": "Speedy", "sector": "courier", "ambiguous": True,
               "phrases": [["speedy"]],
               "query_keys": ["speedy"], "official": ["speedy.bg"]},
    "bgpost": {"label": "Bulgarian Posts", "sector": "courier", "ambiguous": False,
               "phrases": [["bgpost"], ["bgposta"], ["bulgariapost"], ["bg", "post"],
                           ["bulgaria", "post"], ["bgposhta"]],
               "query_keys": ["bgpost", "bulgariapost"], "official": ["bgpost.bg"]},
    "boxnow": {"label": "BOX NOW", "sector": "courier", "ambiguous": True,
               "phrases": [["boxnow"], ["box", "now"]],
               "query_keys": ["boxnow"], "official": ["boxnow.bg"]},
    "cityexpress": {"label": "City Express", "sector": "courier", "ambiguous": True,
                    "phrases": [["cityexpress"], ["city", "express"]],
                    "query_keys": ["cityexpress"], "official": ["cityexpress.bg"]},
    "expressone": {"label": "Express One", "sector": "courier", "ambiguous": True,
                   "phrases": [["expressone"], ["express", "one"]],
                   "query_keys": ["expressone"], "official": ["expressone.bg"]},
    "dpd": {"label": "DPD", "sector": "courier", "ambiguous": True,
            "phrases": [["dpd"]],
            "query_keys": ["dpd"], "official": ["dpd.bg", "dpd.com"]},
    "sameday": {"label": "Sameday", "sector": "courier", "ambiguous": True,
                "phrases": [["sameday"]],
                "query_keys": ["sameday"], "official": ["sameday.bg"]},
    "mvr": {"label": "Ministry of Interior (МВР)", "sector": "state", "ambiguous": True,
            "phrases": [["mvr"]],
            "query_keys": ["mvr"], "official": ["mvr.bg"]},
    "euslugi": {"label": "МВР e-services", "sector": "state", "ambiguous": False,
                "phrases": [["euslugi"], ["e", "uslugi"], ["eusluga"]],
                "query_keys": ["euslugi"], "official": ["mvr.bg", "egov.bg"]},
    "tollpass": {"label": "TollPass", "sector": "toll", "ambiguous": False,
                 "phrases": [["tollpass"], ["toll", "pass"]],
                 "query_keys": ["tollpass"], "official": ["tollpass.bg", "bgtoll.bg"]},
    "vinetki": {"label": "e-vignette (винетки)", "sector": "toll", "ambiguous": True,
                "phrases": [["vinetka"], ["vinetki"], ["evinetka"], ["evinetki"]],
                "query_keys": ["vinetk"], "official": ["vinetki.bg", "bgtoll.bg"]},
    "bulbank": {"label": "UniCredit Bulbank", "sector": "bank", "ambiguous": False,
                "phrases": [["bulbank"], ["unicreditbulbank"], ["unicredit", "bulbank"]],
                "query_keys": ["bulbank"],
                "official": ["unicreditbulbank.bg", "bulbank.bg", "bulbankonline.bg"]},
    "dskbank": {"label": "DSK Bank", "sector": "bank", "ambiguous": False,
                "phrases": [["dskbank"], ["dsk", "bank"], ["dskdirect"]],
                "query_keys": ["dskbank"], "official": ["dskbank.bg", "dsk.bg", "dskdirect.bg"]},
    "fibank": {"label": "Fibank", "sector": "bank", "ambiguous": False,
               "phrases": [["fibank"]],
               "query_keys": ["fibank"], "official": ["fibank.bg"]},
    "postbank": {"label": "Postbank (Bulgaria)", "sector": "bank", "ambiguous": True,
                 "phrases": [["postbank"]],
                 "query_keys": ["postbank"], "official": ["postbank.bg"]},
    "paysera": {"label": "Paysera", "sector": "payments", "ambiguous": True,
                "phrases": [["paysera"]],
                "query_keys": ["paysera"],
                "official": ["paysera.bg", "paysera.com", "paysera.lt"]},
}

# Registrable domains that legitimately carry a tracked brand token but belong to a
# different, unrelated organisation. Found as false positives in the beta tools.
NAMESAKES: dict[str, str] = {
    "postbank.de": "Deutsche Postbank (Germany) - unrelated to Bulgarian Postbank",
    "postbank.com": "Deutsche Postbank group domain",
    "boxnow.gr": "BOX NOW Greece",
    "boxnow.cy": "BOX NOW Cyprus",
    "dpd.de": "DPD Germany",
    "dpd.co.uk": "DPD United Kingdom",
    "mvr.gov.mk": "Ministry of Interior of North Macedonia",
    "paysera.lv": "Paysera Latvia",
    "cas.ms": "Microsoft Defender for Cloud Apps session proxy - rewrites real sites' host names",
    "mcas.ms": "Microsoft Defender for Cloud Apps session proxy - rewrites real sites' host names",
    "admin-mcas.ms": "Microsoft Defender for Cloud Apps admin proxy - rewrites real sites' host names",
    "dslbank.de": "DSL Bank (Germany) - one letter from DSK Bank, unrelated",
}

# SaaS platforms that give each customer a subdomain (fibank-al.3cx.at, x.floqast.ca).
# A bank's name there is usually the bank's own tenant, so it is not treated as a
# sensitive brand hosted by a stranger. Curated from the first live run; not exhaustive.
TENANT_HOSTS = frozenset({
    "3cx.at", "3cx.eu", "3cx.net", "3cx.us", "3cx.uk", "floqast.ca", "floqast.app",
    "service-now.com", "okta.com", "oktapreview.com", "okta-emea.com", "sharepoint.com",
    "zendesk.com", "atlassian.net", "freshdesk.com", "force.com", "salesforce.com",
    "my.site.com", "workday.com", "myworkday.com", "successfactors.com", "sapsf.com",
    "webex.com", "zoom.us", "slack.com", "box.com", "egnyte.com", "outsystemscloud.com",
    "phos.dev",
})

# Sectors where a brand name hosted under someone else's domain is almost never
# legitimate. Couriers are excluded (shops embed them routinely: econt.shopname.bg), and
# so is toll/vignette ("toll": many licensed resellers, e.g. vinetki.<reseller>.bg).
SENSITIVE_SECTORS = frozenset({"bank", "state", "payments"})

# -- context --------------------------------------------------------------------
BG_MARKERS = frozenset({"bg", "bgr", "bulgaria", "bulgarian", "bulgar", "balgaria",
                        "balgariya", "bulgariya", "sofia", "plovdiv", "varna"})

# Bulgarian-language lure wording, transliterated, with common inflections.
BG_LURES = frozenset({
    "dostavka", "dostavki", "dostavkata", "plashtane", "plashtaniya", "plati",
    "plateno", "plashtai", "taksa", "taksi", "taksata", "paket", "paketa", "paketi",
    "pratka", "pratkata", "pratki", "kurier", "kurieri", "poshta", "poshti",
    "proverka", "mito", "globa", "globi", "nalozhen", "nalojen", "platezh",
    "izprati", "poluchi", "poluchavane", "adres", "danni", "vazstanovi",
    "obnovi", "potvardi", "smetka", "karta",
})

# Transliterations that are also ordinary words in German, Polish, Serbian and other
# languages ("paket", "kurier", "karta"...). They still count as lure wording, but NOT
# as evidence that a name targets Bulgaria. REGRESSION (live run 2026-09-26):
# dpdwebpaket.de and kurier-dpd-piekaryslaskie.pl were flagged as Bulgarian DPD phishing.
SHARED_LURES = frozenset({"paket", "paketa", "paketi", "kurier", "kurieri", "karta",
                          "adres", "mito", "taksi", "danni"})
BG_CONTEXT_LURES = BG_LURES - SHARED_LURES

# Two-letter TLDs that are used as generic TLDs (cheap or vanity), so they say nothing
# about the country a name targets. Any other ccTLD except .bg is "foreign".
GENERIC_CCTLDS = frozenset({"cc", "co", "io", "me", "tv", "ws", "la", "ai", "to", "gg",
                            "ly", "fm", "am", "ga", "ml", "tk", "cf", "gq", "pw", "su",
                            "sh", "ac", "im", "eu", "nu", "vg", "cx", "st", "sx", "lc"})

# English lure wording seen in delivery, toll and banking lures.
EN_LURES = frozenset({
    "pay", "payment", "payments", "delivery", "deliver", "redelivery", "redeliver",
    "parcel", "parcels", "package", "track", "tracking", "trace", "fee", "fees",
    "customs", "duty", "refund", "billing", "invoice", "secure", "security",
    "verify", "verification", "confirm", "confirmation", "update", "account",
    "login", "signin", "support", "reschedule", "shipping", "shipment", "order",
    "status", "notice", "claim", "unpaid", "overdue", "fine", "penalty", "wallet",
})

# Neutral words: they carry no signal but let glued tokens segment
# ("econtonline" -> econt + online). No single letters: they would let almost any
# string segment completely.
FILLER = frozenset({
    "www", "my", "app", "apps", "online", "web", "site", "portal", "official",
    "info", "center", "centre", "central", "landing", "page", "home", "new", "go",
    "get", "service", "services", "system", "mobile", "api", "mail", "shop",
    "store", "net", "pro", "plus", "gov", "id", "eu", "en", "direct", "bank",
    "post", "express", "city", "one", "toll", "pass", "box", "now", "uslugi",
    "usluga", "client", "clients", "customer", "user", "cloud", "hub", "zone",
    "group", "team", "dev", "test", "stage", "prod", "item", "items", "office",
    "net", "link", "click", "help", "news", "card", "cards", "points", "bonus",
    "gift", "prize", "win", "free", "check", "form", "data", "auth", "sso",
    "sms", "global", "int", "national",
})

# -- TLDs -------------------------------------------------------------------------
# High-abuse: cheap, loosely policed, and used by legitimate Bulgarian businesses
# essentially never. Moderate: common in phishing but also in legitimate use.
TLD_HIGH = frozenset({
    "cfd", "icu", "top", "cam", "sbs", "cyou", "lat", "qpon", "bond", "click",
    "rest", "monster", "quest", "autos", "boats", "beauty", "hair", "skin",
    "makeup", "christmas", "tk", "ml", "ga", "cf", "gq", "cc", "pw", "su", "buzz",
    "xyz", "win", "bid", "loan", "work", "lol", "pics", "mom", "zip", "mov", "ink",
    "wang", "rocks", "fit", "vip", "support", "help", "shop", "online", "site",
    "store", "live", "delivery", "express", "bar", "homes",
})
TLD_MODERATE = frozenset({
    "life", "one", "digital", "space", "website", "fun", "info", "biz", "today",
    "link", "world", "tech", "pro", "services", "store", "app",
}) - TLD_HIGH

# -- scoring --------------------------------------------------------------------
# (points, corroborating?) Corroborating signals are the hostile context that must
# accompany a brand before a name can be 'possible' or 'likely'. A brand token on
# its own never is: partners, resellers and integrations carry brand names.
RULES: dict[str, dict] = {
    "brand":                {"points": 40, "corroborating": False,
                             "text": "Distinctive brand token or phrase"},
    "brand_contextual":     {"points": 35, "corroborating": False,
                             "text": "Ambiguous brand token with Bulgarian context in the same name (.bg, a marker such as 'bg', or Bulgarian-only lure wording; not under a foreign ccTLD unless a marker is present)"},
    "brand_lookalike":      {"points": 30, "corroborating": False,
                             "text": "Look-alike of a distinctive brand (one edit, or the brand plus known words and at most 2 stray letters - 1 for 5-letter brands)"},
    "brand_exact_squat":    {"points": 25, "corroborating": False,
                             "text": "Ambiguous brand as the entire registrable label on a high-abuse TLD"},
    "tld_high":             {"points": 20, "corroborating": True,
                             "text": "High-abuse top-level domain"},
    "tld_moderate":         {"points": 10, "corroborating": False,
                             "text": "Moderate-abuse top-level domain"},
    "platform":             {"points": 20, "corroborating": True,
                             "text": "Hosted under a shared hosting/tunnelling platform"},
    "lure_bg":              {"points": 20, "corroborating": True,
                             "text": "Bulgarian-language lure wording (whole words only)"},
    "lure_en":              {"points": 15, "corroborating": True,
                             "text": "English lure wording (whole words only)"},
    "multi_brand_certificate": {"points": 15, "corroborating": True,
                             "text": "A certificate listing this name also lists a name impersonating a different brand"},
    "brand_subdomain":      {"points": 10, "corroborating": False,
                             "text": "Courier brand appears only in a subdomain of an unrelated registrable domain"},
    "sensitive_brand_subdomain": {"points": 15, "corroborating": True,
                             "text": "Bank, state or payments brand appears only in a subdomain of an unrelated registrable domain"},
    "foreign_cctld":        {"points": 15, "corroborating": True,
                             "text": "Distinctive Bulgarian brand combined with other words in a registrable domain under a foreign country-code TLD"},
    "generated_label":      {"points": 10, "corroborating": False,
                             "text": "Machine-generated label (hex/digit run, or random letters between brand and TLD)"},
    "wildcard_certificate": {"points": 10, "corroborating": False,
                             "text": "Wildcard certificate on a high/moderate-abuse TLD (hides subdomains from CT)"},
    "recent_issuance":      {"points": 5, "corroborating": False,
                             "text": "First certificate issued within 7 days of the analysis time (triage priority)"},
    "allowlisted":          {"points": 0, "corroborating": False,
                             "text": "Registrable domain is on the legitimate-domain allow-list"},
    "brand_ignored":        {"points": 0, "corroborating": False,
                             "text": "Ambiguous brand token seen but not counted (no Bulgarian context) - recorded to explain non-detections"},
}

THRESHOLDS = {"likely": 60, "possible": 45}
RECENT_DAYS = 7

VERDICTS = ("likely", "possible", "lead", "weak", "none", "legitimate")
VERDICT_TEXT = {
    "likely": "Brand impersonation with corroborating hostile context, score >= 60",
    "possible": "Brand impersonation with corroborating hostile context, score 45-59",
    "lead": "No brand, but Bulgarian lure wording on a high-abuse TLD or shared platform",
    "weak": "Brand-like token without enough hostile context",
    "none": "No brand and no lead pattern",
    "legitimate": "Allow-listed official or namesake domain",
}


def query_keywords() -> list[str]:
    """The crt.sh keywords this rule set needs, in a stable order."""
    return sorted({k for b in BRANDS.values() for k in b["query_keys"]})


def _vocab() -> frozenset:
    words = set(FILLER) | BG_MARKERS | BG_LURES | EN_LURES
    for b in BRANDS.values():
        for phrase in b["phrases"]:
            words.update(phrase)
    return frozenset(w for w in words if len(w) >= 2)


VOCAB = _vocab()
MAX_WORD = max(len(w) for w in VOCAB)
