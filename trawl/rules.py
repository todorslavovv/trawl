"""Detection rules as data. Change anything here -> bump RULES_VERSION.

Every analysis records RULES_VERSION, and the Methodology page and docs/SCORING.md
are checked against this module by tests, so the published rules cannot drift from
the ones that ran.
"""
from __future__ import annotations

RULES_VERSION = "r1-2026-09-26"

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
    "tollpass": {"label": "TollPass", "sector": "state", "ambiguous": False,
                 "phrases": [["tollpass"], ["toll", "pass"]],
                 "query_keys": ["tollpass"], "official": ["tollpass.bg", "bgtoll.bg"]},
    "vinetki": {"label": "e-vignette (винетки)", "sector": "state", "ambiguous": True,
                "phrases": [["vinetka"], ["vinetki"], ["evinetka"], ["evinetki"]],
                "query_keys": ["vinetk"], "official": ["vinetki.bg", "bgtoll.bg"]},
    "bulbank": {"label": "UniCredit Bulbank", "sector": "bank", "ambiguous": False,
                "phrases": [["bulbank"], ["unicreditbulbank"], ["unicredit", "bulbank"]],
                "query_keys": ["bulbank"],
                "official": ["unicreditbulbank.bg", "bulbank.bg", "bulbankonline.bg"]},
    "dskbank": {"label": "DSK Bank", "sector": "bank", "ambiguous": False,
                "phrases": [["dskbank"], ["dsk", "bank"], ["dskdirect"]],
                "query_keys": ["dskbank"], "official": ["dskbank.bg", "dskdirect.bg"]},
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
}

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
    "store", "live", "delivery", "express",
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
                             "text": "Ambiguous brand token with Bulgarian context in the same name"},
    "brand_lookalike":      {"points": 30, "corroborating": False,
                             "text": "Look-alike of a distinctive brand (one edit, or 1-3 extra letters)"},
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
                             "text": "Brand appears only in a subdomain of an unrelated registrable domain"},
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
