"""Detection quality: known positives, known false positives from the beta tools,
explanation integrity, and determinism."""
import pytest

from trawl import rules
from trawl.scoring import Facts, kit_shape, score

from .conftest import AS_OF


def verdict(name, **kw):
    return score(Facts(name, **kw), AS_OF)


# -- should be flagged (synthetic + shapes observed in real Bulgarian campaigns) ---------
@pytest.mark.parametrize("name,expected", [
    ("bgpost-item-track.top", "likely"),
    ("tollpass.dvhl.cam", "likely"),          # kit: brand.<random>.cam
    ("tollpass.vqio.cam", "likely"),
    ("econt.korak-paketa.cyou", "likely"),    # brand subdomain + BG lure
    ("euslugi-system.cc", "likely"),
    ("e-uslugi-mvr.top", "likely"),           # phrase across tokens: e + uslugi
    ("bgposttrack.top", "likely"),            # glued brand + lure
    ("tollpass.pages.dev", "likely"),         # brand on a shared platform
    ("econt-7fa3b2c.sbs", "likely"),          # hex kit label
    ("speedy-bg-dostavka.top", "likely"),     # ambiguous brand WITH Bulgarian context
    ("bg-post-plashtane.icu", "likely"),
    ("dsk-bank-verify.xyz", "likely"),
    ("fibank.xyz", "likely"),
    ("bgpost.shop", "likely"),                # .shop is high-abuse (seen live, 2026-09)
    ("tollpasss.sbs", "possible"),            # look-alike: extra letters
    ("tolpass-pay.cfd", "likely"),            # look-alike: one edit, plus lure
    ("vinetka.top", "possible"),              # exact-label squat of an ambiguous brand
    ("speedy.top", "possible"),
    ("dpd-pratka.top", "likely"),             # Bulgarian-only context word still works
    ("bgpostkd.top", "possible"),             # kit: brand + 2 random letters
    ("bgpostaabg.fit", "possible"),           # kit seen live: brand + letter(s) + bg
    ("bgpostwbg.work", "possible"),
    # r3, from the live-data review: bank/state brands hosted under unrelated domains,
    # and distinctive brands with extra words under foreign ccTLDs
    ("bulbankonline.orangecountyraingutters.com", "possible"),
    ("dskbank.planetanuestro.com", "possible"),
    ("fibank.dbs.moneyp.com.br", "possible"),
    ("bulbank-online-ing.com.ua", "possible"),
    ("dskbank-bg.co.ua", "possible"),
    ("bulbank-hostveri.myftp.biz", "likely"),          # dynamic DNS is a shared platform
    ("bgpost.bar", "likely"),
])
def test_true_positives(name, expected):
    assert verdict(name).verdict == expected, verdict(name)


def test_lead_without_brand():
    d = verdict("korak-paketa.cyou", wildcard=True)
    assert d.verdict == "lead" and d.brands == []


# -- must NOT be flagged: every one of these was a real false positive -----------------
@pytest.mark.parametrize("name", [
    "econtainer-gar.ml",                   # REGRESSION (certwatch): econt inside econtainer
    "econtrack.co.uk",                     # REGRESSION (certwatch)
    "speedypaydayloan.co.uk",              # REGRESSION (certwatch): "speedy" is English
    "speedy-feet.com", "speedy-flower-delivery.xyz",
    "mvr-coin.ga", "mvr-crypto.ga",        # REGRESSION (certwatch): crypto scams, not МВР
    "mvr-gov-mk.cyou",                     # North Macedonia's ministry, not Bulgaria's
    "postbank-datenverifizierung.xyz",     # REGRESSION (certwatch): German Postbank
    "vinetki-dlya-vypusknikov.tk",         # REGRESSION (certwatch): Russian
    "pocztoweuslugi278995449.cfd",         # REGRESSION (cobweb): Polish "postal services"
    "boxnow.aeginapetmarket.gr",           # Greek BOX NOW integration
    "mvrf.tk",                             # three letters are not the ministry
    "dpd-tracking.de",                     # DPD abroad, no Bulgarian context
    "www.syslog.dpdwebpaket.de",           # REGRESSION (v2 live run): German "paket"
    "kurier-dpd-piekaryslaskie.pl",        # REGRESSION (v2 live run): Polish "kurier"
    "econtrek.win",                        # REGRESSION (v2 live run): look-alike too loose
    "econtact.cf", "econtato.tk",          # REGRESSION (v2 live run): e-contact / e-contato
    "econteudo.tk",                        # REGRESSION (v2 live run): Portuguese e-conteudo
    "econtent.am",                         # REGRESSION (v2 live run): e-content
    "fibank.com.kh", "fibank.gr", "econt.hu",   # exact brand under a foreign ccTLD: namesake-like
    "econt.simplamarket.net",              # courier embedded by a shop: integration pattern
    "ibank.uralexpress.ru",                # REGRESSION (r3 review): first-letter edit of fibank
    "econt.bayern.ro",                     # REGRESSION (r3 review): brand only in a foreign subdomain
    "fibank.floqast.ca", "fibank-al.3cx.at",   # SaaS customer tenants
    "fibanko.es", "econta.mx", "econti.cz",   # REGRESSION (r3 review): look-alike abroad is not "brand + words"
    "vinetki.aib.bg",                      # licensed vignette reseller pattern
])
def test_false_positives_stay_unflagged(name):
    d = verdict(name)
    assert d.verdict in ("none", "weak"), d
    assert d.verdict not in ("likely", "possible", "lead")


@pytest.mark.parametrize("name", [
    "girowillkommenspaket.postbank.de",    # REGRESSION (certwatch): namesake + "paket"
    "www.paysera.bg",                      # REGRESSION (certwatch): official, "pay" inside
    "fibank.bg.admin-us3.cas.ms",          # Microsoft Defender for Cloud Apps proxy
    "dskbank.bg.admin-mcas.ms",
    "dskbank.dsk.bg",                      # DSK Bank's own domain
    "kredit.dslbank.de",                   # namesake: DSL Bank (Germany)
    "econt.com", "www.econt.bg", "e-uslugi.mvr.bg", "speedy.bg", "tollpass.bg",
    "mvr.gov.mk",
])
def test_allowlisted_domains_are_legitimate(name):
    d = verdict(name)
    assert d.verdict == "legitimate" and d.score == 0
    assert d.signals[0][0] == "allowlisted"


def test_platform_subdomain_is_never_allowlisted():
    assert verdict("econt.pages.dev").verdict == "likely"


def test_brand_alone_is_weak_not_flagged():
    d = verdict("unicreditbulbank-bg.com")
    assert d.verdict == "weak" and not d.corroborated


def test_ambiguous_brand_without_context_is_recorded_not_counted():
    d = verdict("speedy-feet.com")
    assert d.brands == []
    assert [s[0] for s in d.signals] == ["brand_ignored"]


# -- explanation integrity ---------------------------------------------------------------
@pytest.mark.parametrize("name", ["bgpost-item-track.top", "tollpass.dvhl.cam", "fibank.xyz",
                                  "econt.korak-paketa.cyou", "korak-paketa.cyou"])
def test_score_is_exactly_the_capped_sum_of_signals(name):
    d = verdict(name, wildcard=True, first_issued="2026-09-24T00:00:00")
    assert d.score == min(100, sum(s[1] for s in d.signals))
    for rule, pts, corr, detail in d.signals:
        assert rule in rules.RULES
        assert pts == rules.RULES[rule]["points"] and corr == rules.RULES[rule]["corroborating"]
        assert detail


def test_likely_requires_a_corroborating_signal():
    for name in ["bgpost-item-track.top", "tollpass.pages.dev", "fibank.xyz"]:
        d = verdict(name)
        assert d.verdict == "likely" and any(s[2] for s in d.signals)


def test_multi_brand_certificate_signal():
    d = score(Facts("econt-dostavka.com", sibling_brands=frozenset({"bgpost"})), AS_OF)
    assert "multi_brand_certificate" in [s[0] for s in d.signals]
    assert d.verdict == "likely"


def test_recent_issuance_uses_as_of_not_wall_clock():
    fresh = score(Facts("econt-pay.top", first_issued="2026-09-24T00:00:00"), AS_OF)
    later = score(Facts("econt-pay.top", first_issued="2026-09-24T00:00:00"), "2027-01-01T00:00:00+00:00")
    assert "recent_issuance" in [s[0] for s in fresh.signals]
    assert "recent_issuance" not in [s[0] for s in later.signals]


def test_scoring_is_deterministic():
    names = ["bgpost-item-track.top", "tollpass.dvhl.cam", "econt.korak-paketa.cyou"]
    a = [score(Facts(n, wildcard=True), AS_OF) for n in names]
    b = [score(Facts(n, wildcard=True), AS_OF) for n in names]
    assert [(x.score, x.verdict, x.signals) for x in a] == [(x.score, x.verdict, x.signals) for x in b]


# -- kit shapes ----------------------------------------------------------------------------
@pytest.mark.parametrize("name,shape", [
    ("tollpass.dvhl.cam", "B.X4.cam"),
    ("tollpass.vqio.cam", "B.X4.cam"),        # same kit despite different vowels
    ("econt-7fa3b2c.sbs", "B-H7.sbs"),
    ("www.econt-7fa3b2c.sbs", "B-H7.sbs"),    # leading www ignored
    ("bgpost-item-track.top", "B-W-L.top"),     # "item" is a neutral word (W)
    ("econt-pay.top", None),                  # human-looking: not a fingerprint
])
def test_kit_shape(name, shape):
    assert kit_shape(name) == shape
