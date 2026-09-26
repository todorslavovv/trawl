"""Localisation: Bulgarian is the default, English the alternative, and nothing the UI
can display is left without a translation - including the English evidence sentences
the analysis stores, which the UI renders through the pattern table."""
import json
import random
import re
from pathlib import Path

import pytest

from trawl import availability as AV
from trawl import rules
from trawl.config import load
from trawl.correlate import build
from trawl.scoring import Facts, score
from trawl.server import GLOSSARY, NETWORK, STATIC
from trawl.sources import ADAPTERS, probe

from .conftest import AS_OF

WEB = Path(__file__).resolve().parent.parent / "trawl" / "web"
I18N = json.loads((WEB / "i18n.json").read_text(encoding="utf-8"))
BG, EN = I18N["bg"], I18N["en"]
PATTERNS = [(re.compile(p), rep) for p, rep in I18N["patterns_bg"]]
CYRILLIC = re.compile(r"[А-Яа-я]")


def tx_bg(text: str) -> str:
    """Python port of tx() in app.js (Bulgarian branch)."""
    def match(s):
        for rx, rep in PATTERNS:
            if rx.search(s):
                out = brand_names(rx.sub(re.sub(r"\$(\d)", r"\\g<\1>", rep), s))
                return re.sub(r"\{kinds:([^}]*)\}",
                              lambda m: ", ".join(BG.get(f"kind.{k}", k) for k in m.group(1).split(", ")), out)
        return None

    def brand_names(s):
        for en, bg in I18N["phrases_bg"].items():
            s = s.replace(en, bg)
        for b, spec in rules.BRANDS.items():
            s = s.replace(spec["label"], BG[f"brand.{b}"])
        return s
    whole = match(text)
    if whole is not None:
        return whole
    return "; ".join(match(p) or brand_names(I18N["phrases_bg"].get(p, p)) for p in text.split("; "))


def test_bulgarian_is_the_default_language():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert '<html lang="bg">' in html
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'let LANG = "bg"' in js and 'return LANGS.includes(v) ? v : "bg"' in js
    # both buttons, Bulgarian first and pressed by default
    assert html.index('data-lang="bg"') < html.index('data-lang="en"')
    assert 'data-lang="bg" aria-pressed="true"' in html and 'data-lang="en" aria-pressed="false"' in html
    assert "Български" in html and "English" in html


def test_translations_are_served_same_origin():
    assert STATIC["/i18n.json"][0] == "i18n.json"


def test_both_languages_have_the_same_keys_and_placeholders():
    assert set(BG) == set(EN)
    for k in EN:
        assert BG[k].strip() and EN[k].strip(), k
        assert set(re.findall(r"\{(\w+)\}", BG[k])) == set(re.findall(r"\{(\w+)\}", EN[k])), k


def test_every_key_used_by_the_page_exists():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    html = (WEB / "index.html").read_text(encoding="utf-8")
    used = set(re.findall(r'\bt\("([a-z0-9_.]+)"', js))
    used |= set(re.findall(r'data-i18n(?:-placeholder|-aria)?="([a-z0-9_.]+)"', html))
    assert used - set(EN) == set()


def _needed_dynamic_keys():
    keys = set()
    for v in rules.VERDICTS:
        keys |= {f"verdict.{v}", f"verdict_text.{v}"}
    for tier in ("strong", "corroborated", "chained", "weak"):
        keys |= {f"tier.{tier}", f"tier_text.{tier}"}
    keys |= {f"rule.{r}" for r in rules.RULES}
    keys |= {f"brand.{b}" for b in rules.BRANDS}
    keys |= {f"sector.{s['sector']}" for s in rules.BRANDS.values()}
    keys |= {f"kind.{k}" for k in load()["correlation"]["kinds"]}
    keys |= {f"class.{c}" for c in ("strong", "medium", "weak")}
    keys |= {f"indstatus.{s}" for s in ("active", "suppressed_hub", "singleton")}
    keys |= {f"dns.{o}" for o in ("resolved", "nxdomain", "no_address", "temporary_failure", "failure",
                                   "timeout", "failed", "unchecked")}
    keys |= {f"status.{s}" for s in ("running", "complete", "partial", "failed", "interrupted")}
    keys |= {f"outcome.{o}" for o in ("ok", "ok_empty", "abandoned", "timeout", "http_error",
                                       "network_error", "parse_error", "too_large", "skipped")}
    keys |= {f"coverage.{c}" for c in ("full", "partial", "none")} | {f"coverage_text.{c}" for c in ("full", "partial", "none")}
    keys |= {f"role.{r}" for r in ("prefix", "contains", "dotted")}
    keys |= {f"via.{v}" for v in ("matched_identity", "common_name")}
    for mod in ADAPTERS:
        sid, kind = mod.SOURCE["id"], mod.SOURCE["kind"]
        keys |= {f"source.{sid}.{f}" for f in ("name", "description", "provenance")}
        keys |= {f"srckind.{kind}", f"srcshort.{sid}"}
    for row in NETWORK:
        keys |= {f"net.{row['id']}.{f}" for f in ("from", "purpose", "when", "note")}
    for g in GLOSSARY:
        keys |= {f"glossary.{g['id']}.term", f"glossary.{g['id']}.text"}
    keys |= {f"health.legend.{k}" for k in ("ok", "empty", "abandoned", "timeout", "failed", "skipped")}
    keys |= {f"tl.type.{k}" for k in ("issued", "first_seen", "dns_change")}
    keys |= {f"tl.filter.{k}" for k in ("all", "issued", "first_seen", "dns_change")}
    keys |= {f"meth.does.{i}" for i in range(1, 7)} | {f"meth.cannot.{i}" for i in range(1, 5)}
    keys |= {f"avail.state.{x}" for x in probe.STATES} | {f"avail.reason.{x}" for x in probe.REASONS}
    for x in ("reachable", "unreachable", "unknown", "unchecked"):
        keys |= {f"avail.public.{x}", f"avail.public_text.{x}"}
    for v in AV.REGISTRY:
        keys |= {f"pub.status.{v}", f"pub.status_text.{v}"}
    keys |= {f"avail.tcp.{x}" for x in ("ok", "refused", "timeout", "unreachable", "error")}
    keys |= {f"avail.tls.{x}" for x in ("ok", "cert_invalid", "failed", "timeout")}
    keys |= {f"avail.http.{x}" for x in ("ok", "timeout", "malformed", "no_response")}
    return keys


def test_every_enumerated_value_has_a_translation():
    assert _needed_dynamic_keys() - set(EN) == set()


def test_english_side_matches_the_code_it_describes():
    for r, spec in rules.RULES.items():
        assert EN[f"rule.{r}"] == spec["text"]
    for v in rules.VERDICTS:
        assert EN[f"verdict_text.{v}"] == rules.VERDICT_TEXT[v]
    for mod in ADAPTERS:
        s = mod.SOURCE
        assert (EN[f"source.{s['id']}.name"], EN[f"source.{s['id']}.description"],
                EN[f"source.{s['id']}.provenance"]) == (s["name"], s["description"], s["provenance"])
    for g in GLOSSARY:
        assert (EN[f"glossary.{g['id']}.term"], EN[f"glossary.{g['id']}.text"]) == (g["term"], g["text"])
    for code, (_, text) in probe.REASONS.items():
        assert EN[f"avail.reason.{code}"] == text


# identifiers and technical values that are the same in both languages
SAME_OK = re.compile(r"^(via\.common_name|srckind\..*|srcshort\..*|kind\.tld|net\.browser_crtsh\.note|"
                     r"brand\.(boxnow|dpd|sameday|tollpass|paysera)|search\.placeholder|cert\.wildcard|"
                     r"dns\.nxdomain|unit\..*|col\.dns|col\.dataset_sha)$")


def test_bulgarian_text_is_actually_bulgarian():
    for k, v in BG.items():
        if SAME_OK.match(k) or v == EN[k] and not re.search(r"[A-Za-z]{4,}", v):
            continue
        assert CYRILLIC.search(v), (k, v)


# -- evidence sentences --------------------------------------------------------------------
DATA_ONLY_RULES = {"tld_high", "tld_moderate", "lure_bg", "lure_en", "generated_label", "wildcard_certificate"}
SAMPLE_NAMES = [
    "bgpost-item-track.top", "tollpass.dvhl.cam", "econt.korak-paketa.cyou", "korak-paketa.cyou",
    "tollpasss.sbs", "tolpass-pay.cfd", "vinetka.top", "speedy-bg-dostavka.top", "speedy-feet.com",
    "tollpass.pages.dev", "dskbank.planetanuestro.com", "bulbank-online-ing.com.ua", "girowillkommenspaket.postbank.de",
    "www.paysera.bg", "econt.com", "fibank.bg.admin-us3.cas.ms", "kredit.dslbank.de", "mvr.gov.mk", "boxnow.gr",
    "dpd.de", "postbank.com", "boxnow.cy", "dpd.co.uk", "paysera.lv", "x.mcas.ms", "econt-dostavka-bg.top",
    "fibank.dbs.moneyp.com.br", "e-uslugi-mvr.top", "econt24.top", "speedy.top",
]


def sample_evidence():
    out = set()
    for name in SAMPLE_NAMES:
        for wc in (False, True):
            d = score(Facts(name, wildcard=wc, first_issued="2026-09-24T00:00:00",
                            sibling_brands=frozenset({"bgpost", "econt"})), AS_OF)
            out |= {(s[0], s[3]) for s in d.signals}
    return out


@pytest.mark.parametrize("rule,detail", sorted(sample_evidence()))
def test_every_scoring_detail_is_translated(rule, detail):
    bg = tx_bg(detail)
    if rule in DATA_ONLY_RULES:
        return                                   # e.g. ".top", "pay, track", "*.name"
    assert CYRILLIC.search(bg), (rule, detail, bg)


def test_every_relationship_reason_is_translated():
    from .test_correlation import cfg, synth
    nodes, _ = synth(random.Random(7))
    c = cfg()
    c["min_kinds"], c["require_non_weak"] = 2, True
    reasons = {r.reason for r in build(nodes, c).relationships}
    reasons |= {r.reason for r in build(nodes, cfg(require_non_weak=False)).relationships}
    kinds = {re.sub(r"[\d.]+", "N", r) for r in reasons}
    assert len(kinds) >= 4, kinds                 # strong, corroborated, below-edge, one kind, weak-only
    for r in reasons:
        assert CYRILLIC.search(tx_bg(r)), r
        assert not re.search(r"same_registrable|shared_certificate|kit_shape|issuance_day", tx_bg(r)), tx_bg(r)


def test_every_collection_note_is_translated(conn, cfg):
    from trawl.collect import collect_crtsh

    from .conftest import FakeCrtsh, rec
    cfg["collection"]["truncation_min_records"] = 2
    stale = [rec([f"a{i}.top"], nb="2018-01-01T00:00:00") for i in range(3)]
    data = {"a%": [rec(["a.top"])], "%a%": [], "%.a%": [],
            "b%": "http_error", "%b%": [],
            "c%": [rec([f"c{i}.top"]) for i in range(3)], "%c%": [rec(["x-c.top"])],
            "d%": stale, "%d%": "timeout", "%.d%": "network_error"}
    collect_crtsh(conn, cfg, client=FakeCrtsh(data), keywords=["a", "b", "c", "d"], log=lambda *_: None)
    notes = {r[0] for r in conn.execute("SELECT error FROM queries WHERE error IS NOT NULL")}
    assert len(notes) >= 5, notes
    for n in notes:
        if n.startswith("simulated"):
            continue                              # the fake's own text, not produced by trawl
        assert CYRILLIC.search(tx_bg(n)), n
    for n in ("HTTP 502", "no response within 150 s", "no answer within 12 s", "run time budget exhausted",
              "empty body", "JSON is not a list", "invalid JSON: Expecting value", "body over 1000 bytes"):
        assert tx_bg(n) != n or n.startswith("HTTP"), n


@pytest.mark.parametrize("msg", [
    "no analysis has completed yet", "unknown domain", "unknown certificate", "unknown run",
    "unknown campaign in the current analysis", "name is not a valid domain name", "limit must be an integer",
    "limit must be between 1 and 500", "sort must be one of: first_issued, first_seen, name, score",
    "q too long", "id required", "id must look like C-xxxxxxxxxx",
    "verdict must be a comma list of: likely, possible", "malformed query string", "internal error", "not found",
    "q required",
])
def test_every_api_error_is_translated(msg):
    assert CYRILLIC.search(tx_bg(msg)), msg


def test_namesake_descriptions_are_translated():
    for dom, text in rules.NAMESAKES.items():
        assert CYRILLIC.search(tx_bg(f"{dom}: {text}")), text
