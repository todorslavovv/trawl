"""Explainable scoring of one name.

No model and no hidden weights: a score is the capped sum of named signals, each
with a detail string that says exactly what matched. The verdict is a pure function
of those signals and the thresholds in rules.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from . import rules as R
from .names import Parsed, damerau1, parse, segment, tokens

_HEX = re.compile(r"^[0-9a-f]{6,}$")
_DIGITS = re.compile(r"^[0-9]{5,}$")
_ALPHA = re.compile(r"^[a-z]+$")

_OFFICIAL = {d: b for b, spec in R.BRANDS.items() for d in spec["official"]}
_SINGLE_WORD_DISTINCTIVE = sorted(
    {(p[0], b) for b, s in R.BRANDS.items() if not s["ambiguous"]
     for p in s["phrases"] if len(p) == 1 and len(p[0]) >= 5})


@dataclass(frozen=True)
class Facts:
    """What scoring may know about a name besides the name itself."""
    name: str
    wildcard: bool = False                      # listed as *.name on some certificate
    first_issued: str | None = None             # earliest not_before over its certificates
    sibling_brands: frozenset = frozenset()     # brands of other names on shared certificates


@dataclass
class Decision:
    name: str
    score: int
    verdict: str
    brands: list
    corroborated: bool
    signals: list = field(default_factory=list)   # [(rule, points, corroborating, detail)]


@dataclass(frozen=True)
class NameView:
    parsed: Parsed
    words: tuple            # per label: tuple of words (segmented or raw tokens)
    raw_tokens: tuple       # per label: tuple of raw alphanumeric tokens
    brands: tuple           # ((brand, kind, label_index, detail), ...) counted matches
    ignored: tuple          # ((brand, detail), ...) ambiguous matches without context
    bg_context: bool


def _is_hex(t: str) -> bool:
    return bool(_HEX.match(t)) and any(c.isdigit() for c in t) and any(c.isalpha() for c in t)


def _vowel_ratio(t: str) -> float:
    return sum(c in "aeiou" for c in t) / len(t)


def _words_for(tok: str) -> tuple:
    if tok in R.VOCAB:
        return (tok,)
    seg = segment(tok, R.VOCAB, R.MAX_WORD)
    return tuple(seg) if seg else (tok,)


def _find_phrase(words: tuple, phrase: list) -> bool:
    k = len(phrase)
    return any(list(words[i:i + k]) == phrase for i in range(len(words) - k + 1))


@lru_cache(maxsize=131072)
def view(name: str) -> NameView:
    p = parse(name)
    raw = tuple(tuple(tokens(lbl)) for lbl in p.labels)
    words = tuple(tuple(w for t in toks for w in _words_for(t)) for toks in raw)
    flat = {w for ws in words for w in ws}
    bg_ctx = p.tld == "bg" or bool(flat & R.BG_MARKERS) or bool(flat & R.BG_LURES)

    found: dict = {}
    ignored: list = []
    reg_idx = len(words) - 1
    for brand, spec in R.BRANDS.items():
        for li, ws in enumerate(words):
            hit = next((ph for ph in spec["phrases"] if _find_phrase(ws, ph)), None)
            if hit is None:
                continue
            label = p.labels[li]
            if not spec["ambiguous"]:
                found.setdefault(brand, (brand, "brand", li, f"'{'-'.join(hit)}' in label '{label}'"))
            elif bg_ctx:
                found.setdefault(brand, (brand, "brand_contextual", li,
                                         f"'{'-'.join(hit)}' in label '{label}' with Bulgarian context"))
            elif li == reg_idx and list(ws) == hit and p.tld in R.TLD_HIGH and not p.platform:
                found.setdefault(brand, (brand, "brand_exact_squat", li,
                                         f"'{label}' is exactly the brand, on .{p.tld}"))
            else:
                ignored.append((brand, f"ambiguous '{'-'.join(hit)}' in '{label}' without Bulgarian context"))
            break
    # Look-alikes of distinctive brands, only for tokens that did not segment.
    for li, toks in enumerate(raw):
        for t in toks:
            if t in R.VOCAB or not _ALPHA.match(t) or segment(t, R.VOCAB, R.MAX_WORD):
                continue
            for w, brand in _SINGLE_WORD_DISTINCTIVE:
                if brand in found:
                    continue
                extra = len(t) - len(w)
                if (t.startswith(w) and 1 <= extra <= 3) or (len(w) >= 6 and damerau1(t, w)):
                    found[brand] = (brand, "brand_lookalike", li, f"'{t}' looks like '{w}'")
    brands = tuple(sorted(found.values()))
    ign = tuple(sorted(set(ignored) - {i for i in ignored if i[0] in found}))
    return NameView(p, words, raw, brands, ign, bg_ctx)


def brands_of(name: str) -> frozenset:
    return frozenset(b[0] for b in view(name).brands)


def allowlist_reason(p: Parsed) -> str | None:
    if p.platform:
        return None
    for dom in (p.name, p.registrable):
        if dom in _OFFICIAL:
            return f"{dom} is listed as an official domain of {R.BRANDS[_OFFICIAL[dom]]['label']}"
        if dom in R.NAMESAKES:
            return f"{dom}: {R.NAMESAKES[dom]}"
    return None


def _sig(rule: str, detail: str) -> tuple:
    r = R.RULES[rule]
    return (rule, r["points"], r["corroborating"], detail)


def score(facts: Facts, as_of: str) -> Decision:
    v = view(facts.name)
    p = v.parsed
    why_legit = allowlist_reason(p)
    if why_legit:
        return Decision(facts.name, 0, "legitimate", [], False, [_sig("allowlisted", why_legit)])

    sig: list = []
    if v.brands:
        order = ("brand", "brand_contextual", "brand_lookalike", "brand_exact_squat")
        best = min(v.brands, key=lambda b: order.index(b[1]))
        details = "; ".join(f"{R.BRANDS[b[0]]['label']}: {b[3]}" for b in v.brands)
        sig.append(_sig(best[1], details))
    flat = [w for ws in v.words for w in ws]

    if p.platform:
        sig.append(_sig("platform", f"under shared platform {p.platform}"))
    elif p.tld in R.TLD_HIGH:
        sig.append(_sig("tld_high", f".{p.tld}"))
    elif p.tld in R.TLD_MODERATE:
        sig.append(_sig("tld_moderate", f".{p.tld}"))

    bg_l = sorted(set(flat) & R.BG_LURES)
    en_l = sorted(set(flat) & R.EN_LURES)
    if bg_l:
        sig.append(_sig("lure_bg", ", ".join(bg_l)))
    if en_l:
        sig.append(_sig("lure_en", ", ".join(en_l)))

    own = {b[0] for b in v.brands}
    other = sorted(facts.sibling_brands - own)
    if own and other:
        sig.append(_sig("multi_brand_certificate",
                        "shares a certificate with names impersonating " + ", ".join(other)))

    reg_idx = len(v.words) - 1
    sub_only = own and all(b[2] < reg_idx for b in v.brands) and reg_idx >= 1
    if sub_only:
        sig.append(_sig("brand_subdomain", f"brand in subdomain of {p.registrable}"))

    gen = [t for toks in v.raw_tokens for t in toks if _is_hex(t) or _DIGITS.match(t)]
    if sub_only:
        reg_toks = v.raw_tokens[reg_idx]
        if (len(reg_toks) == 1 and _ALPHA.match(reg_toks[0]) and 4 <= len(reg_toks[0]) <= 8
                and reg_toks[0] not in R.VOCAB and _vowel_ratio(reg_toks[0]) <= 0.25):
            gen.append(reg_toks[0])
    if gen:
        sig.append(_sig("generated_label", ", ".join(sorted(set(gen)))))

    if facts.wildcard and (p.tld in R.TLD_HIGH or p.tld in R.TLD_MODERATE) and not p.platform:
        sig.append(_sig("wildcard_certificate", f"*.{facts.name}"))

    if facts.first_issued:
        try:
            issued = _as_utc(facts.first_issued)
            ref = _as_utc(as_of)
            if timedelta(0) <= ref - issued <= timedelta(days=R.RECENT_DAYS):
                sig.append(_sig("recent_issuance", f"first certificate {facts.first_issued[:10]}"))
        except ValueError:
            pass

    for brand, detail in v.ignored:
        sig.append(("brand_ignored", 0, False, f"{R.BRANDS[brand]['label']}: {detail}"))

    sig.sort(key=lambda s: (-s[1], s[0], s[3]))
    total = min(100, sum(s[1] for s in sig))
    corroborated = any(s[2] for s in sig)
    rules_hit = {s[0] for s in sig}
    if own:
        if corroborated and total >= R.THRESHOLDS["likely"]:
            verdict = "likely"
        elif corroborated and total >= R.THRESHOLDS["possible"]:
            verdict = "possible"
        else:
            verdict = "weak"
    elif "lure_bg" in rules_hit and rules_hit & {"tld_high", "platform"}:
        verdict = "lead"
    else:
        verdict = "none"
    return Decision(facts.name, total, verdict, sorted(own), corroborated, sig)


def _as_utc(s: str) -> datetime:
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def kit_shape(name: str) -> str | None:
    """Structural fingerprint of how a name was generated, or None if not kit-like.

        tollpass.dvhl.cam      -> B.X4.cam
        econt-7fa3b2c.sbs      -> B-H7.sbs
        bgpost-item-track.top  -> B-A4-L.top

    Brand words become B whatever the brand, so one generator used for several
    brands still shares a shape. Human-looking names (brand + one word) return None:
    a shape is only a fingerprint when it looks machine-made.
    """
    v = view(name)
    p = v.parsed
    labels = [(ws, toks) for ws, toks in zip(v.words, v.raw_tokens)]
    if labels and labels[0][1] == ("www",):
        labels = labels[1:]
    if not labels:
        return None
    brand_words = {w for s in R.BRANDS.values() for ph in s["phrases"] for w in ph} - R.FILLER
    out, generative, n_tokens = [], False, 0
    reg_i = len(labels) - 1
    has_brand_sub = any(any(w in brand_words for w in ws) for ws, _ in labels[:-1])
    for i, (ws, toks) in enumerate(labels):
        if i == reg_i and has_brand_sub and len(toks) == 1 and _ALPHA.match(toks[0]) \
                and toks[0] not in R.VOCAB and 3 <= len(toks[0]) <= 8:
            out.append(f"X{len(toks[0])}")
            generative, n_tokens = True, n_tokens + 1
            continue
        codes = []
        for w in ws:
            if w in brand_words:
                c = "B"
            elif w in R.BG_LURES or w in R.EN_LURES:
                c = "L"
            elif w in R.BG_MARKERS:
                c = "M"
            elif w in R.VOCAB:
                c = "W"
            elif _is_hex(w):
                c, generative = f"H{len(w)}", True
            elif w.isdigit():
                c = f"N{len(w)}"
                generative = generative or len(w) >= 3
            elif _ALPHA.match(w) and len(w) >= 4 and _vowel_ratio(w) <= 0.2:
                c, generative = f"R{len(w)}", True
            else:
                c = f"A{len(w)}"
            if not (codes and c == "B" and codes[-1] == "B"):
                codes.append(c)
        n_tokens += len(codes)
        out.append("-".join(codes))
    if not (generative or n_tokens >= 3):
        return None
    return ".".join(out) + "." + p.suffix
