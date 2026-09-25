"""Domain-name parsing: validation, public suffix, tokens, word segmentation.

The lesson from both beta tools is that substring matching on names is wrong:
"econt" inside "econtainer", "paket" inside the German "girowillkommenspaket",
"pay" inside "paysera", "uslugi" inside the Polish "pocztoweuslugi". Everything here
therefore works on tokens: a name is split into labels, labels into alphanumeric
tokens, and a glued token only yields words when the WHOLE token segments into
known vocabulary ("bgposttrack" -> bgpost + track). A token that does not segment
completely yields nothing - it stays an opaque word.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

# A DNS name, optionally wildcarded. Rejects organisation names, e-mail addresses,
# IP addresses and anything with spaces. Punycode TLDs (xn--...) are allowed.
_HOSTNAME = re.compile(
    r"(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"(?:xn--[a-z0-9-]{2,59}|[a-z]{2,63})")
_IPV4ISH = re.compile(r"^[0-9.]+$")

# Multi-label public suffixes that matter for this corpus. Not the full Public
# Suffix List.
# ponytail: a curated subset. Upgrade path: vendor publicsuffix.org's list and load
# it here; registrable() is the only consumer.
PUBLIC_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz", "com.br",
    "com.tr", "co.za", "co.jp", "com.cn", "com.ua", "co.in", "com.mx", "com.gr",
    "com.cy", "com.ro", "com.pl", "net.pl", "org.pl", "com.ru", "com.es", "co.il",
    "com.sg", "com.hk", "com.tw", "eu.org", "co.com", "us.com", "uk.com", "eu.com",
    "de.com", "ru.com", "com.de", "com.se", "za.com",
})

# Shared hosting / tunnelling platforms. Under these, the registrable unit is the
# customer's label (tollpass.pages.dev), and the platform is a signal of its own:
# a brand name on a shared platform is never the brand's own infrastructure.
PLATFORM_SUFFIXES = frozenset({
    "pages.dev", "workers.dev", "r2.dev", "web.app", "firebaseapp.com",
    "herokuapp.com", "netlify.app", "vercel.app", "github.io", "gitlab.io",
    "glitch.me", "repl.co", "replit.app", "onrender.com", "surge.sh",
    "000webhostapp.com", "azurewebsites.net", "blogspot.com", "wixsite.com",
    "weebly.com", "trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app",
    "fly.dev", "deno.dev", "railway.app", "appspot.com", "cloudfront.net",
    "pythonanywhere.com", "webflow.io", "framer.app", "framer.website",
    "godaddysites.com", "mystrikingly.com", "carrd.co", "tilda.ws", "square.site",
    "wordpress.com", "blogspot.bg", "sites.google.com", "notion.site", "gitbook.io",
    "serveo.net", "loca.lt", "duckdns.org", "ddns.net", "no-ip.org", "hopto.org",
    "zapto.org", "servehttp.com", "firebaseio.com", "amplifyapp.com",
    "s3.amazonaws.com", "storage.googleapis.com", "windows.net", "ipfs.dweb.link",
    "run.app", "b-cdn.net", "myshopify.com", "jimdosite.com", "yolasite.com",
})

_SUFFIXES = PUBLIC_SUFFIXES | PLATFORM_SUFFIXES
_MAX_SUFFIX_LABELS = max(s.count(".") + 1 for s in _SUFFIXES)


def normalise(raw: str) -> tuple[str, bool] | None:
    """Return (name without '*.', wildcard?) or None if this is not a DNS name."""
    n = (raw or "").strip().lower().rstrip(".")
    if not n or len(n) > 253 or not _HOSTNAME.fullmatch(n) or _IPV4ISH.match(n):
        return None
    if n.startswith("*."):
        return n[2:], True
    return n, False


@dataclass(frozen=True)
class Parsed:
    name: str
    suffix: str            # public suffix or platform suffix, e.g. "top", "co.uk", "pages.dev"
    tld: str               # last label
    registrable: str       # suffix + one label ("dvhl.cam", "tollpass.pages.dev")
    platform: str | None   # platform suffix if the name sits under one
    labels: tuple          # labels left of the suffix, left to right


@lru_cache(maxsize=65536)
def parse(name: str) -> Parsed:
    parts = name.split(".")
    suffix = parts[-1]
    for k in range(min(_MAX_SUFFIX_LABELS, len(parts) - 1), 1, -1):
        cand = ".".join(parts[-k:])
        if cand in _SUFFIXES:
            suffix = cand
            break
    n_suffix = suffix.count(".") + 1
    labels = tuple(parts[:-n_suffix])
    registrable = ".".join(parts[-(n_suffix + 1):]) if labels else name
    platform = suffix if suffix in PLATFORM_SUFFIXES else None
    return Parsed(name, suffix, parts[-1], registrable, platform, labels)


_TOKEN = re.compile(r"[a-z]+|[0-9]+")
_HEXISH = re.compile(r"^[0-9a-f]{6,}$")


def tokens(label: str) -> list[str]:
    """Tokens of one label: hyphen/underscore parts, split at letter/digit
    boundaries - except hex runs ("7fa3b2c"), which stay whole because splitting
    them destroys exactly the machine-generated pattern worth seeing.
    Punycode labels are opaque."""
    if label.startswith("xn--"):
        return [label]
    out: list[str] = []
    for part in re.split(r"[-_]+", label):
        if not part:
            continue
        if _HEXISH.match(part) and not part.isdigit() and not part.isalpha():
            out.append(part)
        else:
            out.extend(_TOKEN.findall(part))
    return out


def segment(token: str, vocab: frozenset, max_word: int) -> list[str] | None:
    """Split `token` completely into vocabulary words, fewest words first.

    Returns None when no complete split exists. A partial split never counts: that
    is what keeps "econtainer" from yielding "econt".
    """
    n = len(token)
    if n == 0 or n > 63:
        return None
    best: list = [None] * (n + 1)
    best[0] = []
    for i in range(n):
        if best[i] is None:
            continue
        for j in range(i + 1, min(n, i + max_word) + 1):
            w = token[i:j]
            if w in vocab and (best[j] is None or len(best[i]) + 1 < len(best[j])):
                best[j] = best[i] + [w]
    return best[n]


def damerau1(a: str, b: str) -> bool:
    """True if a and b differ by exactly one edit (insert, delete, substitute, swap)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return (len(diff) == 2 and diff[1] == diff[0] + 1
                and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]
