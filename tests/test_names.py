import pytest

from trawl.names import damerau1, normalise, parse, segment, tokens
from trawl.rules import MAX_WORD, VOCAB


@pytest.mark.parametrize("raw,expected", [
    ("Econt-Pay.TOP.", ("econt-pay.top", False)),
    ("*.bgpost-track.cfd", ("bgpost-track.cfd", True)),
    ("xn--80ak6aa92e.xn--90ae", ("xn--80ak6aa92e.xn--90ae", False)),   # IDN TLD kept
    ("_dmarc.example.com", ("_dmarc.example.com", False)),
])
def test_normalise_accepts_dns_names(raw, expected):
    assert normalise(raw) == expected


@pytest.mark.parametrize("raw", [
    "speedy payroll limited",        # crt.sh returns organisation names
    "admin@econt.com",               # and e-mail addresses
    "192.168.1.10", "", "   ", "localhost", "-bad-.com", "a" * 64 + ".com",
])
def test_normalise_rejects_non_dns(raw):
    assert normalise(raw) is None


@pytest.mark.parametrize("name,registrable,suffix,platform,labels", [
    ("tollpass.dvhl.cam", "dvhl.cam", "cam", None, ("tollpass", "dvhl")),
    ("tollpass.pages.dev", "tollpass.pages.dev", "pages.dev", "pages.dev", ("tollpass",)),
    ("x.y.econt.co.uk", "econt.co.uk", "co.uk", None, ("x", "y", "econt")),
    ("a.b.s3.amazonaws.com", "b.s3.amazonaws.com", "s3.amazonaws.com", "s3.amazonaws.com", ("a", "b")),
    ("pages.dev", "pages.dev", "dev", None, ("pages",)),
    ("econt.com", "econt.com", "com", None, ("econt",)),
    ("fibank.com.kh", "fibank.com.kh", "com.kh", None, ("fibank",)),   # REGRESSION (live run)
    ("mail.bulbank--unicredit.com.ua", "bulbank--unicredit.com.ua", "com.ua", None, ("mail", "bulbank--unicredit")),
    ("x.dskbank-bg.co.ua", "dskbank-bg.co.ua", "co.ua", None, ("x", "dskbank-bg")),
])
def test_parse_suffix_and_registrable(name, registrable, suffix, platform, labels):
    p = parse(name)
    assert (p.registrable, p.suffix, p.platform, p.labels) == (registrable, suffix, platform, labels)


def test_tokens_keep_hex_runs_whole_and_split_letters_from_digits():
    assert tokens("econt-7fa3b2c") == ["econt", "7fa3b2c"]
    assert tokens("speedy-dev-1cc7ff6ca661") == ["speedy", "dev", "1cc7ff6ca661"]
    assert tokens("pocztoweuslugi278995449") == ["pocztoweuslugi", "278995449"]
    assert tokens("econt24") == ["econt", "24"]
    assert tokens("xn--80ak6aa92e") == ["xn--80ak6aa92e"]
    assert tokens("decade") == ["decade"]          # all-letter hex-alphabet word stays a word


@pytest.mark.parametrize("tok,words", [
    ("bgposttrack", ["bgpost", "track"]),
    ("econtbgdostavka", ["econt", "bg", "dostavka"]),
    ("paysera", ["paysera"]),               # never pay + sera
    ("econtainer", None),                   # REGRESSION (beta): not econt + ...
    ("girowillkommenspaket", None),         # REGRESSION (beta): German, not "paket"
    ("pocztoweuslugi", None),               # REGRESSION (beta): Polish, not "uslugi"
    ("speedypaydayloan", None),
])
def test_segment_is_complete_or_nothing(tok, words):
    assert segment(tok, VOCAB, MAX_WORD) == words


def test_segment_prefers_fewest_words():
    assert segment("unicreditbulbank", VOCAB, MAX_WORD) == ["unicreditbulbank"]


@pytest.mark.parametrize("a,b,expected", [
    ("tollpas", "tollpass", True), ("tollpsas", "tollpass", True), ("tolpass", "tollpass", True),
    ("tollpass", "tollpass", False), ("toolpas", "tollpass", False), ("fibamk", "fibank", True),
    ("ibank", "fibank", False), ("xibank", "fibank", False),     # first character is never edited
])
def test_damerau1(a, b, expected):
    assert damerau1(a, b) is expected
