"""Claims must match implementation: docs vs rules/config, frontend safety claims,
network claims, and independence from third-party feeds."""
import re
from pathlib import Path

import pytest

from trawl import config as C
from trawl import rules
from trawl.scoring import Facts, score

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
WEB = ROOT / "trawl" / "web"
REQUIRED_DOCS = ["ARCHITECTURE", "DATA_SOURCES", "METHODOLOGY", "SCORING", "CORRELATION",
                 "PROVENANCE", "OPERATIONS", "SECURITY", "LIMITATIONS"]


def test_all_required_documents_exist():
    assert (ROOT / "README.md").exists()
    for d in REQUIRED_DOCS:
        assert (DOCS / f"{d}.md").stat().st_size > 1000, d


def test_scoring_doc_matches_rules_exactly():
    text = (DOCS / "SCORING.md").read_text()
    assert f"`{rules.RULES_VERSION}`" in text
    rows = dict(re.findall(r"^\| `([a-z_]+)` \| (\d+) \|", text, re.M))
    assert rows == {k: str(v["points"]) for k, v in rules.RULES.items()}
    for k, v in rules.RULES.items():
        line = next(ln for ln in text.splitlines() if ln.startswith(f"| `{k}` |"))
        assert ("| yes |" in line) == v["corroborating"], k
    assert f"score ≥ {rules.THRESHOLDS['likely']}" in text
    assert f"score {rules.THRESHOLDS['possible']}-" in text
    for b in rules.BRANDS.values():
        assert f"| {b['label']} |" in text and ", ".join(b["official"]) in text


@pytest.mark.parametrize("name,kw,expect_score,expect_verdict", [
    ("bgpost-item-track.top", {"wildcard": True}, 85, "likely"),
    ("tollpass.dvhl.cam", {}, 80, "likely"),
    ("speedy-bg-dostavka.top", {}, 75, "likely"),
    ("vinetka.top", {}, 45, "possible"),
    ("unicreditbulbank-bg.com", {}, 40, "weak"),
    ("korak-paketa.cyou", {}, 40, "lead"),
    ("speedypaydayloan.co.uk", {}, 0, "none"),
    ("girowillkommenspaket.postbank.de", {}, 0, "legitimate"),
])
def test_scoring_doc_worked_examples_are_true(name, kw, expect_score, expect_verdict):
    d = score(Facts(name, **kw), "2026-09-26T00:00:00+00:00")
    assert (d.score, d.verdict) == (expect_score, expect_verdict)
    text = (DOCS / "SCORING.md").read_text()
    line = next(ln for ln in text.splitlines() if ln.startswith(f"| `{name}`"))
    assert f"| {expect_score} |" in line and expect_verdict in line


def test_readme_names_the_current_rules_version():
    text = (ROOT / "README.md").read_text()
    mentioned = set(re.findall(r"rules (r\d+)", text))
    assert mentioned == {rules.RULES_VERSION.split("-")[0]}, mentioned


def test_correlation_doc_matches_config():
    text = (DOCS / "CORRELATION.md").read_text()
    for kind, spec in C.DEFAULTS["correlation"]["kinds"].items():
        assert re.search(rf"^\| `{kind}` \| {spec['class']} \| {spec['base']} \| {spec['max_df']} \|",
                         text, re.M), kind
    c = C.DEFAULTS["correlation"]
    assert f"`min_edge` ({c['min_edge']})" in text and f"`min_kinds` (2)" in text
    assert f"`chained_density` ({c['chained_density']})" in text


def test_operations_doc_matches_config_defaults():
    text = (DOCS / "OPERATIONS.md").read_text()
    col = C.DEFAULTS["collection"]
    assert f"| `collection.min_interval_hours` | {col['min_interval_hours']:g} |" in text
    assert f"| `collection.pace_s` | {col['pace_s']:g} |" in text
    assert f"| `collection.request_timeout_s` | {col['request_timeout_s']:g} |" in text


def test_timer_interval_matches_documented_and_enforced_interval():
    # REGRESSION (certwatch): the Deck ran hourly while the docs said six hours.
    timer = (ROOT / "deploy" / "trawl-cycle.timer").read_text()
    hours = C.DEFAULTS["collection"]["min_interval_hours"]
    assert f"OnUnitActiveSec={hours:g}h" in timer
    assert "every 6 h" in (DOCS / "OPERATIONS.md").read_text()


def test_tunnel_unit_uses_only_real_cloudflared_flags():
    unit = (ROOT / "deploy" / "trawl-tunnel.service").read_text()
    exec_line = next(ln for ln in unit.splitlines() if ln.startswith("ExecStart="))
    flags = re.findall(r"--[a-z-]+", exec_line)
    assert flags == ["--no-autoupdate", "--url"]
    assert "--no-update" not in unit
    assert "http://127.0.0.1:8790" in exec_line


def test_web_service_binds_loopback_only():
    unit = (ROOT / "deploy" / "trawl-web.service").read_text()
    assert "--host 127.0.0.1" in unit


# -- frontend -----------------------------------------------------------------------------
def test_frontend_never_uses_html_injection_sinks():
    js = (WEB / "app.js").read_text()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                 "new Function", "setTimeout(\"", "javascript:"):
        assert sink not in js.replace("no innerHTML", ""), sink


def test_frontend_loads_nothing_from_third_parties():
    for f in ("index.html", "app.css", "app.js"):
        text = (WEB / f).read_text()
        urls = re.findall(r"https?://[^\s\"'`)]+", text)
        allowed = {"http://www.w3.org/2000/svg", "https://crt.sh/?id="}
        assert all(any(u.startswith(a) for a in allowed) for u in urls), (f, urls)
    html = (WEB / "index.html").read_text()
    assert "<script>" not in html and "style=" not in html      # no inline code (CSP)
    assert "@import" not in (WEB / "app.css").read_text() and "@font-face" not in (WEB / "app.css").read_text()


def test_external_links_are_only_numeric_crtsh_ids():
    js = (WEB / "app.js").read_text()
    assert re.findall(r"https://crt\.sh/\?id=\$\{([^}]+)\}", js) == ["Number(id)"]
    assert 'rel: "noopener noreferrer"' in js


def test_no_page_claims_there_are_no_network_requests():
    # REGRESSION (certwatch): its page claimed "no network requests" while loading
    # Google Fonts. The claim is not made here; the CSP makes third-party loads impossible.
    for f in list(WEB.iterdir()) + list(DOCS.iterdir()) + [ROOT / "README.md"]:
        assert "no network requests" not in f.read_text().lower(), f


# -- independence --------------------------------------------------------------------------
def test_no_detectopod_in_code_data_or_config():
    offenders = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or ".git" in p.parts or "__pycache__" in p.parts or p.suffix in (".db", ".gz"):
            continue
        if p.parent == DOCS or p.name in ("README.md", "test_docs_and_claims.py"):
            continue          # historical mentions in documentation are allowed
        if p == WEB / "app.js":
            continue          # Methodology page states the independence, naming the feed
        if "detectopod" in p.read_text(errors="ignore").lower():
            offenders.append(str(p))
    assert offenders == []
    assert not list(ROOT.rglob("seed_*"))


def test_no_dependency_on_the_beta_projects():
    for p in (ROOT / "trawl").rglob("*.py"):
        text = p.read_text()
        for beta in ("cobweb", "certwatch", "sealbox", "shopwatch", "OSINT_V3"):
            assert not re.search(rf"^\s*(from|import)\s+{beta}", text, re.M), (p, beta)
            assert f"/{beta}/" not in text, (p, beta)


def test_the_only_http_destination_is_crtsh():
    hits = []
    for p in (ROOT / "trawl").rglob("*.py"):
        text = p.read_text()
        if "urlopen" in text or "http.client" in text or "socket.create_connection" in text:
            hits.append(p.name)
    assert hits == ["crtsh.py"]
