"""The web server: read-only, strict headers, no traversal, validated parameters,
no stack traces, and every API route answering for real data."""
import http.client
import json
import threading

import pytest

from trawl import config as C
from trawl.analysis import flagged_by_priority, run_analysis
from trawl.collect import collect_crtsh, dnscheck
from trawl.db import connect
from trawl.server import SECURITY_HEADERS, make_server

from .conftest import FakeCrtsh, fake_resolver
from .test_pipeline_snapshot import DATA, DNS


@pytest.fixture(scope="module")
def server_cfg(tmp_path_factory):
    c = C.load()
    d = tmp_path_factory.mktemp("srv")
    c["db_path"], c["snapshot_dir"] = str(d / "t.db"), str(d / "snaps")
    conn = connect(c["db_path"])
    collect_crtsh(conn, c, client=FakeCrtsh(DATA), keywords=["bgpost", "econt", "tollpass"], log=lambda *_: None)
    dnscheck(conn, c, flagged_by_priority(conn, c), resolve=fake_resolver(DNS), log=lambda *_: None)
    run_analysis(conn, c, as_of="2026-09-26T00:00:00+00:00", log=lambda *_: None)
    conn.close()
    return c


@pytest.fixture(scope="module")
def server(server_cfg):
    srv = make_server(server_cfg["db_path"], "127.0.0.1", 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def req(port, path, method="GET", body=None, raw=False):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    if raw:
        c.putrequest(method, path, skip_accept_encoding=True)
        c.endheaders()
    else:
        c.request(method, path, body=body)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r, data


def j(port, path):
    r, data = req(port, path)
    return r.status, json.loads(data) if data else None


def test_index_and_assets_served_with_security_headers(server):
    for path, ctype in (("/", "text/html"), ("/app.js", "text/javascript"), ("/app.css", "text/css")):
        r, body = req(server, path)
        assert r.status == 200 and r.getheader("Content-Type").startswith(ctype) and body
        for k, v in SECURITY_HEADERS.items():
            assert r.getheader(k) == v
        assert r.getheader("Server") == "trawl"          # no Python version disclosure
        assert r.getheader("Access-Control-Allow-Origin") is None


def test_csp_forbids_third_party_loads():
    csp = SECURITY_HEADERS["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "connect-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp and "http" not in csp


@pytest.mark.parametrize("path", [
    "/../trawl.db", "/%2e%2e/%2e%2e/etc/passwd", "/app.js/../../trawl/db.py", "/web/app.js",
    "/.git/config", "/.env", "/data/trawl.db", "/trawl.db", "//etc/passwd", "/index.html",
    "/api/", "/api/../app.js", "/api/domains/../../x", "/api/nope",
])
def test_no_traversal_or_file_exposure(server, path):
    r, body = req(server, path, raw=True)
    assert r.status == 404
    assert b"root:" not in body and b"sqlite" not in body.lower()


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"])
def test_only_get_and_head(server, method):
    r, _ = req(server, "/api/overview", method=method, body=b"x")
    assert r.status == 405


def test_head_has_no_body(server):
    r, body = req(server, "/api/overview", method="HEAD")
    assert r.status == 200 and body == b""


@pytest.mark.parametrize("path", [
    "/api/meta", "/api/overview", "/api/domains", "/api/domains?verdict=likely,possible&sort=first_seen&order=asc",
    "/api/domains?q=tollpass&dns=resolved", "/api/domains?brand=econt&since_days=3650&since_field=first_issued",
    "/api/domain?name=tollpass.dvhl.cam", "/api/certificates", "/api/certificates?flagged=all&q=econt",
    "/api/certificate?id=1", "/api/campaigns", "/api/campaigns?tier=strong", "/api/timeline?days=3650",
    "/api/timeline?kind=dns_change", "/api/sources", "/api/runs", "/api/runs?source=dns", "/api/run?id=1",
    "/api/analyses", "/api/methodology",
])
def test_api_routes_answer(server, path):
    status, body = j(server, path)
    assert status == 200, (path, body)


def test_campaign_detail_explains_every_edge(server):
    _, camps = j(server, "/api/campaigns")
    for c in camps["rows"]:
        status, d = j(server, f"/api/campaign?id={c['id']}")
        assert status == 200 and d["members"]
        assert all(e["evidence"] and e["reason"] for e in d["edges"])


def test_domain_detail_carries_provenance(server):
    _, d = j(server, "/api/domain?name=tollpass.dvhl.cam")
    assert d["records"] and d["records"][0]["payload_sha256"] and d["records"][0]["query"]
    assert d["provenance"]["dataset_sha256"] and d["signals"]
    assert d["dns"][0]["outcome"] == "resolved"


@pytest.mark.parametrize("path,status", [
    ("/api/domains?verdict=likely;DROP%20TABLE%20domains", 400),
    ("/api/domains?sort=name;--", 400), ("/api/domains?order=sideways", 400),
    ("/api/domains?limit=100000", 400), ("/api/domains?limit=-1", 400), ("/api/domains?offset=abc", 400),
    ("/api/domains?brand=../../x", 400), ("/api/domains?q=" + "a" * 101, 400),
    ("/api/domain?name=<script>alert(1)</script>", 400), ("/api/domain?name=nosuch.example", 404),
    ("/api/campaign?id=C-'or'1'='1", 400), ("/api/campaign?id=C-0000000000", 404),
    ("/api/certificate?id=1e9", 400), ("/api/timeline?days=99999", 400), ("/api/runs?source=file", 400),
])
def test_parameters_are_validated(server, path, status):
    got, body = j(server, path)
    assert got == status and "error" in body
    assert "Traceback" not in json.dumps(body)


def test_like_wildcards_in_search_are_literal(server):
    _, all_rows = j(server, "/api/domains?verdict=likely,possible,lead,weak,none,legitimate")
    _, pct = j(server, "/api/domains?q=%25&verdict=likely,possible,lead,weak,none,legitimate")
    _, und = j(server, "/api/domains?q=_&verdict=likely,possible,lead,weak,none,legitimate")
    assert all_rows["total"] > 0 and pct["total"] == 0 and und["total"] == 0


def test_database_is_opened_read_only(server, server_cfg):
    ro = connect(server_cfg["db_path"], readonly=True)
    with pytest.raises(Exception):
        ro.execute("DELETE FROM domains")


def test_overlong_request_line_rejected(server):
    r, _ = req(server, "/api/domains?q=" + "a" * 3000)
    assert r.status == 414


def test_internal_errors_do_not_leak(server, monkeypatch):
    from trawl import server as S

    def boom(self, p):
        raise RuntimeError("secret internal detail /home/deck/trawl-data")
    monkeypatch.setattr(S.Api, "sources", boom)
    status, body = j(server, "/api/sources")
    assert status == 500 and body == {"error": "internal error"}


def test_request_with_body_closes_the_connection(server):
    import socket
    s = socket.create_connection(("127.0.0.1", server), timeout=5)
    # a GET with a body followed by a smuggled request on the same connection
    s.sendall(b"GET /api/meta HTTP/1.1\r\nHost: x\r\nContent-Length: 30\r\n\r\n"
              b"GET /api/sources HTTP/1.1\r\n\r\n")
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    assert data.count(b"HTTP/1.1 ") == 1 and b"Connection: close" in data
