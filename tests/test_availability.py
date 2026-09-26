"""Availability probe and history. Everything runs against local sockets and a fake
resolver: no test contacts a real site. The SSRF guard stays on in every test - the
fake resolver hands out a public-looking address and a fake connect() routes it to a
local server, so the real address filter is what is being tested."""
from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from trawl import availability as AV
from trawl import config as C
from trawl.sources import probe as P

from .conftest import fake_resolver

HOST = "probe.test"
PUBLIC_IP = "93.184.216.34"


def acfg(**over):
    c = C.load()["availability"] | {"dns_timeout_s": 2.0, "connect_timeout_s": 2.0, "tls_timeout_s": 2.0,
                                    "response_timeout_s": 2.0, "total_timeout_s": 5.0}
    c.update(over)
    return c


class Local:
    """A local TCP server; handler(conn, server) runs for every accepted connection."""

    def __init__(self, handler, tls: ssl.SSLContext | None = None):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.handler, self.tls, self.accepted, self.requests = handler, tls, 0, []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        try:
            if self.tls:
                c = self.tls.wrap_socket(c, server_side=True)
            self.handler(c, self)
        except Exception:
            pass
        finally:
            c.close()

    def close(self):
        self.sock.close()


def read_head(c, srv):
    c.settimeout(3)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = c.recv(4096)
        if not chunk:
            break
        data += chunk
    srv.requests.append(data)
    return data


def reply(raw: bytes, *, then=None):
    def handler(c, srv):
        read_head(c, srv)
        c.sendall(raw)
        if then:
            then(c)
    return handler


def router(ports: dict):
    """connect() stand-in: the vetted address is kept, the port is mapped to a local
    server port (or an exception to raise)."""
    calls = []

    def connect(addr, port, timeout):
        calls.append((addr, port))
        target = ports.get(port, ConnectionRefusedError())
        if isinstance(target, BaseException):
            raise target
        return socket.create_connection(("127.0.0.1", target), timeout=timeout)
    connect.calls = calls
    return connect


RESOLVE = fake_resolver({HOST: [PUBLIC_IP]})


def plain(raw: bytes, **kw):
    """Probe HOST against a plain-HTTP local server (443 refused, 80 served)."""
    srv = Local(reply(raw, **kw.pop("then_kw", {})))
    try:
        conn = router({443: ConnectionRefusedError(), 80: srv.port})
        r = P.probe(HOST, acfg(**kw), resolve=RESOLVE, connect=conn)
        return r, srv, conn
    finally:
        srv.close()


# -- SSRF guard ----------------------------------------------------------------------------
@pytest.mark.parametrize("addr", [
    "127.0.0.1", "127.8.9.10", "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1",
    "100.119.132.39",                                  # tailnet (CGNAT) - the Deck's own network
    "169.254.169.254", "169.254.1.1", "0.0.0.0", "224.0.1.1", "239.255.255.250", "240.0.0.1",
    "255.255.255.255", "192.0.0.1", "198.18.0.1", "192.0.2.1", "::1", "::", "fe80::1", "fd00::1",
    "fc00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1",
    "64:ff9b:1::a00:1", "2002:a00:1::1", "2001::1", "2001:db8::1", "fe80::1%eth0", "not-an-ip", "",
])
def test_non_public_addresses_are_refused(addr):
    assert not P.is_public(addr)


@pytest.mark.parametrize("addr", ["93.184.216.34", "104.16.123.96", "2606:4700::6810:7b60", "1.1.1.1"])
def test_public_addresses_are_allowed(addr):
    assert P.is_public(addr)


@pytest.mark.parametrize("ips", [["127.0.0.1"], ["10.0.0.5", "192.168.0.2"], ["169.254.169.254"],
                                 ["::1", "fd12::3"], ["::ffff:127.0.0.1"], ["64:ff9b::7f00:1"]])
def test_a_name_resolving_only_to_private_addresses_is_never_contacted(ips):
    conn = router({443: 1, 80: 1})
    r = P.probe(HOST, acfg(), resolve=fake_resolver({HOST: ips}), connect=conn)
    assert conn.calls == []
    assert (r["state"], r["reason"], r["address"]) == ("unreachable", "non_public", None)


def test_only_the_public_address_of_a_mixed_answer_is_contacted():
    srv = Local(reply(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
    try:
        conn = router({443: ConnectionRefusedError(), 80: srv.port})
        r = P.probe(HOST, acfg(), resolve=fake_resolver({HOST: ["127.0.0.1", "10.0.0.1", PUBLIC_IP]}), connect=conn)
    finally:
        srv.close()
    assert {a for a, _ in conn.calls} == {PUBLIC_IP}
    assert r["state"] == "reachable"


@pytest.mark.parametrize("name", ["127.0.0.1", "10.0.0.1", "http://probe.test/", "probe.test:8080",
                                  "PROBE.TEST", "*.probe.test", "probe..test", "", "localhost"])
def test_anything_but_a_normalised_dns_name_is_not_checked(name):
    calls = []
    conn = router({})

    def resolve(*a, **k):
        calls.append(a)
        raise AssertionError("must not resolve")
    r = P.probe(name, acfg(), resolve=resolve, connect=conn)
    assert calls == [] and conn.calls == []
    assert (r["state"], r["reason"]) == ("unknown", "invalid_name")


def test_the_name_is_resolved_once_and_the_vetted_address_is_what_gets_connected():
    # DNS rebinding: a second lookup could answer 127.0.0.1. There is no second lookup.
    answers = iter([[PUBLIC_IP], ["127.0.0.1"], ["127.0.0.1"]])
    seen = []

    def resolve(host, port, type=None):
        ips = next(answers)
        seen.append(ips)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]
    srv = Local(reply(b"HTTP/1.1 200 OK\r\n\r\n"))
    try:
        conn = router({443: ConnectionRefusedError(), 80: srv.port})
        r = P.probe(HOST, acfg(), resolve=resolve, connect=conn)
    finally:
        srv.close()
    assert len(seen) == 1 and {a for a, _ in conn.calls} == {PUBLIC_IP}
    assert r["address"] == PUBLIC_IP and r["state"] == "reachable"


def test_the_checker_only_uses_its_own_vetted_connect():
    src = open(P.__file__, encoding="utf-8").read()
    assert "urlopen" not in src and "http.client" not in src and "HTTPSConnection" not in src
    # every connection goes through connect(addr, ...) with a vetted address
    assert src.count("socket.create_connection(") == 1


# -- DNS -----------------------------------------------------------------------------------
@pytest.mark.parametrize("code,state,reason", [
    (socket.EAI_NONAME, "unreachable", "nxdomain"),
    (socket.EAI_AGAIN, "unknown", "dns_failure"),            # resolver unavailable: no conclusion
    (socket.EAI_FAIL, "unknown", "dns_failure"),
])
def test_dns_outcomes(code, state, reason):
    conn = router({})
    r = P.probe(HOST, acfg(), resolve=fake_resolver({HOST: code}), connect=conn)
    assert (r["state"], r["reason"]) == (state, reason) and conn.calls == []


def test_name_without_addresses_is_unreachable():
    nodata = getattr(socket, "EAI_NODATA", None)
    if nodata is None:
        pytest.skip("platform has no EAI_NODATA")
    r = P.probe(HOST, acfg(), resolve=fake_resolver({HOST: nodata}), connect=router({}))
    assert (r["state"], r["reason"]) == ("unreachable", "no_address")


def test_a_hanging_resolver_is_a_timeout_not_unreachable():
    def slow(*a, **k):
        time.sleep(3)
        return []
    t0 = time.monotonic()
    r = P.probe(HOST, acfg(dns_timeout_s=0.5), resolve=slow, connect=router({}))
    assert time.monotonic() - t0 < 2
    assert (r["state"], r["reason"]) == ("timeout", "dns_timeout")


# -- TCP -----------------------------------------------------------------------------------
def test_connection_refused_on_both_ports_is_unreachable():
    conn = router({443: ConnectionRefusedError(), 80: ConnectionRefusedError()})
    r = P.probe(HOST, acfg(), resolve=RESOLVE, connect=conn)
    assert conn.calls == [(PUBLIC_IP, 443), (PUBLIC_IP, 80)]
    assert (r["state"], r["reason"], r["tcp"]) == ("unreachable", "refused", "refused")


def test_connect_timeout_is_timeout():
    conn = router({443: socket.timeout("timed out"), 80: ConnectionRefusedError()})
    r = P.probe(HOST, acfg(), resolve=RESOLVE, connect=conn)
    assert (r["state"], r["reason"]) == ("timeout", "tcp_timeout")


def test_no_route_from_the_checker_is_unknown_not_unreachable():
    err = OSError(101, "Network is unreachable")
    r = P.probe(HOST, acfg(), resolve=fake_resolver({HOST: ["2606:4700::1"]}),
                connect=router({443: err, 80: err}))
    assert (r["state"], r["reason"]) == ("unknown", "network_error")


# -- HTTP ----------------------------------------------------------------------------------
@pytest.mark.parametrize("status,state,reason", [
    (200, "reachable", "http_2xx"), (204, "reachable", "http_2xx"),
    (301, "reachable", "http_3xx"), (302, "reachable", "http_3xx"),
    (401, "reachable", "http_denied"), (403, "reachable", "http_denied"),
    (429, "reachable", "http_429"), (404, "reachable", "http_4xx"), (410, "reachable", "http_4xx"),
    (500, "server_error", "http_5xx"), (502, "server_error", "http_5xx"), (522, "server_error", "http_5xx"),
])
def test_http_status_classification(status, state, reason):
    r, srv, _ = plain(f"HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n".encode())
    assert (r["state"], r["reason"], r["http_status"], r["port"]) == (state, reason, status, 80)
    assert srv.accepted == 1


def test_redirect_is_recorded_and_never_followed():
    r, srv, conn = plain(b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/login?next=1\r\n"
                         b"Content-Length: 0\r\n\r\n")
    assert r["location"] == "https://elsewhere.example/login?next=1"
    assert r["state"] == "reachable" and srv.accepted == 1 and len(srv.requests) == 1
    assert conn.calls == [(PUBLIC_IP, 443), (PUBLIC_IP, 80)]        # nothing towards the Location


def test_the_request_is_one_plain_get_with_the_name_as_host():
    r, srv, _ = plain(b"HTTP/1.1 200 OK\r\n\r\n")
    req = srv.requests[0].decode()
    lines = req.split("\r\n")
    assert lines[0] == "GET / HTTP/1.1" and f"Host: {HOST}" in lines
    assert "Connection: close" in lines and "Cookie" not in req and "Authorization" not in req


def test_cloudflare_challenge_is_reachable_but_not_content():
    r, _, _ = plain(b"HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\nCF-RAY: 8c1f-SOF\r\n"
                    b"cf-mitigated: challenge\r\nContent-Length: 0\r\n\r\n")
    assert (r["state"], r["reason"], r["protection"], r["challenge"]) == ("reachable", "challenge", "cloudflare", 1)


def test_challenge_page_recognised_from_its_body():
    body = b"<html><head><title>Just a moment...</title></head><body>challenge-platform</body></html>"
    r, _, _ = plain(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
    assert (r["reason"], r["challenge"], r["protection"]) == ("challenge", 1, None)


def test_challenge_words_on_a_normal_page_are_not_a_challenge():
    body = b"<p>Just a moment... loading</p>"
    r, _, _ = plain(b"HTTP/1.1 200 OK\r\nServer: cloudflare\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
    assert (r["reason"], r["challenge"], r["protection"]) == ("http_2xx", 0, "cloudflare")


def test_cloudflare_origin_error_is_a_server_error_not_reachable():
    r, _, _ = plain(b"HTTP/1.1 522 Origin Connection Time-out\r\nServer: cloudflare\r\nContent-Length: 0\r\n\r\n")
    assert (r["state"], r["protection"]) == ("server_error", "cloudflare")


@pytest.mark.parametrize("raw,reason", [
    (b"this is not http\r\n\r\n", "http_malformed"),
    (b"SSH-2.0-OpenSSH_9.6\r\n", "http_malformed"),            # bytes, then close, no header end
    (b"HTTP/1.1 200 OK\r\nno-colon-here\r\n\r\n", "http_malformed"),
    (b"HTTP/9.9 200 OK\r\n\r\n", "http_malformed"),
    (b"", "no_response"),
])
def test_malformed_and_missing_responses(raw, reason):
    r, _, _ = plain(raw)
    assert r["reason"] == reason
    assert r["state"] == P.REASONS[reason][0] == ("dns_only")


def test_oversized_headers_are_cut_off():
    r, _, _ = plain(b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 40000 + b"\r\n\r\n", max_header_bytes=16384)
    assert r["reason"] == "http_malformed" and "headers over" in r["error"]


def test_oversized_body_is_read_only_up_to_the_cap():
    big = b"x" * (2 * 1024 * 1024)
    t0 = time.monotonic()
    r, _, _ = plain(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(big), big), max_body_bytes=16384)
    assert (r["reason"], r["truncated"], r["body_bytes"]) == ("http_2xx", 1, 16384)
    assert time.monotonic() - t0 < 3


def test_a_server_that_never_answers_is_a_timeout():
    def silent(c, srv):
        time.sleep(4)
    srv = Local(silent)
    try:
        t0 = time.monotonic()
        r = P.probe(HOST, acfg(response_timeout_s=0.8), resolve=RESOLVE,
                    connect=router({443: ConnectionRefusedError(), 80: srv.port}))
    finally:
        srv.close()
    assert (r["state"], r["reason"]) == ("timeout", "http_timeout")
    assert time.monotonic() - t0 < 2.5


def test_a_dripping_server_cannot_hold_the_checker():
    def drip(c, srv):
        read_head(c, srv)
        c.sendall(b"HTTP/1.1 200 OK\r\n")
        for _ in range(100):
            c.sendall(b"X")                   # one header byte every 0.2 s, forever
            time.sleep(0.2)
    srv = Local(drip)
    try:
        t0 = time.monotonic()
        r = P.probe(HOST, acfg(response_timeout_s=1.0, total_timeout_s=1.5), resolve=RESOLVE,
                    connect=router({443: ConnectionRefusedError(), 80: srv.port}))
    finally:
        srv.close()
    assert r["state"] == "timeout"
    assert time.monotonic() - t0 < 2.5


# -- TLS -----------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl not available to make a throwaway test certificate")
    d = tmp_path_factory.mktemp("tls")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "k.pem"),
                    "-out", str(d / "c.pem"), "-days", "2", "-subj", f"/CN={HOST}",
                    "-addext", f"subjectAltName=DNS:{HOST}"], check=True, capture_output=True)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(d / "c.pem", d / "k.pem")
    return server, ssl.create_default_context(cafile=str(d / "c.pem"))


def test_tls_ok_then_http(cert):
    server_ctx, trusting = cert
    srv = Local(reply(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), tls=server_ctx)
    try:
        conn = router({443: srv.port})
        r = P.probe(HOST, acfg(), resolve=RESOLVE, connect=conn, tls_context=trusting)
    finally:
        srv.close()
    assert (r["port"], r["tls"], r["http_status"], r["state"]) == (443, "ok", 200, "reachable")
    assert conn.calls == [(PUBLIC_IP, 443)]


def test_untrusted_certificate_is_a_tls_error(cert):
    server_ctx, _ = cert
    srv = Local(reply(b"HTTP/1.1 200 OK\r\n\r\n"), tls=server_ctx)
    try:
        r = P.probe(HOST, acfg(), resolve=RESOLVE, connect=router({443: srv.port}))   # system trust store
    finally:
        srv.close()
    assert (r["state"], r["reason"], r["tls"]) == ("tls_error", "tls_cert_invalid", "cert_invalid")
    assert srv.requests == []                   # no HTTP over an unverified channel


def test_certificate_for_another_name_is_a_tls_error(cert):
    server_ctx, trusting = cert
    srv = Local(reply(b"HTTP/1.1 200 OK\r\n\r\n"), tls=server_ctx)
    try:
        r = P.probe("other.test", acfg(), resolve=fake_resolver({"other.test": [PUBLIC_IP]}),
                    connect=router({443: srv.port}), tls_context=trusting)
    finally:
        srv.close()
    assert r["reason"] == "tls_cert_invalid"


def test_tls_handshake_failure():
    def garbage(c, srv):
        c.recv(4096)
        c.sendall(b"HTTP/1.1 400 this is not TLS\r\n\r\n")
    srv = Local(garbage)
    try:
        r = P.probe(HOST, acfg(), resolve=RESOLVE, connect=router({443: srv.port}))
    finally:
        srv.close()
    assert (r["state"], r["reason"]) == ("tls_error", "tls_failed")


def test_tls_handshake_that_never_finishes_is_a_timeout():
    def mute(c, srv):
        time.sleep(4)
    srv = Local(mute)
    try:
        t0 = time.monotonic()
        r = P.probe(HOST, acfg(tls_timeout_s=0.8), resolve=RESOLVE, connect=router({443: srv.port}))
    finally:
        srv.close()
    assert (r["state"], r["reason"]) == ("timeout", "tls_timeout")
    assert time.monotonic() - t0 < 2.5


# -- history and state --------------------------------------------------------------------
def test_summary_from_observations_only():
    h = [("2026-09-24T20:00:00+00:00", "reachable"), ("2026-09-25T14:00:00+00:00", "unreachable"),
         ("2026-09-25T20:00:00+00:00", "timeout"), ("2026-09-26T08:00:00+00:00", "reachable"),
         ("2026-09-26T14:00:00+00:00", "reachable")]
    s = AV.summarize(h)
    assert s == {"checks": 5, "reachable_checks": 3, "failed_checks": 2,
                 "first_checked": "2026-09-24T20:00:00+00:00", "last_checked": "2026-09-26T14:00:00+00:00",
                 "last_reachable": "2026-09-26T14:00:00+00:00",
                 "previous_reachable": "2026-09-26T08:00:00+00:00",
                 "last_state": "reachable", "state": "reachable"}


def test_a_missing_day_is_not_an_outage():
    # 25 Sep reachable, no check on 26 Sep, 27 Sep reachable: nothing says "down" on the 26th.
    s = AV.summarize([("2026-09-25T10:00:00+00:00", "reachable"), ("2026-09-27T10:00:00+00:00", "reachable")])
    assert (s["checks"], s["failed_checks"], s["state"]) == (2, 0, "reachable")
    assert (s["last_reachable"], s["previous_reachable"]) == ("2026-09-27T10:00:00+00:00", "2026-09-25T10:00:00+00:00")


@pytest.mark.parametrize("last,public", [
    ("reachable", "reachable"), ("unreachable", "unreachable"), ("timeout", "unknown"),
    ("tls_error", "unknown"), ("server_error", "unknown"), ("dns_only", "unknown"), ("unknown", "unknown"),
])
def test_current_state_follows_the_latest_check(last, public):
    s = AV.summarize([("2026-09-25T10:00:00+00:00", "reachable"), ("2026-09-26T10:00:00+00:00", last)])
    assert s["state"] == public
    assert s["last_reachable"] == ("2026-09-26T10:00:00+00:00" if last == "reachable" else "2026-09-25T10:00:00+00:00")


def test_never_checked_is_its_own_state():
    s = AV.summarize([])
    assert (s["state"], s["last_checked"], s["last_reachable"], s["checks"]) == ("unchecked", None, None, 0)


def _run(conn, cfg, names, table, srv_port=None, **kw):
    conn_fn = router({443: ConnectionRefusedError(), 80: srv_port or ConnectionRefusedError()})
    cfg["availability"].update(dns_timeout_s=2.0, connect_timeout_s=2.0, response_timeout_s=2.0, total_timeout_s=5.0)
    return AV.run(conn, cfg, names, resolve=fake_resolver(table), connect=conn_fn, log=lambda *_: None, **kw)


def test_runs_append_and_never_overwrite(conn, cfg):
    srv = Local(reply(b"HTTP/1.1 200 OK\r\n\r\n"))
    try:
        table = {"a.test": [PUBLIC_IP], "b.test": socket.EAI_NONAME}
        r1 = _run(conn, cfg, ["a.test", "b.test"], table, srv.port, force=True)
        r2 = _run(conn, cfg, ["a.test", "b.test"], {"a.test": socket.EAI_NONAME, "b.test": socket.EAI_NONAME},
                  srv.port, force=True)
    finally:
        srv.close()
    rows = conn.execute("SELECT run_id, domain, state, reason, source_id, checker FROM availability_observations"
                        " ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [
        (r1, "a.test", "reachable", "http_2xx", "availability", P.CHECKER),
        (r1, "b.test", "unreachable", "nxdomain", "availability", P.CHECKER),
        (r2, "a.test", "unreachable", "nxdomain", "availability", P.CHECKER),
        (r2, "b.test", "unreachable", "nxdomain", "availability", P.CHECKER)]
    s = AV.summarize(AV.histories(conn, ["a.test"])["a.test"])
    assert (s["state"], s["checks"], s["reachable_checks"]) == ("unreachable", 2, 1)
    assert s["last_reachable"] == conn.execute("SELECT checked_at FROM availability_observations WHERE id=1").fetchone()[0]
    run = conn.execute("SELECT status, queries_ok, queries_empty FROM collection_runs WHERE id=?", (r1,)).fetchone()
    assert tuple(run) == ("complete", 1, 1)


def test_a_run_where_the_checker_had_no_dns_is_ignored_by_summaries(conn, cfg):
    names = ["a.test", "b.test", "c.test"]
    _run(conn, cfg, names, {n: socket.EAI_NONAME for n in names}, force=True)
    rid = _run(conn, cfg, names, {n: socket.EAI_AGAIN for n in names}, force=True)   # resolver down
    assert conn.execute("SELECT status FROM collection_runs WHERE id=?", (rid,)).fetchone()[0] == "failed"
    assert conn.execute("SELECT COUNT(*) FROM availability_observations WHERE run_id=?", (rid,)).fetchone()[0] == 3
    s = AV.summarize(AV.histories(conn, ["a.test"])["a.test"])
    assert (s["checks"], s["state"]) == (1, "unreachable")


def test_due_schedule(conn, cfg):
    names = ["new.test", "fresh.test", "old.test", "gone.test"]
    _run(conn, cfg, ["fresh.test", "old.test"], {}, force=True)
    for _ in range(3):
        _run(conn, cfg, ["gone.test"], {}, force=True)
    now = datetime.now(timezone.utc)
    assert AV.due(conn, cfg, names, now) == ["new.test"]
    later = now + timedelta(hours=cfg["availability"]["recheck_hours"] + 1)
    # gone.test failed 3 times in a row: it waits for the slower re-check
    assert AV.due(conn, cfg, names, later) == ["new.test", "fresh.test", "old.test"]
    much_later = now + timedelta(hours=cfg["availability"]["unreachable_recheck_hours"] + 1)
    assert set(AV.due(conn, cfg, names, much_later)) == set(names)
    cfg["availability"]["max_per_run"] = 2
    assert AV.due(conn, cfg, names, much_later) == ["new.test", "fresh.test"]


def test_availability_never_changes_detection_or_fingerprints(conn, cfg):
    from trawl.analysis import flagged_by_priority, run_analysis
    from trawl.collect import collect_crtsh, dnscheck
    from trawl.snapshot import cutoffs_now, dataset_sha256

    from .conftest import FakeCrtsh
    from .test_pipeline_snapshot import DATA, DNS
    quiet = {"log": lambda *_: None}
    collect_crtsh(conn, cfg, client=FakeCrtsh(DATA), keywords=["bgpost", "econt", "tollpass"], **quiet)
    dnscheck(conn, cfg, flagged_by_priority(conn, cfg), resolve=fake_resolver(DNS), **quiet)
    a1 = run_analysis(conn, cfg, as_of="2026-09-26T00:00:00+00:00", **quiet)
    before = dataset_sha256(conn, cutoffs_now(conn))[0]
    names = AV.registry_names(conn)
    assert names
    _run(conn, cfg, names, {n: socket.EAI_NONAME for n in names}, force=True)
    sha, counts = dataset_sha256(conn, cutoffs_now(conn))
    assert sha == before and counts["source"] == 2        # the probe's source row is not in the dataset
    a2 = run_analysis(conn, cfg, as_of="2026-09-26T00:00:00+00:00", **quiet)
    r = conn.execute("SELECT results_sha256, domains_flagged FROM analysis_runs WHERE id IN (?, ?) ORDER BY id",
                     (a1, a2)).fetchall()
    assert tuple(r[0]) == tuple(r[1])


def test_run_budget_skips_instead_of_guessing(conn, cfg):
    cfg["availability"]["max_run_minutes"] = 0.0
    rid = _run(conn, cfg, ["a.test", "b.test"], {}, force=True)
    row = conn.execute("SELECT status, queries_skipped FROM collection_runs WHERE id=?", (rid,)).fetchone()
    assert tuple(row) == ("failed", 2)
    assert conn.execute("SELECT COUNT(*) FROM availability_observations").fetchone()[0] == 0


# -- scheduling: which registry names are due --------------------------------------------
T0 = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)


def _obs(conn, name, state, at, run_status="complete"):
    """One observation at an exact time (test database only)."""
    rid = conn.execute("INSERT INTO collection_runs(source_id, started_at, finished_at, status,"
                       " software_version, config_json) VALUES ('availability', ?, ?, ?, 'test', '{}')",
                       (at.isoformat(), at.isoformat(), run_status)).lastrowid
    reason = {"reachable": "http_2xx", "unreachable": "nxdomain", "timeout": "tcp_timeout",
              "tls_error": "tls_failed", "unknown": "dns_failure"}[state]
    conn.execute("INSERT INTO availability_observations(run_id, source_id, checker, domain, checked_at,"
                 " duration_ms, dns, addresses, state, reason) VALUES (?, 'availability', 'test', ?, ?, 1,"
                 " 'resolved', '[]', ?, ?)", (rid, name, at.isoformat(timespec="seconds"), state, reason))
    conn.commit()


def _hours(h):
    return T0 + timedelta(hours=h)


def test_a_name_is_due_only_after_recheck_hours(conn, cfg):
    _obs(conn, "a.test", "reachable", T0)
    wait = cfg["availability"]["recheck_hours"]
    assert AV.due(conn, cfg, ["a.test"], _hours(wait - 0.1)) == []          # not yet due: skipped
    assert AV.due(conn, cfg, ["a.test"], _hours(wait)) == ["a.test"]        # due


def test_new_names_come_first_then_the_longest_unchecked(conn, cfg):
    _obs(conn, "old.test", "reachable", _hours(-30))
    _obs(conn, "older.test", "reachable", _hours(-40))
    _obs(conn, "recent.test", "reachable", _hours(-1))
    assert AV.due(conn, cfg, ["recent.test", "old.test", "new.test", "older.test"], T0) == \
        ["new.test", "older.test", "old.test"]


def test_repeatedly_unreachable_moves_to_the_slow_schedule_and_back_when_reachable(conn, cfg):
    a = cfg["availability"]
    fast, slow, k = a["recheck_hours"], a["unreachable_recheck_hours"], a["unreachable_after"]
    for i in range(k - 1):
        _obs(conn, "x.test", "unreachable", _hours(i * fast))
    last = (k - 2) * fast
    assert AV.due(conn, cfg, ["x.test"], _hours(last + fast)) == ["x.test"]      # k-1 misses: still daily
    _obs(conn, "x.test", "unreachable", _hours(last + fast))                     # k-th miss in a row
    last += fast
    assert AV.due(conn, cfg, ["x.test"], _hours(last + fast)) == []              # slow tier now
    assert AV.due(conn, cfg, ["x.test"], _hours(last + slow)) == ["x.test"]
    _obs(conn, "x.test", "reachable", _hours(last + slow))                       # it answers again
    last += slow
    assert AV.due(conn, cfg, ["x.test"], _hours(last + fast)) == ["x.test"]      # back to daily


def test_only_unreachable_results_count_toward_the_slow_tier(conn, cfg):
    # timeouts, TLS errors and undetermined answers are not evidence that a site is gone
    for i, st in enumerate(["timeout", "tls_error", "unknown", "timeout"]):
        _obs(conn, "t.test", st, _hours(i * 24))
    assert AV.due(conn, cfg, ["t.test"], _hours(3 * 24 + cfg["availability"]["recheck_hours"])) == ["t.test"]


def test_a_checker_outage_does_not_move_names_to_the_slow_tier(conn, cfg):
    _obs(conn, "o.test", "unreachable", _hours(0))
    _obs(conn, "o.test", "unreachable", _hours(24))
    _obs(conn, "o.test", "unknown", _hours(48), run_status="failed")   # the checker's DNS was down
    # the failed run is ignored: two misses, not three, and the last informative check was at +24 h
    assert AV.due(conn, cfg, ["o.test"], _hours(24 + cfg["availability"]["recheck_hours"])) == ["o.test"]
    assert AV.summarize(AV.histories(conn, ["o.test"])["o.test"])["checks"] == 2


def test_a_forced_run_ignores_the_schedule_but_respects_max_per_run(conn, cfg):
    for n in ("a.test", "b.test", "c.test"):
        _obs(conn, n, "reachable", T0)
    cfg["availability"]["max_per_run"] = 2
    assert AV.due(conn, cfg, ["a.test", "b.test", "c.test"], _hours(1)) == []
    rid = _run(conn, cfg, ["a.test", "b.test", "c.test"], {}, force=True)
    assert conn.execute("SELECT COUNT(*) FROM availability_observations WHERE run_id=?", (rid,)).fetchone()[0] == 2


def test_snapshot_manifest_lists_only_the_runs_in_its_dataset(conn, cfg, tmp_path):
    import json

    from trawl.analysis import run_analysis
    from trawl.collect import collect_crtsh
    from trawl.snapshot import export

    from .conftest import FakeCrtsh
    from .test_pipeline_snapshot import DATA
    quiet = {"log": lambda *_: None}
    collect_crtsh(conn, cfg, client=FakeCrtsh(DATA), keywords=["bgpost", "econt", "tollpass"], **quiet)
    _run(conn, cfg, ["a.test"], {}, force=True)
    aid = run_analysis(conn, cfg, as_of="2026-09-26T00:00:00+00:00", **quiet)
    man = json.loads(export(conn, aid, tmp_path).read_text())
    assert {r["source_id"] for r in man["collection_runs"]} == {"crtsh"}


def test_cli_writes_private_files_whatever_the_umask(tmp_path):
    import os

    from trawl.cli import main
    old = os.umask(0o022)
    try:
        assert main(["--db", str(tmp_path / "u.db"), "dnscheck"]) == 0
    finally:
        os.umask(old)
    for f in ("u.db", "u.db.lock"):
        assert (tmp_path / f).stat().st_mode & 0o777 == 0o600, f
