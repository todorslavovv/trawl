"""The crt.sh client must classify every failure, never report it as 'no results',
retry with backoff, pace requests, and only ever contact crt.sh."""
import io
import json
import socket
import urllib.error

from trawl.sources.crtsh import BASE_URL, Client


class Resp(io.BytesIO):
    def __init__(self, body: bytes, status=200):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def client(script, **kw):
    """script: list of callables/values returned per attempt."""
    calls, sleeps = [], []
    it = iter(script)

    def opener(url, timeout):
        calls.append(url)
        v = next(it)
        if isinstance(v, BaseException):
            raise v
        return v
    t = [0.0]

    def clock():
        return t[0]

    def sleep(s):
        sleeps.append(s)
        t[0] += s
    c = Client(timeout_s=5, max_attempts=kw.get("attempts", 3), backoff_base_s=2, backoff_max_s=60,
               pace_s=kw.get("pace", 3), max_bytes=kw.get("max_bytes", 10_000), opener=opener,
               sleep=sleep, clock=clock)
    return c, calls, sleeps


def http_error(code, retry_after=None):
    hdrs = {"Retry-After": str(retry_after)} if retry_after else {}
    return urllib.error.HTTPError(BASE_URL, code, "err", hdrs, None)


def test_ok_and_ok_empty_are_distinct():
    c, calls, _ = client([Resp(json.dumps([{"id": 1, "name_value": "a.top"}]).encode())])
    r = c.search("econt%")
    assert r.outcome == "ok" and len(r.records) == 1 and r.response_sha256 and r.bytes
    c, _, _ = client([Resp(b"[]")])
    assert c.search("econt%").outcome == "ok_empty"


def test_only_crtsh_is_contacted_and_pattern_is_encoded():
    from urllib.parse import parse_qs, urlsplit
    c, calls, _ = client([Resp(b"[]")])
    evil = "%econt%&output=html&x=http://evil.example/"
    c.search(evil)
    u = urlsplit(calls[0])
    assert (u.scheme, u.netloc, u.path) == ("https", "crt.sh", "/")
    assert parse_qs(u.query) == {"q": [evil], "output": ["json"]}   # injected & stays inside q


def test_timeout_after_retries_is_timeout_not_empty():
    c, calls, sleeps = client([TimeoutError(), TimeoutError(), socket.timeout()])
    r = c.search("econt%")
    assert r.outcome == "timeout" and r.attempts == 3 and r.records == []
    assert len(calls) == 3 and sum(1 for s in sleeps if s >= 1.5) >= 2   # backoff between tries


def test_5xx_then_success_is_retried():
    c, calls, _ = client([http_error(502), http_error(503), Resp(b'[{"id":2,"name_value":"x.cfd"}]')])
    r = c.search("econt%")
    assert r.outcome == "ok" and r.attempts == 3


def test_404_is_retried_because_crtsh_emits_spurious_404s():
    # REGRESSION (live run 2026-09-26): boxnow% answered 404, then 200 minutes later.
    c, calls, _ = client([http_error(404), Resp(b"[]")])
    assert c.search("boxnow%").outcome == "ok_empty" and len(calls) == 2


def test_400_is_not_retried():
    c, calls, _ = client([http_error(400), Resp(b"[]")])
    r = c.search("econt%")
    assert r.outcome == "http_error" and r.http_status == 400 and len(calls) == 1


def test_retry_after_is_honoured_and_capped():
    c, _, sleeps = client([http_error(429, retry_after=30), Resp(b"[]")])
    c.search("econt%")
    assert 30 in sleeps
    c, _, sleeps = client([http_error(429, retry_after=9999), Resp(b"[]")])
    c.search("econt%")
    assert 60 in sleeps                                   # capped at backoff_max_s


def test_html_error_page_with_200_is_parse_error():
    c, _, _ = client([Resp(b"<html>502 Bad Gateway</html>")] * 3)
    r = c.search("econt%")
    assert r.outcome == "parse_error" and r.records == []


def test_empty_body_is_not_an_empty_list():
    c, _, _ = client([Resp(b"")] * 3)
    assert c.search("econt%").outcome == "parse_error"


def test_json_object_is_not_a_list():
    c, _, _ = client([Resp(b'{"error":"x"}')] * 3)
    assert c.search("econt%").outcome == "parse_error"


def test_oversized_body_is_refused_without_retry():
    c, calls, _ = client([Resp(b"[" + b" " * 20_000 + b"]")], max_bytes=1000)
    r = c.search("econt%")
    assert r.outcome == "too_large" and len(calls) == 1 and r.records == []


def test_network_error_classified():
    c, _, _ = client([urllib.error.URLError(ConnectionRefusedError())] * 3)
    assert c.search("econt%").outcome == "network_error"


def test_requests_are_paced():
    c, _, sleeps = client([Resp(b"[]"), Resp(b"[]")], pace=6)
    c.search("a%")
    c.search("b%")
    assert any(abs(s - 6) < 1e-9 for s in sleeps)


def test_redirects_are_never_followed():
    from trawl.sources.crtsh import _OPENER, _NoRedirect
    assert any(isinstance(h, _NoRedirect) for h in _OPENER.handlers)
    assert _NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.example/") is None


def test_tls_verification_is_on():
    import ssl
    from trawl.sources.crtsh import _OPENER
    https = next(h for h in _OPENER.handlers if isinstance(h, __import__("urllib.request").request.HTTPSHandler))
    ctx = https._context
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
