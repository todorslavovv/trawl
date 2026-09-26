"""Availability probe: did a registry domain's infrastructure respond when trawl checked?

One check per domain:  DNS -> TCP -> TLS -> one HTTP GET / -> classification.

It answers "did something answer at this name's public address at time T", never
"is the phishing page there": nothing is rendered, executed, followed or stored beyond
the status line, three headers and whether a bot-protection challenge was served.
Challenges are recorded, never solved or bypassed.

Safety rules, each enforced here and covered by tests:
  * the name is re-validated as a DNS name (never an IP literal, URL or port);
  * it is resolved ONCE and only globally routable addresses are kept - loopback,
    RFC 1918, CGNAT, link-local (incl. 169.254.169.254 metadata), multicast, reserved,
    IPv6 ULA / link-local and every IPv4-in-IPv6 form (mapped, NAT64, 6to4, Teredo)
    are refused. The connection goes to that vetted address, so there is no second
    lookup a rebinding answer could exploit;
  * redirects are recorded (Location, truncated), never followed;
  * TLS is verified against the system trust store, SNI = the name;
  * every phase has a timeout and the whole check a hard deadline, enforced on each
    socket wait (non-blocking I/O + poll), so a server dripping bytes cannot hold a
    worker; at most max_header_bytes of headers and max_body_bytes of body are read,
    and the body is only scanned for challenge markers, then discarded.
"""
from __future__ import annotations

import concurrent.futures as cf
import errno
import ipaddress
import re
import select
import socket
import ssl
import threading
import time
from datetime import datetime, timezone

from .. import names
from . import dns

CHECKER = "probe/1"
USER_AGENT = "Mozilla/5.0 (compatible; trawl-availability/1; research)"

SOURCE = {
    "id": "availability",
    "name": "Availability probe (DNS, TCP, TLS, HTTP)",
    "kind": "availability",
    "endpoint": "each registry domain's own public address: TCP 443 with TLS, else TCP 80",
    "description": (
        "Checks whether the infrastructure behind each domain in the public registry "
        "responds: DNS lookup, TCP connection, TLS handshake and one HTTP request for "
        "'/'. Each check is appended; history is never overwritten. A response proves "
        "that something answered, not that phishing content was served."),
    "provenance": (
        "Each observation stores the check time, checker version, duration, the DNS "
        "result, the address and port contacted, the TCP, TLS and HTTP results, the "
        "HTTP status, any redirect target (not followed), detected bot protection and "
        "the classification with its reason. The domain's operator sees the checker's "
        "IP address and User-Agent."),
}

# reason code -> (state, English explanation). The UI translates by code.
REASONS = {
    "http_2xx": ("reachable", "The server answered with HTTP {status}."),
    "http_3xx": ("reachable", "The server answered with a redirect (HTTP {status}); it was recorded, not followed."),
    "http_denied": ("reachable", "The server answered but refused access (HTTP {status})."),
    "http_429": ("reachable", "The server answered but rate-limited the check (HTTP 429)."),
    "http_4xx": ("reachable", "The server answered with HTTP {status}; the page itself was not confirmed."),
    "challenge": ("reachable", "A bot-protection challenge answered (HTTP {status}); the page behind it was not seen."),
    "http_5xx": ("server_error", "A server answered with an error (HTTP {status}); the site behind it may be down."),
    "http_other": ("unknown", "The server answered with an unexpected HTTP {status}."),
    "http_malformed": ("dns_only", "Something accepted the connection but did not answer with valid HTTP."),
    "no_response": ("dns_only", "The connection was accepted and closed without an HTTP answer."),
    "http_timeout": ("timeout", "The connection was accepted but no HTTP answer arrived in time."),
    "tls_cert_invalid": ("tls_error", "TLS answered with a certificate that is not valid for this name."),
    "tls_failed": ("tls_error", "The TLS handshake failed."),
    "tls_timeout": ("timeout", "The TLS handshake did not finish in time."),
    "refused": ("unreachable", "The address refused connections on ports 443 and 80."),
    "tcp_timeout": ("timeout", "No TCP connection could be made in time."),
    "network_error": ("unknown", "The checker could not reach the address (network error on the checker's path)."),
    "nxdomain": ("unreachable", "The name does not exist in DNS (NXDOMAIN)."),
    "no_address": ("unreachable", "The name exists but has no IPv4 or IPv6 address."),
    "non_public": ("unreachable", "The name resolves only to non-public addresses (e.g. a sinkhole); they were not contacted."),
    "dns_failure": ("unknown", "The DNS lookup failed; nothing can be concluded."),
    "dns_timeout": ("timeout", "The DNS lookup did not answer in time."),
    "invalid_name": ("unknown", "Not a valid DNS name; not checked."),
    "deadline": ("timeout", "The check exceeded its overall time limit."),
    "error": ("unknown", "The check failed unexpectedly; nothing can be concluded."),
}
STATES = ("reachable", "dns_only", "unreachable", "timeout", "tls_error", "server_error", "unknown")
# What a visitor sees. Only a response proves reachability, only DNS non-existence,
# a sinkhole or refused connections count as unreachable; everything else is unknown.
PUBLIC = {"reachable": "reachable", "unreachable": "unreachable"}


def public_state(state: str | None) -> str:
    return "unchecked" if state is None else PUBLIC.get(state, "unknown")


_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def is_public(addr: str) -> bool:
    """True only for a globally routable unicast address that embeds no IPv4."""
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and (ip.ipv4_mapped or ip.sixtofour or ip.teredo
                            or any(ip in n for n in _NAT64)):
        return False
    return (ip.is_global and not ip.is_multicast and not ip.is_reserved
            and not ip.is_loopback and not ip.is_link_local and not ip.is_unspecified)


class _Deadline(Exception):
    pass


def _wait(sock, want_write: bool, deadline: float, clock):
    left = deadline - clock()
    if left <= 0:
        raise _Deadline()
    poller = select.poll()                  # poll, not select: no FD_SETSIZE ceiling
    poller.register(sock, select.POLLOUT if want_write else select.POLLIN)
    if not poller.poll(left * 1000):
        raise _Deadline()


def _send_all(sock, data: bytes, deadline: float, clock):
    view = memoryview(data)
    while view:
        try:
            view = view[sock.send(view):]
        except (ssl.SSLWantWriteError, BlockingIOError):
            _wait(sock, True, deadline, clock)
        except ssl.SSLWantReadError:
            _wait(sock, False, deadline, clock)


def _recv(sock, n: int, deadline: float, clock) -> bytes:
    while True:
        try:
            return sock.recv(n)
        except (ssl.SSLWantReadError, BlockingIOError):
            _wait(sock, False, deadline, clock)
        except ssl.SSLWantWriteError:
            _wait(sock, True, deadline, clock)


def _resolve(host: str, timeout: float, resolve) -> tuple[str, list[str], str | None]:
    box: list = []
    th = threading.Thread(target=lambda: box.append(dns.classify(host, resolve)), daemon=True)
    th.start()
    th.join(timeout)          # getaddrinfo has no timeout; a stuck lookup is abandoned
    return box[0] if box else ("timeout", [], f"no answer within {timeout:.0f} s")


def _tcp_error(e: OSError) -> str:
    if isinstance(e, ConnectionRefusedError):
        return "refused"
    if isinstance(e, (TimeoutError, socket.timeout)):
        return "timeout"
    if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT):
        return "unreachable"
    return "error"


def _connect(addr: str, port: int, timeout: float):
    return socket.create_connection((addr, port), timeout=timeout)


_STATUS = re.compile(rb"HTTP/1\.[01] (\d{3})(?: [^\r\n]*)?")
_CHALLENGE_MARKERS = (b"challenge-platform", b"cf-chl", b"cf_chl", b"just a moment...",
                      b"checking your browser", b"ddos-guard")


def _protection(headers: dict) -> str | None:
    server = headers.get("server", "").lower()
    if server == "cloudflare" or "cf-ray" in headers:
        return "cloudflare"
    if server.startswith("ddos-guard"):
        return "ddos-guard"
    if server.startswith("sucuri") or "x-sucuri-id" in headers:
        return "sucuri"
    if server.startswith("akamaighost"):
        return "akamai"
    return None


def _http(sock, host: str, deadline: float, clock, cfg: dict, r: dict):
    req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
           "Accept: text/html,*/*;q=0.5\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
    http_deadline = min(deadline, clock() + cfg["response_timeout_s"])
    _send_all(sock, req.encode("ascii"), http_deadline, clock)
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > cfg["max_header_bytes"]:
            r["http"] = "malformed"
            r["error"] = f"response headers over {cfg['max_header_bytes']} bytes"
            return
        chunk = _recv(sock, 4096, http_deadline, clock)
        if not chunk:
            r["http"] = "no_response" if not buf else "malformed"
            return
        buf += chunk
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    m = _STATUS.fullmatch(lines[0])
    if not m:
        r["http"] = "malformed"
        r["error"] = "invalid status line"
        return
    headers = {}
    for ln in lines[1:]:
        k, sep, v = ln.partition(b":")
        if not sep or not k.strip():
            r["http"] = "malformed"
            r["error"] = "invalid header line"
            return
        headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    r["http"] = "ok"
    r["http_status"] = int(m.group(1))
    r["location"] = headers.get("location", "")[:300] or None
    r["server"] = headers.get("server", "")[:80] or None
    r["protection"] = _protection(headers)
    # Body: only enough to recognise a challenge page, never kept, never parsed.
    cap = cfg["max_body_bytes"]
    body_deadline = min(deadline, clock() + cfg["response_timeout_s"])
    try:
        while len(body) <= cap:
            chunk = _recv(sock, 4096, body_deadline, clock)
            if not chunk:
                break
            body += chunk
    except (_Deadline, OSError):
        pass                                   # the status line already answered
    r["truncated"] = int(len(body) > cap)
    r["body_bytes"] = min(len(body), cap)
    sample = body[:cap].lower()
    r["challenge"] = int(headers.get("cf-mitigated", "").lower() == "challenge"
                         or (r["http_status"] in (403, 429, 503)
                             and any(mk in sample for mk in _CHALLENGE_MARKERS)))


def classify(r: dict) -> str:
    """Reason code for one check; the state is REASONS[code][0]. Pure function."""
    if r.get("reason") in ("deadline", "error"):
        return r["reason"]
    d = r.get("dns")
    if d is None:
        return "invalid_name"
    if d in ("nxdomain", "no_address"):
        return d
    if d == "timeout":
        return "dns_timeout"
    if d != "resolved":
        return "dns_failure"
    if not r.get("address"):
        if r.get("tcp") is None:
            return "non_public"
        return {"refused": "refused", "timeout": "tcp_timeout"}.get(r["tcp"], "network_error")
    if r.get("tls") == "timeout":
        return "tls_timeout"
    if r.get("tls") == "cert_invalid":
        return "tls_cert_invalid"
    if r.get("tls") == "failed":
        return "tls_failed"
    h = r.get("http")
    if h == "timeout":
        return "http_timeout"
    if h == "no_response":
        return "no_response"
    if h != "ok":
        return "http_malformed"
    s = r["http_status"]
    if r.get("challenge"):
        return "challenge"
    if 200 <= s < 300:
        return "http_2xx"
    if 300 <= s < 400:
        return "http_3xx"
    if s in (401, 403, 407):
        return "http_denied"
    if s == 429:
        return "http_429"
    if 400 <= s < 500:
        return "http_4xx"
    if 500 <= s < 600:
        return "http_5xx"
    return "http_other"


def probe(host: str, cfg: dict, *, resolve=socket.getaddrinfo, connect=_connect,
          tls_context: ssl.SSLContext | None = None, clock=time.monotonic) -> dict:
    """Check one name. Never raises; every path ends in a classified result."""
    t0 = clock()
    deadline = t0 + cfg["total_timeout_s"]
    r = {"domain": host, "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "dns": None, "addresses": [], "address": None, "port": None, "tcp": None,
         "tls": None, "http": None, "http_status": None, "location": None, "server": None,
         "protection": None, "challenge": 0, "body_bytes": None, "truncated": 0, "error": None}
    sock = None
    try:
        norm = names.normalise(host)
        if norm is None or norm != (host, False):
            r["error"] = "not a DNS name"
            return _finish(r, t0, clock)
        r["dns"], r["addresses"], err = _resolve(host, min(cfg["dns_timeout_s"], deadline - clock()), resolve)
        r["error"] = err
        public = [a for a in r["addresses"] if is_public(a)]
        if r["dns"] != "resolved" or not public:
            return _finish(r, t0, clock)
        # IPv4 first (the common case and the checker's most reliable path).
        cands = sorted(public, key=lambda a: (":" in a, a))[: cfg["max_addresses"]]
        outcomes = []
        for port in (443, 80):
            for addr in cands:
                left = deadline - clock()
                if left <= 0:
                    raise _Deadline()
                try:
                    sock = connect(addr, port, min(cfg["connect_timeout_s"], left))
                    r["address"], r["port"], r["tcp"] = addr, port, "ok"
                    break
                except OSError as e:
                    outcomes.append(_tcp_error(e))
            if sock is not None:
                break
        if sock is None:
            r["tcp"] = ("refused" if outcomes and all(o == "refused" for o in outcomes)
                        else "timeout" if "timeout" in outcomes else
                        "unreachable" if "unreachable" in outcomes else "error")
            return _finish(r, t0, clock)
        sock.setblocking(False)
        if r["port"] == 443:
            ctx = tls_context or ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False)
            tls_deadline = min(deadline, clock() + cfg["tls_timeout_s"])
            try:
                while True:
                    try:
                        sock.do_handshake()
                        break
                    except ssl.SSLWantReadError:
                        _wait(sock, False, tls_deadline, clock)
                    except ssl.SSLWantWriteError:
                        _wait(sock, True, tls_deadline, clock)
            except _Deadline:
                r["tls"] = "timeout"
                return _finish(r, t0, clock)
            except ssl.SSLCertVerificationError as e:
                r["tls"], r["error"] = "cert_invalid", str(e.verify_message or e)[:160]
                return _finish(r, t0, clock)
            except (ssl.SSLError, OSError) as e:
                r["tls"], r["error"] = "failed", str(e)[:160]
                return _finish(r, t0, clock)
            r["tls"] = "ok"
        try:
            _http(sock, host, deadline, clock, cfg, r)
        except _Deadline:
            r["http"] = "timeout"
        except OSError as e:
            r["http"], r["error"] = "no_response", str(e)[:160]
        return _finish(r, t0, clock)
    except _Deadline:
        r["reason"] = "deadline"
        return _finish(r, t0, clock)
    except Exception as e:                      # never let one hostile answer stop a run
        r["reason"], r["error"] = "error", f"{type(e).__name__}: {str(e)[:120]}"
        return _finish(r, t0, clock)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _finish(r: dict, t0: float, clock) -> dict:
    r["reason"] = classify(r)
    r["state"] = REASONS[r["reason"]][0]
    r["duration_ms"] = int((clock() - t0) * 1000)
    return r


def check_many(hosts: list[str], cfg: dict, *, run_deadline: float | None = None, **kw) -> dict:
    """Probe hosts concurrently (cfg['workers']). Hosts not started before
    run_deadline (time.monotonic) are returned as None = skipped, not checked."""
    def one(h):
        if run_deadline is not None and time.monotonic() > run_deadline:
            return None
        return probe(h, cfg, **kw)
    out: dict = {}
    pool = cf.ThreadPoolExecutor(max_workers=max(1, cfg["workers"]))
    try:
        futs = {h: pool.submit(one, h) for h in hosts}
        for h, fut in futs.items():
            try:
                out[h] = fut.result(timeout=cfg["total_timeout_s"] + cfg["dns_timeout_s"]
                                    + (max(0.0, run_deadline - time.monotonic()) if run_deadline else 600))
            except cf.TimeoutError:
                out[h] = None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return out
