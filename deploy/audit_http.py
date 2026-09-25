#!/usr/bin/env python3
"""External-facing HTTP audit of a running trawl instance. Standard library only.

    python3 deploy/audit_http.py http://127.0.0.1:8790
    python3 deploy/audit_http.py https://<name>.trycloudflare.com

Every check prints PASS/FAIL with evidence; exit status 1 if anything failed.
Only the given origin is contacted, with a handful of ordinary GET/HEAD/other requests.
"""
from __future__ import annotations

import http.client
import json
import ssl
import sys
from urllib.parse import urlsplit

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8790"
U = urlsplit(BASE)
results = []


def conn():
    if U.scheme == "https":
        return http.client.HTTPSConnection(U.hostname, U.port or 443, timeout=30,
                                           context=ssl.create_default_context())
    return http.client.HTTPConnection(U.hostname, U.port or 80, timeout=30)


def req(method, path, body=None, headers=None):
    c = conn()
    c.putrequest(method, path, skip_accept_encoding=True)
    for k, v in (headers or {}).items():
        c.putheader(k, v)
    if body is not None:
        c.putheader("Content-Length", str(len(body)))
    c.endheaders(body)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r, data


def check(name, ok, evidence=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{evidence}]" if evidence else ""))


r, body = req("GET", "/")
check("index served", r.status == 200, r.status)
csp = r.getheader("Content-Security-Policy") or ""
check("CSP default-src 'none', no unsafe-*", "default-src 'none'" in csp and "unsafe" not in csp, csp[:60])
for h, v in (("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
             ("Referrer-Policy", "no-referrer")):
    check(f"header {h}", r.getheader(h) == v, r.getheader(h))
server = r.getheader("Server") or ""
check("no software version disclosed in Server header", "Python" not in server and "/" not in server, server)
check("no CORS allow-origin", r.getheader("Access-Control-Allow-Origin") is None)
check("page references no third-party origins",
      b"http://" not in body.replace(b"http://www.w3.org", b"") and b"https://" not in body)

r, js = req("GET", "/app.js")
check("app.js has no innerHTML/eval", b"innerHTML =" not in js and b"eval(" not in js, len(js))

for path in ("/../trawl.db", "/%2e%2e/%2e%2e/etc/passwd", "/.env", "/.git/config", "/trawl.db",
             "/data/trawl.db", "/deploy/deck.json", "/trawl/db.py", "/web/", "/api/", "//etc/passwd",
             "/api/../app.js", "/server-status", "/debug", "/admin"):
    r, b = req("GET", path)
    check(f"no exposure: {path}", r.status == 404 and b"root:" not in b and b"CREATE TABLE" not in b,
          r.status)

for m in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"):
    r, _ = req(m, "/api/meta", body=b"x=1")
    check(f"method {m} refused", r.status == 405, r.status)

for path, want in (("/api/domains?verdict=likely;DROP%20TABLE%20domains", 400),
                   ("/api/domains?sort=name;--", 400), ("/api/domains?limit=100000", 400),
                   ("/api/domain?name=%3Cscript%3Ealert(1)%3C/script%3E", 400),
                   ("/api/campaign?id=C-'or'1'='1", 400), ("/api/runs?source=file", 400)):
    r, b = req("GET", path)
    ok = r.status == want and b"Traceback" not in b and b"sqlite" not in b.lower()
    check(f"validated: {path[:48]}", ok, f"{r.status} {b[:60]!r}")

r, b = req("GET", "/api/domains?q=" + "a" * 3000)
check("oversized request line refused", r.status in (414, 400, 431), r.status)

r, b = req("GET", "/api/meta")
if r.status == 200:
    meta = json.loads(b)
    check("provenance exposed with dataset fingerprint", len(meta["provenance"]["dataset_sha256"]) == 64)
else:
    check("meta endpoint answers (analysis present)", False, r.status)

print(f"\n{sum(results)}/{len(results)} checks passed against {BASE}")
sys.exit(0 if all(results) else 1)
