# Security

An investigative tool must not become an attack surface, must not be usable against
its own network, and must touch the infrastructure it watches as little as possible. This document is the threat model, the
controls, and the audit that was actually performed.

## Threat model

| Asset / concern | Threat | Control |
|---|---|---|
| Web UI / API | injection, XSS, traversal, request smuggling, info leak, DoS | read-only server, strict routing, validated params, CSP, fixed error bodies, connection handling (below) |
| Database | tampering, disclosure | web process opens it read-only; files mode 600 in a 700 directory; never served; tamper-evident fingerprints |
| Collector | SSRF, redirect abuse, MITM, hostile data | one hard-coded HTTPS origin, TLS verified, redirects refused, JSON parsed as data, names validated |
| Suspect infrastructure | the tool acting as a visitor of it | raw certificate names are never contacted; registry domains get one availability check a day (one `GET /`, nothing rendered, no redirects followed, no bot protection bypassed); a visitor's search never triggers a check |
| Availability probe | SSRF towards loopback, private networks, the tailnet or cloud metadata; DNS rebinding; redirect abuse; hostile answers (huge, slow, malformed) | only globally routable addresses, one resolution, connect to the vetted address, redirects never followed, verified TLS, bounded reads and a hard deadline per check ([AVAILABILITY](AVAILABILITY.md)) |
| Host (Steam Deck) | the app as a foothold | loopback binding, systemd sandboxing, no subprocesses, no secrets, no new listening ports beyond 127.0.0.1:8790 (+ cloudflared's own loopback metrics port) |
| Reviewer trust | claims that are not true | docs checked against code by tests; the beta page's false "makes no requests" claim is not repeated; CSP enforces what the docs say |

## Controls

**Web server (`trawl/server.py`).**
* Binds `127.0.0.1` by default; a warning is printed for any other host.
* GET/HEAD only; all other methods → 405. There is no write endpoint.
* Static assets: four files (`index.html`, `app.js`, `app.css`, `i18n.json`) loaded into
  memory at start-up and looked up by exact path. No URL is ever mapped to the filesystem: no traversal, no directory listing,
  no exposure of `.env`, `.git`, the database or source.
* Parameters: length-limited; integers range-checked; enums whitelisted; domain names
  validated by the same DNS-name parser as the collector; `parse_qs` field count
  capped; request line capped at 2048 bytes (414).
* SQL: parameterised everywhere. The only interpolated fragments are fixed strings
  chosen from whitelists (sort column, order). User text in `LIKE` has `%`, `_` and
  `\` escaped.
* Database opened with `mode=ro` and `PRAGMA query_only=ON`.
* Public lookup (`/api/lookup`): whatever the visitor typed is parsed to one hostname
  (a URL is reduced to its host; IP literals, other schemes and invalid names are 400)
  and looked up in the database. The web process has no network client code and opens
  no outbound connection (tested with the socket functions replaced by failures).
* Errors: fixed JSON bodies (`internal error`); tracebacks go to the service log only.
  Protocol errors (unparsable request line, unsupported HTTP version, oversize or too
  many headers) get a fixed `{"error":"bad request"}` over HTTP/1.0 with the security
  headers, and the connection is closed. The standard library's default would answer
  an unparsable request line HTTP/0.9-style: no headers, and an HTML page echoing the
  input.
* Headers on every response: `Content-Security-Policy: default-src 'none';
  script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self';
  font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
  no-referrer`, `Cross-Origin-Opener-Policy` and `-Resource-Policy: same-origin`,
  `Permissions-Policy`, `Cache-Control: no-store` (API). `Server: trawl` (no version).
  No CORS headers: other origins cannot read the API from a browser.
* Connections: requests carrying a body close the connection after the response, so
  unread bytes cannot be parsed as a second request (desync behind a reverse proxy);
  idle connections time out after 20 s.
* Access log: method, path without query string, status. No client addresses.

**Frontend (`trawl/web/`).** All data reaches the DOM via `textContent` or
`setAttribute` on fixed attribute names - no `innerHTML`, `eval`, inline script or
inline style attributes. The only URLs built from data are same-origin hash routes
(`encodeURIComponent`) and `https://crt.sh/?id=<integer>` links with
`rel="noopener noreferrer"`. No fonts, CDNs or analytics: the CSP would block them.

**Collector.** `https://crt.sh/` is the collector's only HTTP destination; the only
other outbound code is the availability probe (a test asserts that exactly these two
modules contain network code, and the web server none). The search pattern is URL-encoded into `q`; nothing else is user-controlled.
TLS certificates and host names are verified; **redirects are refused**; responses
are size-capped and parsed with `json.loads` only. Collected names are validated as DNS
names before they are stored or resolved. There is no `subprocess`, `os.system`,
`pickle`, `eval` or shell anywhere in the package. Snapshot import accepts JSON lines
into a fixed column set per table and refuses manifests that name files outside their
directory.

**Availability probe (`trawl/sources/probe.py`).** Targets are registry names from the
database, re-validated as DNS names. Each is resolved once; every non-global address
is refused (loopback, RFC 1918, CGNAT incl. the tailnet, link-local incl.
`169.254.169.254`, multicast, reserved, IPv6 ULA/link-local, IPv4-mapped, NAT64, 6to4,
Teredo), and a name with no public address is not contacted. The TCP connection goes
to the vetted address, so a rebinding answer cannot redirect it. TLS is verified with
SNI; an invalid certificate ends the check. The request is a fixed `GET /` with the
name as `Host` (ASCII, validated), no cookies or credentials. Redirects are recorded
and never followed. Headers and body are capped at 16 KiB each; every socket wait and
the whole check are time-limited (non-blocking I/O with `poll`), so slow or dripping
servers cannot hold a worker; at most 6 checks run at once. The body is scanned for
challenge markers and discarded - never parsed as HTML, executed or stored.

**Secrets.** None exist: no API keys, tokens or passwords are used or stored.

**Deployment (systemd user units).** `NoNewPrivileges`, `PrivateTmp`,
`ProtectSystem=strict`, write access only to `~/trawl-data`, `UMask=0077`. The web
service listens on 127.0.0.1:8790 only. The tunnel runs `cloudflared` with only the
documented `--no-autoupdate` and `--url` flags, under its own sandbox (read-only home,
private `/dev` and `/tmp`, kernel/clock/hostname protection, address families limited
to UNIX/IPv4/IPv6/netlink, `@system-service` system-call filter, no W+X memory).

## Automated checks (run on every test run)

`tests/test_availability.py` (local sockets and a fake resolver, never a real site):
refused address classes, private-only and mixed answers, invalid names never resolved,
one resolution per check (rebinding), no redirect following, request shape, DNS
success / NXDOMAIN / no address / resolver failure / resolver hang, connection refused
/ timeout / no route, TLS ok / untrusted / wrong name / handshake failure / handshake
hang, HTTP 200 / 204 / 301 / 302 / 401 / 403 / 404 / 410 / 429 / 500 / 502 / 522,
Cloudflare challenge by header and by body, malformed and missing responses,
oversized headers and body, a server dripping bytes, history, summaries, the
failed-run rule, scheduling, and that availability changes no fingerprint.
`tests/test_server.py` adds: registry listing, URL-to-hostname lookup, rejection of
IP/metadata/`file:`/script inputs, and a lookup with every socket entry point replaced
by a failure.


`tests/test_server.py`, `tests/test_docs_and_claims.py`, `tests/test_crtsh_client.py`
cover: traversal attempts (`/../`, `%2e%2e`, `/.git/config`, `/.env`, `/data/trawl.db`),
non-GET methods, oversize request lines, SQL-looking and out-of-range parameters,
`LIKE` wildcard escaping, read-only database, no traceback leakage, security headers
on every response, request-smuggling attempt, no HTML sinks or third-party URLs in the
frontend, crt.sh as the only HTTP destination, redirects refused, TLS verification on,
no dependency on third-party feeds or the beta projects.

## Audit performed

See the "Audit log" section below - it lists what was checked on the deployed system,
how, and the result.

## Audit log

Dated records, newest first; each states what was true for that version.

**2026-09-26, freeze pass (Steam Deck, trawl 2.2.1, rules r3)**

| Check | How | Result |
|---|---|---|
| HTTP audit, 75 checks | `deploy/audit_http.py` | 75/75 against the PC development server, 75/75 on the Deck at `http://127.0.0.1:8790`, 75/75 through the Quick Tunnel |
| Test suite (incl. all SSRF / availability / scheduling tests) | `python3 -m pytest tests` | 518 passed, exit 0, on the PC (Python 3.12.3) and on the Deck (Python 3.13.5) |
| Public lookup stays database-only | test with socket functions disabled; browser network log on the tunnel | lookups answer from the database; the browser made only same-origin requests; `http://169.254.169.254/` is refused with 400 |
| File modes | snapshot written from an interactive shell (umask 022) came out 644 - **found in this pass, fixed**: the CLI now sets umask 077 (regression test); the two files were set to 600 | all trawl files 600 in 700 directories |
| Listening ports, sandboxing | `ss -ltnp`; connects from the PC; `systemd-analyze --user security` | unchanged: only `127.0.0.1:8790` and `127.0.0.1:20242`, both refused from the PC; web / cycle / tunnel 4.5 |
| Scanner | OWASP ZAP | **not performed**: not installed on the PC or the Deck (not installed for this pass either) |

**2026-09-26, public registry and availability probe (Steam Deck, trawl 2.2.0, rules r3)**

The probe makes outbound connections chosen by database content, so every earlier
result was re-checked rather than carried over.

| Check | How | Result |
|---|---|---|
| HTTP audit, 75 checks (the 63 before + 12 for `/api/registry` and `/api/lookup`: URL-to-host lookup, rejection of `127.0.0.1`, `169.254.169.254`, `[::1]`, `file:`, `gopher:`, IP literals, script and CRLF input, page-size validation) | `deploy/audit_http.py` | 75/75 against the PC development server, 75/75 on the Deck at `http://127.0.0.1:8790`, 75/75 through the Quick Tunnel |
| SSRF guard of the probe | `tests/test_availability.py`: 33 refused address forms (loopback, RFC 1918, CGNAT incl. the tailnet address, metadata, multicast, reserved, IPv6 local, IPv4-mapped, NAT64, 6to4, Teredo, scoped), private-only and mixed answers, invalid names, single resolution (rebinding), no redirect following | all pass; a private-only name is never connected to |
| Hostile answers | same tests: oversized headers (40 KB) and body (2 MiB), a server dripping one byte every 0.2 s, silent servers, TLS handshakes that never finish, malformed and missing responses | bounded: capped reads, every check ended within its limit |
| Public search cannot fetch | `tests/test_server.py`: lookups with `socket.getaddrinfo`, `socket.create_connection` and `socket.socket.connect` replaced by failures | lookups answer from the database |
| Probe in production | the real `trawl-cycle` unit (systemd sandbox) started once | 335 registry domains checked in about 2 minutes, slowest check 14 s, no `error` or `deadline` results |
| Fingerprints unaffected | new analysis on the Deck after the availability run | analysis 5 has the same dataset (`bb04d618…`) and results (`2261dae6…`) fingerprints as analysis 4; the first production snapshot replays with `"reproduced": true` under 2.2.0 |
| Listening ports | `ss -ltnp` on the Deck; TCP connects from the PC | still only `127.0.0.1:8790` and `127.0.0.1:20242` added; both refused from the PC |
| Sandboxing | `systemd-analyze --user security` | trawl-web 4.5, trawl-cycle 4.5, trawl-tunnel 4.5 ("OK") |
| Scanner | OWASP ZAP | **not performed**: not installed on the PC or the Deck |

**2026-09-26, final state (Steam Deck, trawl 2.1.2, rules r3)**

| Check | How | Result |
|---|---|---|
| HTTP audit | `deploy/audit_http.py`, 63 checks: exposure paths (`/.env`, `/.git`, `/metrics`, `/debug`, the database...), methods, traversal, parameter validation, XSS reflection, CORS preflight, redirects, oversize header, malformed request line, smuggling, HTTP/1.0, headers, provenance | 63/63 against the PC development server, 63/63 on the Deck at `http://127.0.0.1:8790`, 63/63 through the Quick Tunnel |
| Malformed request line (**found in this audit, fixed**) | raw socket | before: an HTTP/0.9-style answer with no headers and an HTML page echoing the input; after: fixed JSON `bad request`, security headers, connection closed. Regression tests in `tests/test_server.py`. Through the tunnel, Cloudflare's edge rejects such a request itself (400) before it reaches the origin |
| Listening ports | `ss -ltnp` on the Deck; TCP connects from the PC over the tailnet | added by trawl: `127.0.0.1:8790` (trawl-web) and `127.0.0.1:20242` (cloudflared metrics), both loopback; 8790 and 20242 refused from the PC |
| Metrics not public | `/metrics` through the tunnel | 404 from trawl: the tunnel forwards only to 127.0.0.1:8790, cloudflared's own metrics port is not routed |
| TLS through the tunnel | `curl -v` | TLS 1.3, HTTP/2, CSP and the other security headers present end to end |
| Sandboxing | `systemd-analyze --user security` | trawl-web 4.5, trawl-cycle 4.5, trawl-tunnel 4.5 (7.6 before the tunnel unit was sandboxed); all "OK" |
| Tunnel stability | `systemctl --user restart trawl-web`; `kill -9` of the web process | the web process came back (`Restart=on-failure`); tunnel PID and public hostname unchanged (the tunnel unit uses `Wants=`, not `Requires=`) |
| Single writer | writer lock held with `flock`, then `trawl analyze` | refused with one line and exit status 2 (a traceback before 2.1.2); database untouched |
| Reproducibility | `trawl verify` + `trawl replay` of production snapshot `trawl-a00001-a96e362dc17f`, on the PC and on the Deck | both fingerprints match; `"reproduced": true` |
| Scanner | OWASP ZAP baseline | **not performed**: ZAP is not installed on the PC or the Deck |

**2026-09-26, deployed system (Steam Deck, trawl 2.1.0, rules r3)**

| Check | How | Result |
|---|---|---|
| Listening ports | `ss -ltnp` on the Deck | only `127.0.0.1:8790` (trawl-web) and `127.0.0.1:20242` (cloudflared metrics) added; nothing on 0.0.0.0 |
| Debug mode / stack traces | code review + forced 500 in tests | no debug mode exists; fixed `{"error":"internal error"}` body |
| Secrets in frontend / env files | audit script, repo grep | none exist; `/.env`, `/.git/config`, `/data/trawl.db`, `/deploy/deck.json` → 404/400 |
| Directory browsing / traversal | audit script, locally and through the tunnel | no filesystem mapping; Cloudflare rejects dot-segments (400) or normalises them to a public asset |
| Methods | audit script | POST/PUT/DELETE/PATCH/OPTIONS/TRACE → 405 |
| Input validation | audit script (SQL-like, XSS-like, oversize values) | 400 with a fixed message; oversize request line 414 |
| Headers | audit script through the tunnel | CSP, nosniff, DENY, no-referrer present end to end; `Server: cloudflare` at the edge, `trawl` at the origin |
| Sandboxing | `systemd-analyze --user security` | trawl-web exposure 4.5 ("OK"), from 9.0 before hardening |
| Outbound reach | code review + test | collector: crt.sh (redirects refused) and the host resolver only; web process makes no outbound connections |
| Suspect domains | code review | never fetched; DNS lookups only |
| Reproducibility | `trawl verify` + `trawl replay` on the first production snapshot | both fingerprints match; replay `"reproduced": true` |

Result: `deploy/audit_http.py` 39/39 against `http://127.0.0.1:8790` and 39/39 against the
public Quick Tunnel URL. Not done: an authenticated scanner (e.g. ZAP) run, and egress
firewalling at the OS level (systemd IP filtering is unavailable to user units here).
