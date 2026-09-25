# Security

An investigative tool must not become an attack surface, and must not become a
visitor of the infrastructure it watches. This document is the threat model, the
controls, and the audit that was actually performed.

## Threat model

| Asset / concern | Threat | Control |
|---|---|---|
| Web UI / API | injection, XSS, traversal, request smuggling, info leak, DoS | read-only server, strict routing, validated params, CSP, fixed error bodies, connection handling (below) |
| Database | tampering, disclosure | web process opens it read-only; files mode 600 in a 700 directory; never served; tamper-evident fingerprints |
| Collector | SSRF, redirect abuse, MITM, hostile data | one hard-coded HTTPS origin, TLS verified, redirects refused, JSON parsed as data, names validated |
| Suspect infrastructure | the tool visiting or signalling to it | no HTTP to collected names, ever; DNS lookups only, through the host resolver |
| Host (Steam Deck) | the app as a foothold | loopback binding, systemd sandboxing, no subprocesses, no secrets, no new listening ports beyond 127.0.0.1:8790 (+ cloudflared's own loopback metrics port) |
| Reviewer trust | claims that are not true | docs checked against code by tests; the beta page's false "makes no requests" claim is not repeated; CSP enforces what the docs say |

## Controls

**Web server (`trawl/server.py`).**
* Binds `127.0.0.1` by default; a warning is printed for any other host.
* GET/HEAD only; all other methods → 405. There is no write endpoint.
* Static assets: three files loaded into memory at start-up and looked up by exact
  path. No URL is ever mapped to the filesystem: no traversal, no directory listing,
  no exposure of `.env`, `.git`, the database or source.
* Parameters: length-limited; integers range-checked; enums whitelisted; domain names
  validated by the same DNS-name parser as the collector; `parse_qs` field count
  capped; request line capped at 2048 bytes (414).
* SQL: parameterised everywhere. The only interpolated fragments are fixed strings
  chosen from whitelists (sort column, order). User text in `LIKE` has `%`, `_` and
  `\` escaped.
* Database opened with `mode=ro` and `PRAGMA query_only=ON`.
* Errors: fixed JSON bodies (`internal error`); tracebacks go to the service log only.
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

**Collector.** `https://crt.sh/` is the only HTTP destination in the code (asserted by
a test). The search pattern is URL-encoded into `q`; nothing else is user-controlled.
TLS certificates and host names are verified; **redirects are refused**; responses
are size-capped and parsed with `json.loads` only. Collected names are validated as DNS
names before they are stored or resolved. There is no `subprocess`, `os.system`,
`pickle`, `eval` or shell anywhere in the package. Snapshot import accepts JSON lines
into a fixed column set per table and refuses manifests that name files outside their
directory.

**Secrets.** None exist: no API keys, tokens or passwords are used or stored.

**Deployment (systemd user units).** `NoNewPrivileges`, `PrivateTmp`,
`ProtectSystem=strict`, write access only to `~/trawl-data`, `UMask=0077`. The web
service listens on 127.0.0.1:8790 only. The tunnel runs `cloudflared` with only the
documented `--no-autoupdate` and `--url` flags.

## Automated checks (run on every test run)

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
