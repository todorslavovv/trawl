# Operations

## Requirements

Python 3.11+ (standard library only). Tested on Python 3.12 (development PC) and 3.13
(SteamOS 3.8 on the Steam Deck). `pytest` for the test suite. Current version: 2.2.0.

## Configuration

Defaults are in `trawl/config.py`. Override any subset with a JSON file passed as
`--config FILE` (or `TRAWL_CONFIG`). Unknown keys and wrong types are rejected.

| Key | Default | Meaning |
|---|---|---|
| `db_path` | `data/trawl.db` | SQLite database |
| `snapshot_dir` | `data/snapshots` | snapshot files |
| `collection.min_interval_hours` | 6 | a new crt.sh run is refused sooner than this after the previous one (`--force` overrides) |
| `collection.request_timeout_s` | 150 | per request |
| `collection.max_attempts` | 3 | per query |
| `collection.backoff_base_s` / `backoff_max_s` | 10 / 180 | exponential backoff with ±25 % jitter; Retry-After honoured up to the max |
| `collection.pace_s` | 6 | minimum gap between any two crt.sh requests (min 1) |
| `collection.max_run_minutes` | 180 | remaining queries are recorded as `skipped` |
| `collection.max_response_mb` | 256 | larger answers are refused |
| `collection.exclude_expired` | true | query only unexpired certificates (crt.sh caps full-history answers to the oldest rows) |
| `collection.truncation_min_records` / `truncation_stale_days` | 1000 / 45 | a large answer whose newest certificate is stale is recorded as truncated |
| `dns.max_per_run` / `workers` / `timeout_s` / `recheck_hours` | 600 / 8 / 12 / 20 | DNS re-check |
| `availability.enabled` | true | availability step in the cycle |
| `availability.recheck_hours` | 20 | a registry name is due when its last check is older (≈ daily) |
| `availability.unreachable_after` / `unreachable_recheck_hours` | 3 / 68 | after 3 unreachable checks in a row, re-check about every 3 days |
| `availability.max_per_run` / `workers` / `max_run_minutes` | 500 / 6 / 45 | load limits; names not started in time are skipped |
| `availability.dns_timeout_s` / `connect_timeout_s` / `tls_timeout_s` / `response_timeout_s` / `total_timeout_s` | 8 / 6 / 8 / 10 / 30 | per-phase limits and the hard limit per check |
| `availability.max_addresses` / `max_header_bytes` / `max_body_bytes` | 2 / 16384 / 16384 | addresses tried per port; read caps |
| `analysis.keep_derived` | 4 | analyses whose derived rows are kept |
| `snapshots.interval_hours` / `keep` | 24 / 14 | snapshot cadence and retention |
| `correlation.*` | see [CORRELATION](CORRELATION.md) | recorded (with SHA-256) in every analysis |

## Commands

```bash
python3 -m trawl [--config F] [--db PATH] <command>
  collect  [--force] [--keywords k ...]   one crt.sh collection run
  dnscheck                                re-resolve flagged names
  analyze                                 score + correlate; records provenance
  cycle    [--force]                      collect -> dnscheck -> analyze -> availability -> snapshot if due
  availability [--force]                  check the registry domains that are due (all with --force)
  snapshot [--analysis N] [--out DIR]     export a fingerprinted dataset
  verify   MANIFEST                       check snapshot hashes (exit 1 on mismatch)
  replay   MANIFEST                       rebuild + re-run; exit 1 unless reproduced
  report   [--analysis N] [-o FILE]       deterministic JSON report of an analysis
  stats                                   dataset and collection summary
  serve    [--host 127.0.0.1] [--port 8790]   read-only UI + API
```

Writers (`collect`, `dnscheck`, `analyze`, `cycle`, `availability`, `snapshot`) take an exclusive
lock (`<db>.lock`); a second writer is refused immediately with one line on stderr
(`refused: another trawl writer is running (lock held)`) and exit status 2. On start, runs left `running`
by a killed process are marked `interrupted`.

## Deployment on the Steam Deck

Environment found on 2026-09-26: SteamOS 3.8.16 (Arch-based), x86_64, Python 3.13.5,
SQLite 3.50.3, podman (no Docker), `cloudflared 2026.9.3` at `~/bin/cloudflared`,
systemd user session with `Linger=no`. Ports already in use by other services
(8777, 8778, 8081, Steam, Sunshine, KDE Connect) are left alone; trawl uses
**127.0.0.1:8790**.

Layout: code in `~/trawl` (replaced on deploy), data in `~/trawl-data` (mode 700,
never touched by deploys), config `~/trawl/deploy/deck.json`.

```bash
./deploy/push.sh                      # from the PC: rsync code, install units, daemon-reload
ssh deck@steamdeck-1 'systemctl --user enable --now trawl-cycle.timer trawl-web.service'
ssh deck@steamdeck-1 'systemctl --user enable --now trawl-tunnel.service'   # public demo only
```

| Unit | What |
|---|---|
| `trawl-cycle.service` + `.timer` | one cycle every 6 h (`OnUnitActiveSec=6h`, `Persistent=true`): collection, DNS re-check, analysis, availability checks of due registry domains, snapshot if due; sandboxed (`ProtectSystem=strict`, write access only to `~/trawl-data`, `NoNewPrivileges`, `PrivateTmp`) |
| `trawl-web.service` | `serve --host 127.0.0.1 --port 8790`; same sandboxing |
| `trawl-tunnel.service` | `~/bin/cloudflared tunnel --no-autoupdate --url http://127.0.0.1:8790`; `Wants=trawl-web.service` (not `Requires=`), so a web restart does not restart the tunnel; sandboxed (read-only home, private `/dev`, restricted address families, system-call filter) |

`Linger=no` means user services stop when the `deck` user session ends; the Deck is
kept logged in (it runs other user services the same way). Enabling linger is a system
setting and was not changed.

### Cloudflare Quick Tunnel

The public URL is a Cloudflare **Quick Tunnel** (`trycloudflare.com`), which Cloudflare
documents as a testing/development mechanism: a random hostname, no account, no
uptime guarantee, and a **new hostname whenever the tunnel restarts**. Read the current
one with:

```bash
journalctl --user -u trawl-tunnel | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | tail -1
```

`--no-autoupdate` is set because the tunnel runs as a service, not interactively: the
installed `cloudflared` lists the flag under `tunnel` ("Disable periodic check for
updates, restarting the server with the new version"), and an unattended self-update
already killed an older tunnel on this machine. The origin is given as `127.0.0.1`
rather than `localhost` because the web service binds IPv4 loopback only. For anything
persistent, use a named, managed Cloudflare Tunnel with Access policies instead.

### Updating

`./deploy/push.sh` then `systemctl --user restart trawl-web`. The tunnel keeps running
and the public hostname stays the same. The cycle picks up new code on its next run.
Restarting `trawl-tunnel` (only needed when its unit changes) issues a new hostname. If `RULES_VERSION` changed, the next analysis re-scores
everything under the new rules; old analyses keep their recorded rules version.

## Logs and health

```bash
journalctl --user -u trawl-cycle -u trawl-web -u trawl-tunnel
python3 -m trawl --config deploy/deck.json stats
```

The Collection and Sources pages show every run, its outcomes and coverage. Web access
logs contain method, path (no query string) and status - no client addresses.

## Backups

The database is the archive. `sqlite3 ~/trawl-data/trawl.db ".backup backup.db"` is
safe while the services run. Snapshot files are self-verifying (`trawl verify`).
