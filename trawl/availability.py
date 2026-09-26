"""Availability history of the public registry.

The registry is the flagged population (likely / possible / lead) of the latest
complete analysis - not the raw certificate names. Each cycle checks the registry
names that are due and appends one observation per check (sources/probe.py).

Semantics, kept strict on purpose:
  * nothing is overwritten; a check is one row with its time, method and result;
  * a day without a row means "not checked", never "down" - summaries are built only
    from observations that exist;
  * "last confirmed reachable" is the latest check whose result was 'reachable';
  * observations of a run in which the checker itself had no working DNS at all
    (status 'failed') are kept but ignored by summaries: they say nothing about the
    domains.

Availability is an extra observation layer. It is not an input of scoring,
correlation, snapshots or any fingerprint.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from .collect import _start_run
from .config import canonical
from .db import utcnow
from .sources import probe

REGISTRY = ("likely", "possible", "lead")


def has_table(conn) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table'"
                        " AND name='availability_observations'").fetchone() is not None


def registry_names(conn) -> list[str]:
    row = conn.execute("SELECT MAX(id) FROM analysis_runs WHERE status='complete'").fetchone()
    if not row or row[0] is None:
        return []
    return [r[0] for r in conn.execute(
        "SELECT d.name FROM decisions x JOIN domains d ON d.id=x.domain_id WHERE x.analysis_id=?"
        f" AND x.verdict IN ({','.join('?' * len(REGISTRY))}) ORDER BY x.score DESC, d.name",
        (row[0], *REGISTRY))]


def histories(conn, names: list[str] | None = None) -> dict[str, list[tuple[str, str]]]:
    """(checked_at, state) per domain, oldest first, from informative runs only."""
    if not has_table(conn):
        return {}
    sql = ("SELECT o.domain, o.checked_at, o.state FROM availability_observations o"
           " JOIN collection_runs r ON r.id=o.run_id WHERE r.status != 'failed'")
    args: tuple = ()
    if names is not None:
        if not names:
            return {}
        sql += f" AND o.domain IN ({','.join('?' * len(names))})"
        args = tuple(names)
    out: dict = {}
    for d, t, s in conn.execute(sql + " ORDER BY o.id", args):
        out.setdefault(d, []).append((t, s))
    return out


def summarize(history: list[tuple[str, str]]) -> dict:
    """Everything the registry shows about one domain, from its observations alone."""
    reach = [t for t, s in history if s == "reachable"]
    last = history[-1] if history else (None, None)
    return {"checks": len(history), "reachable_checks": len(reach),
            "failed_checks": len(history) - len(reach),
            "first_checked": history[0][0] if history else None, "last_checked": last[0],
            "last_reachable": reach[-1] if reach else None,
            "previous_reachable": reach[-2] if len(reach) > 1 else None,
            "last_state": last[1], "state": probe.public_state(last[1])}


def due(conn, cfg: dict, names: list[str], now: datetime | None = None) -> list[str]:
    """Names to check now: never checked first, then the longest-unchecked. A name whose
    last `unreachable_after` checks were all 'unreachable' waits longer."""
    a = cfg["availability"]
    now = now or datetime.now(timezone.utc)
    hist = histories(conn)
    never, old = [], []
    for n in names:
        h = hist.get(n)
        if not h:
            never.append(n)
            continue
        k = a["unreachable_after"]
        gone = len(h) >= k and all(s == "unreachable" for _, s in h[-k:])
        wait = a["unreachable_recheck_hours"] if gone else a["recheck_hours"]
        last = datetime.fromisoformat(h[-1][0])
        if now - last >= timedelta(hours=wait):
            old.append((last, n))
    old.sort()
    return (never + [n for _, n in old])[: a["max_per_run"]]


def run(conn, cfg: dict, names: list[str], *, force: bool = False, log=print, **probe_kw) -> int | None:
    """Check the due names (all of `names` with force) and append the observations."""
    a = cfg["availability"]
    todo = list(names)[: a["max_per_run"]] if force else due(conn, cfg, names)
    if not todo:
        log("  availability: nothing due")
        return None
    run_id = _start_run(conn, "availability",
                        {"availability": a, "checker": probe.CHECKER, "targets": len(todo)})
    deadline = time.monotonic() + a["max_run_minutes"] * 60
    results = probe.check_many(todo, a, run_deadline=deadline, **probe_kw)
    states = {s: 0 for s in probe.STATES}
    reasons: dict = {}
    skipped = answered = 0
    for host in sorted(results):
        r = results[host]
        if r is None:
            skipped += 1                       # run budget spent: not checked, not stored
            continue
        states[r["state"]] += 1
        reasons[r["reason"]] = reasons.get(r["reason"], 0) + 1
        answered += r["dns"] in ("resolved", "nxdomain", "no_address")
        conn.execute(
            "INSERT INTO availability_observations(run_id, source_id, checker, domain, checked_at,"
            " duration_ms, dns, addresses, address, port, tcp, tls, http, http_status, location,"
            " server, protection, challenge, body_bytes, truncated, state, reason, error)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, probe.SOURCE["id"], probe.CHECKER, host, r["checked_at"], r["duration_ms"],
             r["dns"], json.dumps(r["addresses"]), r["address"], r["port"], r["tcp"], r["tls"],
             r["http"], r["http_status"], r["location"], r["server"], r["protection"],
             r["challenge"], r["body_bytes"], r["truncated"], r["state"], r["reason"], r["error"]))
    stored = len(todo) - skipped
    # No DNS answer for any of several names: the checker's own network was down.
    status = ("failed" if stored == 0 or (stored >= 3 and answered == 0)
              else "partial" if skipped else "complete")
    conn.execute(
        "UPDATE collection_runs SET finished_at=?, status=?, queries_requested=?, queries_ok=?,"
        " queries_empty=?, queries_failed=?, queries_timeout=?, queries_skipped=?,"
        " records_received=?, records_new=?, note=? WHERE id=?",
        (utcnow(), status, len(todo), states["reachable"], states["unreachable"],
         states["dns_only"] + states["tls_error"] + states["server_error"] + states["unknown"],
         states["timeout"], skipped, stored, stored,
         canonical({"states": states, "reasons": reasons}), run_id))
    conn.commit()
    log(f"  availability: {stored} checked, {skipped} skipped {states}")
    return run_id
