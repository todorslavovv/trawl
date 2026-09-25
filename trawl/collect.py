"""Collection runs: crt.sh keyword collection, DNS re-checks, and normalisation.

Partial collection is the normal case against a free shared service, so it is
modelled explicitly rather than treated as an error:

  * every query ends in one classified outcome (see sources/crtsh.py);
  * crt.sh answers HTTP 200 with [] - or with a truncated list - when it gives up
    on an expensive scan, and that must never read as "nothing (more) exists". So a
    leading-wildcard answer is checked against the indexed prefix query for the same
    keyword: an empty answer is accepted only if the prefix answer was also verifiably
    empty, and a superset answer smaller than its own subset is truncated. Both are
    reclassified 'abandoned' (records received are still kept);
  * per keyword, coverage is full (the contains-pattern answered), partial
    (only prefix/dotted patterns answered) or none;
  * the run is complete only if every keyword has full coverage.
"""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from . import VERSION, names, rules
from .config import canonical, sha256_of
from .db import utcnow
from .sources import crtsh, dns

OK_OUTCOMES = ("ok", "ok_empty")


class TooSoon(Exception):
    pass


def _start_run(conn, source_id: str, config: dict) -> int:
    cur = conn.execute(
        "INSERT INTO collection_runs(source_id, started_at, status, software_version, config_json)"
        " VALUES (?, ?, 'running', ?, ?)", (source_id, utcnow(), VERSION, canonical(config)))
    conn.commit()
    return cur.lastrowid


def last_run_started(conn, source_id: str) -> datetime | None:
    row = conn.execute("SELECT MAX(started_at) FROM collection_runs WHERE source_id=?",
                       (source_id,)).fetchone()
    return datetime.fromisoformat(row[0]) if row and row[0] else None


# -- crt.sh -----------------------------------------------------------------------
def collect_crtsh(conn: sqlite3.Connection, cfg: dict, *, force: bool = False,
                  keywords: list | None = None, client: crtsh.Client | None = None,
                  clock=time.monotonic, log=print) -> int:
    col = cfg["collection"]
    prev = last_run_started(conn, "crtsh")
    if prev and not force:
        due = prev + timedelta(hours=col["min_interval_hours"])
        if datetime.now(timezone.utc) < due:
            raise TooSoon(f"previous crt.sh run started {prev.isoformat()}; next allowed "
                          f"after {due.isoformat()} (collection.min_interval_hours="
                          f"{col['min_interval_hours']}); use --force to override")
    keywords = sorted(keywords or rules.query_keywords())
    client = client or crtsh.Client(
        timeout_s=col["request_timeout_s"], max_attempts=col["max_attempts"],
        backoff_base_s=col["backoff_base_s"], backoff_max_s=col["backoff_max_s"],
        pace_s=col["pace_s"], max_bytes=int(col["max_response_mb"] * 1024 * 1024))
    run_cfg = {"collection": col, "keywords": keywords, "rules_version": rules.RULES_VERSION,
               "patterns": {"prefix": "{k}%", "contains": "%{k}%", "dotted": "%.{k}%"}}
    run_id = _start_run(conn, "crtsh", run_cfg)
    deadline = clock() + col["max_run_minutes"] * 60
    coverage = {}
    for kw in keywords:
        results = {}
        for role, pat in (("prefix", f"{kw}%"), ("contains", f"%{kw}%")):
            results[role] = _query(conn, client, run_id, kw, role, pat, clock, deadline)
        pre, con = results["prefix"], results["contains"]
        why = None
        if con["outcome"] == "ok_empty" and pre["outcome"] != "ok_empty":
            why = (f"empty answer to %{kw}% although {kw}% returned {pre['records']} records"
                   if pre["outcome"] == "ok" else
                   f"empty answer to %{kw}% cannot be verified: {kw}% itself failed "
                   f"({pre['outcome']})")
        elif con["outcome"] == "ok" and pre["outcome"] == "ok" and con["records"] < pre["records"]:
            why = (f"%{kw}% (a superset) returned {con['records']} records but {kw}% returned "
                   f"{pre['records']} - truncated answer; its records are kept")
        if why:
            conn.execute("UPDATE queries SET outcome='abandoned', error=? WHERE id=?",
                         (why + " - crt.sh abandoned the scan", con["id"]))
            conn.commit()
            con["outcome"] = "abandoned"
        if con["outcome"] in OK_OUTCOMES:
            coverage[kw] = "full"
        else:
            dot = _query(conn, client, run_id, kw, "dotted", f"%.{kw}%", clock, deadline)
            if dot["outcome"] == "ok_empty" and pre["outcome"] != "ok_empty":
                # A leading-wildcard scan answering [] is only credible when the
                # indexed prefix query also found nothing; otherwise it is the same
                # abandoned-scan symptom as above and cannot be read as "no matches".
                conn.execute("UPDATE queries SET outcome='abandoned', error=? WHERE id=?",
                             (f"empty answer to leading-wildcard scan %.{kw}% while the "
                              f"prefix query did not return an empty result - unverifiable",
                              dot["id"]))
                conn.commit()
                dot["outcome"] = "abandoned"
            answered = [r for r in (pre, dot) if r["outcome"] in OK_OUTCOMES]
            coverage[kw] = "partial" if answered else "none"
        log(f"  {kw:14} coverage={coverage[kw]:8} " + " ".join(
            f"{r}={results[r]['outcome']}" for r in results))
    return _finish_crtsh(conn, run_id, coverage)


def _query(conn, client, run_id, kw, role, pattern, clock, deadline) -> dict:
    started = utcnow()
    if clock() > deadline:
        res = crtsh.QueryResult(outcome="skipped", error="run time budget exhausted")
    else:
        res = client.search(pattern)
    new = invalid = 0
    cur = conn.execute(
        "INSERT INTO queries(run_id, keyword, role, query, started_at, finished_at, duration_s,"
        " outcome, http_status, attempts, bytes, response_sha256, records, error)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (run_id, kw, role, pattern, started, utcnow(), res.duration_s, res.outcome,
         res.http_status, res.attempts, res.bytes, res.response_sha256,
         len(res.records) if res.outcome in OK_OUTCOMES else None, res.error))
    qid = cur.lastrowid
    fetched = utcnow()
    for rec in res.records if res.outcome == "ok" else ():
        if not (isinstance(rec, dict) and isinstance(rec.get("id"), int)
                and isinstance(rec.get("name_value"), str)):
            invalid += 1
            continue
        payload = canonical(rec)
        sha = sha256_of(rec)
        c = conn.execute(
            "INSERT OR IGNORE INTO source_records(source_id, record_key, external_id, run_id,"
            " query_id, fetched_at, payload, payload_sha256) VALUES ('crtsh',?,?,?,?,?,?,?)",
            (f"{rec['id']}:{sha[:16]}", str(rec["id"]), run_id, qid, fetched, payload, sha))
        new += c.rowcount
    conn.execute("UPDATE queries SET records_new=?, records_invalid=? WHERE id=?",
                 (new, invalid, qid))
    conn.commit()
    return {"id": qid, "outcome": res.outcome,
            "records": len(res.records) if res.outcome in OK_OUTCOMES else 0}


def _finish_crtsh(conn, run_id: int, coverage: dict) -> int:
    q = conn.execute(
        "SELECT COUNT(*) n,"
        " SUM(outcome='ok') ok, SUM(outcome='ok_empty') empty,"
        " SUM(outcome IN ('http_error','network_error','parse_error','too_large')) failed,"
        " SUM(outcome='timeout') timeout, SUM(outcome='abandoned') abandoned,"
        " SUM(outcome='skipped') skipped, COALESCE(SUM(records),0) recs,"
        " COALESCE(SUM(records_new),0) new FROM queries WHERE run_id=?", (run_id,)).fetchone()
    vals = list(coverage.values())
    if vals and all(v == "full" for v in vals):
        status = "complete"
    elif not vals or all(v == "none" for v in vals):
        status = "failed"
    else:
        status = "partial"
    note = canonical({"coverage": coverage})
    conn.execute(
        "UPDATE collection_runs SET finished_at=?, status=?, queries_requested=?, queries_ok=?,"
        " queries_empty=?, queries_failed=?, queries_timeout=?, queries_abandoned=?,"
        " queries_skipped=?, records_received=?, records_new=?, note=? WHERE id=?",
        (utcnow(), status, q["n"], q["ok"] or 0, q["empty"] or 0, q["failed"] or 0,
         q["timeout"] or 0, q["abandoned"] or 0, q["skipped"] or 0, q["recs"], q["new"],
         note, run_id))
    conn.commit()
    normalize(conn)
    return run_id


# -- normalisation --------------------------------------------------------------
def _cert_key(rec: dict) -> str:
    serial = str(rec.get("serial_number") or "").lower().lstrip("0")
    if not serial:
        return f"crtsh:{rec['id']}"
    return f"{rec.get('issuer_ca_id')}:{serial}"


def normalize(conn: sqlite3.Connection) -> int:
    """Derive domains/certificates/cert_names from new source records.

    Deterministic and incremental: records are processed in id order, names in
    sorted order, and every insert is idempotent. A precertificate and its final
    certificate share issuer and serial, so they become one certificate with two
    crt.sh records instead of two findings.
    """
    row = conn.execute("SELECT value FROM meta WHERE key='normalized_through'").fetchone()
    last = int(row[0]) if row else 0
    top = last
    rows = conn.execute("SELECT id, payload, fetched_at FROM source_records"
                        " WHERE source_id='crtsh' AND id > ? ORDER BY id", (last,))
    for rid, payload, fetched in rows.fetchall():
        rec = json.loads(payload)
        key = _cert_key(rec)
        conn.execute(
            "INSERT OR IGNORE INTO certificates(cert_key, issuer_ca_id, issuer_name, serial,"
            " common_name, not_before, not_after, first_seen_at, first_record_id)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (key, rec.get("issuer_ca_id"), rec.get("issuer_name"),
             str(rec.get("serial_number") or "").lower() or None,
             (rec.get("common_name") or "").lower() or None, rec.get("not_before"),
             rec.get("not_after"), fetched, rid))
        cid = conn.execute("SELECT id FROM certificates WHERE cert_key=?", (key,)).fetchone()[0]
        conn.execute("INSERT OR IGNORE INTO cert_records(certificate_id, record_id, crtsh_id)"
                     " VALUES (?,?,?)", (cid, rid, rec["id"]))
        idents = {("matched_identity", n) for n in rec["name_value"].split("\n")}
        if rec.get("common_name"):
            idents.add(("common_name", rec["common_name"]))
        for via, raw in sorted(idents):
            norm = names.normalise(raw)
            if norm is None:
                continue                      # organisation names, e-mails, IPs
            name, wildcard = norm
            p = names.parse(name)
            conn.execute(
                "INSERT OR IGNORE INTO domains(name, registrable, suffix, first_seen_at,"
                " first_record_id) VALUES (?,?,?,?,?)", (name, p.registrable, p.suffix, fetched, rid))
            did = conn.execute("SELECT id FROM domains WHERE name=?", (name,)).fetchone()[0]
            conn.execute(
                "INSERT OR IGNORE INTO cert_names(certificate_id, domain_id, wildcard, via,"
                " first_record_id) VALUES (?,?,?,?,?)", (cid, did, int(wildcard), via, rid))
        top = rid
    conn.execute("INSERT INTO meta(key, value) VALUES ('normalized_through', ?)"
                 " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(top),))
    conn.commit()
    return top - last


# -- DNS --------------------------------------------------------------------------
def dnscheck(conn: sqlite3.Connection, cfg: dict, targets: list[str], *,
             resolve=None, log=print) -> int | None:
    """Re-resolve `targets` (already prioritised by the caller), skipping names
    checked within dns.recheck_hours. Every result is appended, never overwritten."""
    d = cfg["dns"]
    cut = (datetime.now(timezone.utc) - timedelta(hours=d["recheck_hours"])).isoformat(timespec="seconds")
    recent = {r[0] for r in conn.execute(
        "SELECT DISTINCT domain FROM dns_observations WHERE checked_at > ?", (cut,))}
    todo = [t for t in targets if t not in recent][: d["max_per_run"]]
    if not todo:
        log("  dns: nothing due")
        return None
    resolver = dns.resolver_description()
    run_id = _start_run(conn, "dns", {"dns": d, "resolver": resolver, "targets": len(todo)})
    kw = {"resolve": resolve} if resolve else {}
    results = dns.check_many(todo, workers=d["workers"], timeout_s=d["timeout_s"], **kw)
    now = utcnow()
    counts = {"resolved": 0, "nxdomain": 0, "no_address": 0, "temporary_failure": 0,
              "failure": 0, "timeout": 0}
    for host in sorted(results):
        outcome, addrs, err = results[host]
        counts[outcome] += 1
        conn.execute("INSERT INTO dns_observations(run_id, domain, checked_at, resolver, outcome,"
                     " addresses, error) VALUES (?,?,?,?,?,?,?)",
                     (run_id, host, now, resolver, outcome, json.dumps(addrs), err))
    failed = counts["temporary_failure"] + counts["failure"]
    answered = counts["resolved"] + counts["nxdomain"] + counts["no_address"]
    status = ("complete" if failed + counts["timeout"] == 0
              else "failed" if answered == 0 else "partial")
    conn.execute(
        "UPDATE collection_runs SET finished_at=?, status=?, queries_requested=?, queries_ok=?,"
        " queries_empty=?, queries_failed=?, queries_timeout=?, records_received=?,"
        " records_new=?, note=? WHERE id=?",
        (utcnow(), status, len(todo), counts["resolved"],
         counts["nxdomain"] + counts["no_address"], failed, counts["timeout"], len(todo),
         len(todo), canonical(counts), run_id))
    conn.commit()
    log(f"  dns: {len(todo)} checked {counts}")
    return run_id
