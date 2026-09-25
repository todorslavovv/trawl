"""Command line.

    python -m trawl collect   [--force]       crt.sh keyword collection (one run)
    python -m trawl dnscheck                  re-resolve flagged names
    python -m trawl analyze                   score + correlate, record provenance
    python -m trawl cycle     [--force]       collect -> dnscheck -> analyze -> snapshot if due
    python -m trawl snapshot  [--analysis N]  export a portable, fingerprinted dataset
    python -m trawl verify    MANIFEST        check a snapshot's hashes
    python -m trawl replay    MANIFEST        rebuild and re-run; compare fingerprints
    python -m trawl report    [--analysis N]  deterministic JSON report of an analysis
    python -m trawl stats                     dataset and collection health
    python -m trawl serve     [--port 8790]   read-only web UI + JSON API on localhost
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import VERSION
from . import config as C
from .db import connect, recover_interrupted, writer_lock


def _latest_analysis(conn) -> int:
    row = conn.execute("SELECT MAX(id) FROM analysis_runs WHERE status='complete'").fetchone()
    if not row or row[0] is None:
        raise SystemExit("no complete analysis yet - run `trawl analyze`")
    return row[0]


def _writer(args, cfg):
    conn = connect(cfg["db_path"])
    n = recover_interrupted(conn)
    if n:
        print(f"note: marked {n} run(s) left 'running' by a previous process as interrupted")
    return conn


def cmd_collect(args, cfg):
    from .collect import TooSoon, collect_crtsh
    with writer_lock(cfg["db_path"]):
        conn = _writer(args, cfg)
        try:
            rid = collect_crtsh(conn, cfg, force=args.force, keywords=args.keywords or None)
        except TooSoon as e:
            print(f"skipped: {e}")
            return 0
        r = conn.execute("SELECT * FROM collection_runs WHERE id=?", (rid,)).fetchone()
        print(f"run {rid}: {r['status']} - {r['queries_requested']} queries, ok={r['queries_ok']}"
              f" empty={r['queries_empty']} failed={r['queries_failed']} timeout="
              f"{r['queries_timeout']} abandoned={r['queries_abandoned']} skipped="
              f"{r['queries_skipped']}; {r['records_received']} records ({r['records_new']} new)")
    return 0


def cmd_dnscheck(args, cfg):
    from .analysis import flagged_by_priority
    from .collect import dnscheck
    with writer_lock(cfg["db_path"]):
        conn = _writer(args, cfg)
        dnscheck(conn, cfg, flagged_by_priority(conn, cfg))
    return 0


def cmd_analyze(args, cfg):
    from .analysis import run_analysis
    with writer_lock(cfg["db_path"]):
        conn = _writer(args, cfg)
        run_analysis(conn, cfg)
    return 0


def cmd_cycle(args, cfg):
    from .analysis import flagged_by_priority, run_analysis
    from .collect import TooSoon, collect_crtsh, dnscheck
    from .snapshot import export, prune
    with writer_lock(cfg["db_path"]):
        conn = _writer(args, cfg)
        try:
            collect_crtsh(conn, cfg, force=args.force)
        except TooSoon as e:
            print(f"collect skipped: {e}")
        dnscheck(conn, cfg, flagged_by_priority(conn, cfg))
        aid = run_analysis(conn, cfg)
        last = conn.execute("SELECT MAX(created_at) FROM snapshots").fetchone()[0]
        due = (last is None or datetime.now(timezone.utc) - datetime.fromisoformat(last)
               >= timedelta(hours=cfg["snapshots"]["interval_hours"]))
        if due:
            path = export(conn, aid, cfg["snapshot_dir"])
            prune(conn, cfg["snapshot_dir"], cfg["snapshots"]["keep"])
            print(f"  snapshot: {path}")
    return 0


def cmd_snapshot(args, cfg):
    from .snapshot import export
    with writer_lock(cfg["db_path"]):
        conn = _writer(args, cfg)
        aid = args.analysis or _latest_analysis(conn)
        print(export(conn, aid, args.out or cfg["snapshot_dir"]))
    return 0


def cmd_verify(args, cfg):
    from .snapshot import verify
    res = verify(args.manifest)
    print(json.dumps(res, indent=2))
    return 0 if res["file_sha256_ok"] and res["dataset_sha256_ok"] else 1


def cmd_replay(args, cfg):
    from .snapshot import replay
    res = replay(args.manifest, cfg)
    print(json.dumps(res, indent=2))
    return 0 if res["reproduced"] else 1


def cmd_report(args, cfg):
    from .analysis import report
    conn = connect(cfg["db_path"], readonly=True)
    rep = report(conn, args.analysis or _latest_analysis(conn), cfg)
    text = json.dumps(rep, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        p = rep["provenance"]
        same = p["results_sha256_recorded"] == p["results_sha256_regenerated"]
        print(f"wrote {args.output}; results fingerprint "
              f"{'matches' if same else 'DIFFERS FROM'} the recorded one")
    else:
        sys.stdout.write(text)
    return 0


def cmd_stats(args, cfg):
    conn = connect(cfg["db_path"], readonly=True)
    q = lambda s, *a: conn.execute(s, a).fetchone()[0]
    print(f"trawl {VERSION} - {cfg['db_path']}")
    print(f"source records : {q('SELECT COUNT(*) FROM source_records')}")
    print(f"certificates   : {q('SELECT COUNT(*) FROM certificates')}")
    print(f"names          : {q('SELECT COUNT(*) FROM domains')}")
    print(f"dns checks     : {q('SELECT COUNT(*) FROM dns_observations')}")
    for r in conn.execute("SELECT source_id, status, COUNT(*) n FROM collection_runs"
                          " GROUP BY source_id, status ORDER BY source_id, status"):
        print(f"runs           : {r['source_id']:6} {r['status']:12} {r['n']}")
    a = conn.execute("SELECT * FROM analysis_runs WHERE status='complete' ORDER BY id DESC"
                     " LIMIT 1").fetchone()
    if a:
        print(f"last analysis  : #{a['id']} as_of {a['as_of']} flagged={a['domains_flagged']}"
              f" campaigns={a['campaigns_total']} dataset={a['dataset_sha256'][:16]}")
    return 0


def cmd_serve(args, cfg):
    from .server import serve
    serve(cfg["db_path"], host=args.host, port=args.port)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="trawl", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", help="JSON config file (overrides defaults)")
    ap.add_argument("--db", help="database path (overrides config)")
    ap.add_argument("--version", action="version", version=f"trawl {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("collect")
    p.add_argument("--force", action="store_true")
    p.add_argument("--keywords", nargs="*")
    sub.add_parser("dnscheck")
    sub.add_parser("analyze")
    p = sub.add_parser("cycle")
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("snapshot")
    p.add_argument("--analysis", type=int)
    p.add_argument("--out")
    for name in ("verify", "replay"):
        sub.add_parser(name).add_argument("manifest")
    p = sub.add_parser("report")
    p.add_argument("--analysis", type=int)
    p.add_argument("-o", "--output")
    sub.add_parser("stats")
    p = sub.add_parser("serve")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8790)
    args = ap.parse_args(argv)
    cfg = C.load(args.config)
    if args.db:
        cfg["db_path"] = args.db
    return globals()[f"cmd_{args.cmd}"](args, cfg)


if __name__ == "__main__":
    sys.exit(main())
