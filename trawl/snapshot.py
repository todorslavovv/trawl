"""Canonical dataset, fingerprints, portable snapshots and replay.

The dataset an analysis ran on is defined by three cut-offs (last collection run,
last source record, last DNS observation). Because observations are append-only,
those cut-offs select exactly the same rows forever, so the live database is itself
the archive: any past analysis can be re-derived from it.

`dataset_sha256` hashes one canonical serialisation of those rows. A snapshot file
is that same serialisation, gzip-compressed with a fixed header, plus a manifest -
so a third party can check the file against the fingerprint recorded in the
analysis, then replay the analysis and compare its results fingerprint.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path

from . import VERSION
from .config import canonical
from .db import connect, utcnow

# Only the sources an analysis reads. Availability checks (sources/probe.py) are an
# observation layer beside the analysis: their source row and runs are not part of the
# dataset, so they can never change a dataset or results fingerprint.
ANALYSIS_SOURCES = ("crtsh", "dns")
_IN = "('" + "','".join(ANALYSIS_SOURCES) + "')"
_SELECTS = (
    ("source", f"SELECT id, kind, endpoint FROM sources WHERE id IN {_IN} ORDER BY id", None),
    ("run", f"SELECT * FROM collection_runs WHERE id <= :run AND source_id IN {_IN} ORDER BY id", "run"),
    ("query", "SELECT * FROM queries WHERE run_id <= :run ORDER BY id", "run"),
    ("record", "SELECT id, source_id, record_key, external_id, run_id, query_id, fetched_at,"
               " payload, payload_sha256 FROM source_records WHERE id <= :record ORDER BY id",
     "record"),
    ("dns", "SELECT * FROM dns_observations WHERE id <= :dns ORDER BY id", "dns"),
)
_TABLE = {"run": "collection_runs", "query": "queries", "record": "source_records",
          "dns": "dns_observations"}


def cutoffs_now(conn: sqlite3.Connection) -> dict:
    q = lambda sql: conn.execute(sql).fetchone()[0] or 0
    return {"run": q("SELECT MAX(id) FROM collection_runs WHERE status != 'running'"),
            "record": q("SELECT MAX(id) FROM source_records"),
            "dns": q("SELECT MAX(id) FROM dns_observations")}


def iter_lines(conn: sqlite3.Connection, cutoffs: dict):
    for kind, sql, _ in _SELECTS:
        cur = conn.execute(sql, cutoffs)
        cols = [c[0] for c in cur.description]
        for row in cur:
            yield kind, canonical({"t": kind, **dict(zip(cols, row))})


def dataset_sha256(conn: sqlite3.Connection, cutoffs: dict) -> tuple[str, dict]:
    h = hashlib.sha256()
    counts: dict = {}
    for t, line in iter_lines(conn, cutoffs):
        h.update(line.encode("utf-8"))
        h.update(b"\n")
        counts[t] = counts.get(t, 0) + 1
    return h.hexdigest(), counts


def export(conn: sqlite3.Connection, analysis_id: int, out_dir: str | os.PathLike) -> Path:
    a = conn.execute("SELECT * FROM analysis_runs WHERE id=? AND status='complete'",
                     (analysis_id,)).fetchone()
    if a is None:
        raise ValueError(f"no complete analysis {analysis_id}")
    cut = {"run": a["cutoff_run_id"], "record": a["cutoff_record_id"], "dns": a["cutoff_dns_id"]}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"trawl-a{analysis_id:05d}-{a['dataset_sha256'][:12]}"
    data_path = out / f"{stem}.jsonl.gz"
    h = hashlib.sha256()
    counts: dict = {}
    tmp = data_path.with_suffix(".tmp")
    with open(tmp, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0,
                                                filename="", compresslevel=6) as gz:
        for t, line in iter_lines(conn, cut):
            b = line.encode("utf-8") + b"\n"
            h.update(b)
            gz.write(b)
            counts[t] = counts.get(t, 0) + 1
    if h.hexdigest() != a["dataset_sha256"]:
        tmp.unlink()
        raise RuntimeError("dataset fingerprint differs from the one recorded for this "
                           "analysis - observations were modified after it ran")
    os.replace(tmp, data_path)
    file_sha = hashlib.sha256(data_path.read_bytes()).hexdigest()
    runs = conn.execute(
        f"SELECT source_id, status, COUNT(*) n FROM collection_runs WHERE id <= ? AND source_id IN {_IN}"
        " GROUP BY source_id, status ORDER BY source_id, status", (cut["run"],)).fetchall()
    manifest = {
        "format": "trawl-dataset/1",
        "dataset_sha256": a["dataset_sha256"],
        "file": data_path.name,
        "file_sha256": file_sha,
        "counts": counts,
        "cutoffs": cut,
        "analysis": {
            "id": analysis_id, "as_of": a["as_of"], "software_version": a["software_version"],
            "rules_version": a["rules_version"],
            "correlation_config": json.loads(a["correlation_config"]),
            "correlation_sha256": a["correlation_sha256"],
            "results_sha256": a["results_sha256"],
        },
        "collection_runs": [dict(r) for r in runs],
        "exported_at": utcnow(),
        "exported_by": f"trawl {VERSION}",
    }
    man_path = out / f"{stem}.manifest.json"
    man_path.write_text(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    conn.execute("INSERT INTO snapshots(created_at, analysis_id, dataset_sha256, file_name,"
                 " file_sha256, bytes) VALUES (?,?,?,?,?,?)",
                 (utcnow(), analysis_id, a["dataset_sha256"], data_path.name, file_sha,
                  data_path.stat().st_size))
    conn.commit()
    return man_path


def _read_manifest(manifest_path: str | os.PathLike) -> tuple[dict, Path]:
    mp = Path(manifest_path)
    man = json.loads(mp.read_text(encoding="utf-8"))
    if man.get("format") != "trawl-dataset/1":
        raise ValueError("not a trawl dataset manifest")
    name = man["file"]
    if "/" in name or "\\" in name or name.startswith("."):
        raise ValueError("manifest names a file outside its own directory")
    return man, mp.parent / name


def verify(manifest_path: str | os.PathLike) -> dict:
    """Check file hash and content fingerprint against the manifest."""
    man, data = _read_manifest(manifest_path)
    file_ok = hashlib.sha256(data.read_bytes()).hexdigest() == man["file_sha256"]
    h = hashlib.sha256()
    with gzip.open(data, "rb") as gz:
        for chunk in iter(lambda: gz.read(1 << 20), b""):
            h.update(chunk)
    return {"file_sha256_ok": file_ok, "dataset_sha256_ok": h.hexdigest() == man["dataset_sha256"],
            "dataset_sha256": h.hexdigest()}


def import_into(conn: sqlite3.Connection, data_path: Path) -> None:
    """Load a snapshot's observations into an empty database, keeping original ids.

    Parsing is json.loads only (no pickle, no eval) and every row goes through
    parameterised INSERTs into a fixed column list per table.
    """
    cols_cache: dict = {}
    with gzip.open(data_path, "rt", encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            t = row.pop("t")
            if t == "source":
                continue                  # registered by connect()
            table = _TABLE.get(t)
            if table is None:
                raise ValueError(f"unknown row type {t!r}")
            if table not in cols_cache:
                cols_cache[table] = [c[1] for c in conn.execute(f"PRAGMA table_info({table})")]
            cols = [c for c in row if c in cols_cache[table]]
            if len(cols) != len(row):
                raise ValueError(f"unexpected columns for {table}")
            conn.execute(f"INSERT INTO {table}({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                         [row[c] for c in cols])
    conn.commit()


def replay(manifest_path: str | os.PathLike, cfg: dict, work_dir: str | None = None) -> dict:
    """Rebuild a fresh database from a snapshot and re-run its analysis."""
    from .analysis import run_analysis
    from .collect import normalize
    man, data = _read_manifest(manifest_path)
    check = verify(manifest_path)
    if not (check["file_sha256_ok"] and check["dataset_sha256_ok"]):
        return {"reproduced": False, "reason": "snapshot integrity check failed", **check}
    with tempfile.TemporaryDirectory(dir=work_dir) as td:
        conn = connect(Path(td) / "replay.db")
        import_into(conn, data)
        normalize(conn)
        a = man["analysis"]
        corr = a["correlation_config"]
        aid = run_analysis(conn, {**cfg, "correlation": corr}, as_of=a["as_of"],
                           cutoffs=man["cutoffs"], log=lambda *_: None)
        row = conn.execute("SELECT dataset_sha256, results_sha256, rules_version,"
                           " software_version FROM analysis_runs WHERE id=?", (aid,)).fetchone()
        conn.close()
    same_rules = row["rules_version"] == a["rules_version"]
    return {
        "reproduced": row["results_sha256"] == a["results_sha256"]
                      and row["dataset_sha256"] == man["dataset_sha256"],
        "dataset_sha256": row["dataset_sha256"],
        "results_sha256": row["results_sha256"],
        "expected_results_sha256": a["results_sha256"],
        "rules_version": row["rules_version"],
        "expected_rules_version": a["rules_version"],
        "note": None if same_rules else
                "rules version differs from the one that produced the snapshot; "
                "results are expected to differ",
    }


def prune(conn: sqlite3.Connection, snap_dir: str | os.PathLike, keep: int) -> int:
    """Keep the newest `keep` snapshot files. The database rows stay as a record."""
    rows = conn.execute("SELECT file_name FROM snapshots ORDER BY id DESC").fetchall()
    removed = 0
    for r in rows[keep:]:
        for suffix in (".jsonl.gz", ".manifest.json"):
            p = Path(snap_dir) / (r["file_name"].removesuffix(".jsonl.gz") + suffix)
            if p.exists():
                p.unlink()
                removed += 1
    return removed
