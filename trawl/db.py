"""SQLite storage.

Three layers, kept deliberately separate:

1. Observations (append-only): collection runs, the queries they made, the raw
   source records exactly as received, and DNS observations. Nothing here is ever
   updated after the run that wrote it finishes, and nothing is ever deleted.
2. Normalised index (derived, deterministic): domains, certificates and which
   certificate lists which name - rebuilt identically from (1) by `normalize`.
3. Analyses (derived, reproducible): scores, signals, indicators, relationships and
   campaign hypotheses, each tied to an analysis run that records the exact input
   cut-off, dataset fingerprint, software/rule versions and configuration. Old
   analyses' derived rows may be pruned; their metadata rows are kept forever and
   can be regenerated from the observations.
"""
from __future__ import annotations

import fcntl
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    endpoint    TEXT NOT NULL,
    description TEXT NOT NULL,
    provenance  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collection_runs (
    id                INTEGER PRIMARY KEY,
    source_id         TEXT NOT NULL REFERENCES sources(id),
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    status            TEXT NOT NULL CHECK (status IN
                        ('running','complete','partial','failed','interrupted')),
    software_version  TEXT NOT NULL,
    config_json       TEXT NOT NULL,
    queries_requested INTEGER NOT NULL DEFAULT 0,
    queries_ok        INTEGER NOT NULL DEFAULT 0,
    queries_empty     INTEGER NOT NULL DEFAULT 0,
    queries_failed    INTEGER NOT NULL DEFAULT 0,
    queries_timeout   INTEGER NOT NULL DEFAULT 0,
    queries_abandoned INTEGER NOT NULL DEFAULT 0,
    queries_skipped   INTEGER NOT NULL DEFAULT 0,
    records_received  INTEGER NOT NULL DEFAULT 0,
    records_new       INTEGER NOT NULL DEFAULT 0,
    note              TEXT
);

CREATE TABLE IF NOT EXISTS queries (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES collection_runs(id),
    keyword         TEXT NOT NULL,
    role            TEXT NOT NULL,
    query           TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT NOT NULL,
    duration_s      REAL NOT NULL,
    outcome         TEXT NOT NULL CHECK (outcome IN
                      ('ok','ok_empty','abandoned','timeout','http_error',
                       'network_error','parse_error','too_large','skipped')),
    http_status     INTEGER,
    attempts        INTEGER NOT NULL,
    bytes           INTEGER,
    response_sha256 TEXT,
    records         INTEGER,
    records_new     INTEGER,
    records_invalid INTEGER,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_queries_run ON queries(run_id);

CREATE TABLE IF NOT EXISTS source_records (
    id             INTEGER PRIMARY KEY,
    source_id      TEXT NOT NULL REFERENCES sources(id),
    record_key     TEXT NOT NULL,
    external_id    TEXT,
    run_id         INTEGER NOT NULL REFERENCES collection_runs(id),
    query_id       INTEGER NOT NULL REFERENCES queries(id),
    fetched_at     TEXT NOT NULL,
    payload        TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    UNIQUE (source_id, record_key)
);

CREATE TABLE IF NOT EXISTS dns_observations (
    id         INTEGER PRIMARY KEY,
    run_id     INTEGER NOT NULL REFERENCES collection_runs(id),
    domain     TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    resolver   TEXT NOT NULL,
    outcome    TEXT NOT NULL CHECK (outcome IN
                 ('resolved','nxdomain','no_address','temporary_failure','failure','timeout')),
    addresses  TEXT NOT NULL,
    error      TEXT
);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_observations(domain, id);

-- normalised index, derived from source_records -----------------------------
CREATE TABLE IF NOT EXISTS domains (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    registrable     TEXT NOT NULL,
    suffix          TEXT NOT NULL,
    first_seen_at   TEXT NOT NULL,
    first_record_id INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_domains_reg ON domains(registrable);

CREATE TABLE IF NOT EXISTS certificates (
    id              INTEGER PRIMARY KEY,
    cert_key        TEXT NOT NULL UNIQUE,
    issuer_ca_id    INTEGER,
    issuer_name     TEXT,
    serial          TEXT,
    common_name     TEXT,
    not_before      TEXT,
    not_after       TEXT,
    first_seen_at   TEXT NOT NULL,
    first_record_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cert_records (
    certificate_id INTEGER NOT NULL REFERENCES certificates(id),
    record_id      INTEGER NOT NULL REFERENCES source_records(id),
    crtsh_id       INTEGER NOT NULL,
    PRIMARY KEY (certificate_id, record_id)
);

CREATE TABLE IF NOT EXISTS cert_names (
    certificate_id  INTEGER NOT NULL REFERENCES certificates(id),
    domain_id       INTEGER NOT NULL REFERENCES domains(id),
    wildcard        INTEGER NOT NULL,
    via             TEXT NOT NULL CHECK (via IN ('matched_identity','common_name')),
    first_record_id INTEGER NOT NULL,
    PRIMARY KEY (certificate_id, domain_id, wildcard, via)
);
CREATE INDEX IF NOT EXISTS idx_cert_names_domain ON cert_names(domain_id);

-- analyses -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analysis_runs (
    id                    INTEGER PRIMARY KEY,
    created_at            TEXT NOT NULL,
    as_of                 TEXT NOT NULL,
    status                TEXT NOT NULL CHECK (status IN ('running','complete','failed')),
    software_version      TEXT NOT NULL,
    rules_version         TEXT NOT NULL,
    correlation_config    TEXT NOT NULL,
    correlation_sha256    TEXT NOT NULL,
    cutoff_run_id         INTEGER NOT NULL,
    cutoff_record_id      INTEGER NOT NULL,
    cutoff_dns_id         INTEGER NOT NULL,
    dataset_sha256        TEXT,
    results_sha256        TEXT,
    domains_total         INTEGER,
    domains_flagged       INTEGER,
    campaigns_total       INTEGER,
    duration_s            REAL,
    derived_pruned        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS decisions (
    analysis_id  INTEGER NOT NULL REFERENCES analysis_runs(id),
    domain_id    INTEGER NOT NULL REFERENCES domains(id),
    score        INTEGER NOT NULL,
    verdict      TEXT NOT NULL,
    brands       TEXT NOT NULL,
    corroborated INTEGER NOT NULL,
    first_issued TEXT,
    PRIMARY KEY (analysis_id, domain_id)
);
CREATE INDEX IF NOT EXISTS idx_decisions_verdict ON decisions(analysis_id, verdict, score);

CREATE TABLE IF NOT EXISTS signals (
    analysis_id INTEGER NOT NULL,
    domain_id   INTEGER NOT NULL,
    rule        TEXT NOT NULL,
    points      INTEGER NOT NULL,
    corroborating INTEGER NOT NULL,
    detail      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_signals_domain ON signals(analysis_id, domain_id);

CREATE TABLE IF NOT EXISTS indicators (
    analysis_id INTEGER NOT NULL,
    id          INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    class       TEXT NOT NULL,
    df          INTEGER NOT NULL,
    weight      REAL NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('active','suppressed_hub','singleton')),
    PRIMARY KEY (analysis_id, id)
);

CREATE TABLE IF NOT EXISTS domain_indicators (
    analysis_id  INTEGER NOT NULL,
    domain_id    INTEGER NOT NULL,
    indicator_id INTEGER NOT NULL,
    PRIMARY KEY (analysis_id, domain_id, indicator_id)
);
CREATE INDEX IF NOT EXISTS idx_di_ind ON domain_indicators(analysis_id, indicator_id);

CREATE TABLE IF NOT EXISTS relationships (
    analysis_id INTEGER NOT NULL,
    id          INTEGER NOT NULL,
    a_domain_id INTEGER NOT NULL,
    b_domain_id INTEGER NOT NULL,
    weight      REAL NOT NULL,
    kinds       TEXT NOT NULL,
    accepted    INTEGER NOT NULL,
    strength    TEXT NOT NULL,
    reason      TEXT NOT NULL,
    PRIMARY KEY (analysis_id, id)
);
CREATE INDEX IF NOT EXISTS idx_rel_a ON relationships(analysis_id, a_domain_id);
CREATE INDEX IF NOT EXISTS idx_rel_b ON relationships(analysis_id, b_domain_id);

CREATE TABLE IF NOT EXISTS relationship_evidence (
    analysis_id     INTEGER NOT NULL,
    relationship_id INTEGER NOT NULL,
    indicator_id    INTEGER NOT NULL,
    weight          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rev ON relationship_evidence(analysis_id, relationship_id);

CREATE TABLE IF NOT EXISTS campaigns (
    analysis_id  INTEGER NOT NULL,
    id           TEXT NOT NULL,
    rank         INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    edges        INTEGER NOT NULL,
    density      REAL NOT NULL,
    cohesion     REAL NOT NULL,
    min_weight   REAL NOT NULL,
    tier         TEXT NOT NULL CHECK (tier IN ('strong','corroborated','chained')),
    brands       TEXT NOT NULL,
    first_issued TEXT,
    last_issued  TEXT,
    PRIMARY KEY (analysis_id, id)
);

CREATE TABLE IF NOT EXISTS campaign_members (
    analysis_id INTEGER NOT NULL,
    campaign_id TEXT NOT NULL,
    domain_id   INTEGER NOT NULL,
    PRIMARY KEY (analysis_id, campaign_id, domain_id)
);
CREATE INDEX IF NOT EXISTS idx_cm_domain ON campaign_members(analysis_id, domain_id);

CREATE TABLE IF NOT EXISTS snapshots (
    id             INTEGER PRIMARY KEY,
    created_at     TEXT NOT NULL,
    analysis_id    INTEGER NOT NULL REFERENCES analysis_runs(id),
    dataset_sha256 TEXT NOT NULL,
    file_name      TEXT NOT NULL,
    file_sha256    TEXT NOT NULL,
    bytes          INTEGER NOT NULL
);
"""

SCHEMA_VERSION = "1"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str | os.PathLike, *, readonly: bool = False) -> sqlite3.Connection:
    """Open the database. Read-only connections cannot write even if a bug tries to."""
    if readonly:
        uri = Path(path).resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        conn.execute("PRAGMA query_only = ON")
    else:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA)
        conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                     (SCHEMA_VERSION,))
        from .sources import register_all
        register_all(conn)
        conn.commit()
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


class LockBusy(RuntimeError):
    """Another trawl writer holds the lock."""


@contextmanager
def writer_lock(db_path: str | os.PathLike):
    """One writer at a time. Held for the whole of collect / dnscheck / analyze.

    It also makes stale-run recovery safe: while the lock is held, any run still
    marked 'running' belongs to a process that died, never to a live one.
    """
    lock_path = Path(str(db_path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "w")
    try:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LockBusy("another trawl writer is running (lock held)") from None
        yield
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


def recover_interrupted(conn: sqlite3.Connection) -> int:
    """Mark runs left 'running' by a killed process. Call only under writer_lock."""
    cur = conn.execute(
        "UPDATE collection_runs SET status='interrupted', finished_at=?,"
        " note=COALESCE(note,'') || 'process ended before the run finished' "
        "WHERE status='running'", (utcnow(),))
    conn.execute("UPDATE analysis_runs SET status='failed' WHERE status='running'")
    conn.commit()
    return cur.rowcount
