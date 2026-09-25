"""Source adapters.

An adapter is a module that exposes `SOURCE` (its provenance description, stored in
the `sources` table) and a fetch function that returns classified outcomes rather
than raising or returning an empty list on failure. Adding a source means adding a
module here and a collector step in collect.py; nothing else changes.
"""
from __future__ import annotations

import sqlite3

from . import crtsh, dns

ADAPTERS = (crtsh, dns)


def register_all(conn: sqlite3.Connection) -> None:
    for mod in ADAPTERS:
        s = mod.SOURCE
        conn.execute(
            "INSERT INTO sources(id, name, kind, endpoint, description, provenance)"
            " VALUES (:id, :name, :kind, :endpoint, :description, :provenance)"
            " ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind,"
            " endpoint=excluded.endpoint, description=excluded.description,"
            " provenance=excluded.provenance", s)
