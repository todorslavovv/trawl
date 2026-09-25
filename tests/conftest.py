"""Shared fixtures. No test touches the network: crt.sh and DNS are faked."""
from __future__ import annotations

import itertools
import socket
from datetime import datetime, timedelta, timezone

import pytest

from trawl import config as C
from trawl.db import connect
from trawl.sources.crtsh import QueryResult

AS_OF = "2026-09-26T00:00:00+00:00"
_ids = itertools.count(10_000)


def rec(names, *, cn=None, serial=None, nb=None, ca=1, rid=None):
    """A crt.sh-shaped JSON record. not_before defaults to 5 days ago (relative to the
    real clock, because collection-time truncation checks use the real clock)."""
    if nb is None:
        nb = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S")
    i = rid if rid is not None else next(_ids)
    return {"id": i, "issuer_ca_id": ca, "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
            "common_name": cn if cn is not None else names[0].lstrip("*."),
            "name_value": "\n".join(names), "not_before": nb,
            "not_after": "2026-12-19T10:00:00", "serial_number": serial or f"0a{i:x}",
            "result_count": len(names)}


class FakeCrtsh:
    """Maps a pattern to records, or to a failure outcome string."""

    def __init__(self, data: dict):
        self.data = data
        self.calls: list = []
        self.exclude_expired: list = []

    def search(self, pattern, exclude_expired=True):
        self.calls.append(pattern)
        self.exclude_expired.append(exclude_expired)
        v = self.data.get(pattern, [])
        if isinstance(v, str):
            return QueryResult(outcome=v, attempts=3, error=f"simulated {v}")
        return QueryResult(outcome="ok" if v else "ok_empty", http_status=200, attempts=1,
                           records=v, bytes=100)


def fake_resolver(table: dict):
    """getaddrinfo stand-in: name -> list of IPs, or an EAI_* error code."""
    def resolve(host, port, type=None):
        v = table.get(host, socket.EAI_NONAME)
        if isinstance(v, int):
            raise socket.gaierror(v, "simulated")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in v]
    return resolve


@pytest.fixture
def cfg(tmp_path):
    c = C.load()
    c["db_path"] = str(tmp_path / "t.db")
    c["snapshot_dir"] = str(tmp_path / "snaps")
    c["collection"]["min_interval_hours"] = 0.0
    return c


@pytest.fixture
def conn(cfg):
    c = connect(cfg["db_path"])
    yield c
    c.close()
