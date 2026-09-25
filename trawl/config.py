"""Configuration: built-in defaults, optionally overridden by one JSON file.

Unknown keys and wrong types are rejected rather than ignored - a typo in a
threshold must not silently fall back to a default and change results unnoticed.
Everything that changes analysis results (the `correlation` section) is
fingerprinted into each analysis record.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os

DEFAULTS: dict = {
    "db_path": "data/trawl.db",
    "snapshot_dir": "data/snapshots",
    "collection": {
        # Enforced in code, not only by the timer: a cycle that starts sooner than
        # this after the previous crt.sh run is refused (use --force to override).
        "min_interval_hours": 6.0,
        # crt.sh routinely takes 30-60 s for an ordinary prefix query. A shorter
        # timeout turns slow answers into self-inflicted "failures".
        "request_timeout_s": 150.0,
        "max_attempts": 3,
        "backoff_base_s": 10.0,
        "backoff_max_s": 180.0,
        "pace_s": 6.0,               # minimum gap between any two requests
        "max_run_minutes": 180.0,    # remaining queries are recorded as skipped
        "max_response_mb": 256,
    },
    "dns": {
        "max_per_run": 600,
        "workers": 8,
        "timeout_s": 12.0,
        "recheck_hours": 20.0,
    },
    "analysis": {
        "keep_derived": 4,           # analyses whose derived rows are kept
    },
    "snapshots": {
        "interval_hours": 24.0,
        "keep": 14,
    },
    "correlation": {
        "population": ["likely", "possible", "lead"],
        "min_edge": 2.0,
        "min_kinds": 2,
        "require_non_weak": True,
        "small_corpus": 30,
        "chained_density": 0.34,
        "kinds": {
            "same_registrable": {"class": "strong", "base": 10.0, "max_df": 150},
            "shared_certificate": {"class": "strong", "base": 8.0, "max_df": 40},
            "shared_ip": {"class": "medium", "base": 2.5, "max_df": 15},
            "kit_shape": {"class": "medium", "base": 2.5, "max_df": 40},
            "issuance_day": {"class": "weak", "base": 1.0, "max_df": 25},
            "brand": {"class": "weak", "base": 1.0, "max_df": 25},
            "lure": {"class": "weak", "base": 0.8, "max_df": 25},
            "platform": {"class": "weak", "base": 0.4, "max_df": 8},
            "tld": {"class": "weak", "base": 0.3, "max_df": 8},
        },
    },
}


def load(path: str | None = None) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    path = path or os.environ.get("TRAWL_CONFIG")
    if path:
        with open(path, encoding="utf-8") as fh:
            override = json.load(fh)
        if not isinstance(override, dict):
            raise ValueError("config file must contain a JSON object")
        _merge(cfg, override, "")
    _validate(cfg)
    return cfg


def _merge(base: dict, over: dict, where: str) -> None:
    for key, val in over.items():
        if key not in base:
            raise ValueError(f"unknown config key: {where}{key}")
        cur = base[key]
        if isinstance(cur, dict):
            if not isinstance(val, dict):
                raise ValueError(f"{where}{key}: expected an object")
            _merge(cur, val, f"{where}{key}.")
        elif isinstance(cur, float) and isinstance(val, int) and not isinstance(val, bool):
            base[key] = float(val)
        elif type(val) is not type(cur):
            raise ValueError(f"{where}{key}: expected {type(cur).__name__}")
        else:
            base[key] = val


def _validate(cfg: dict) -> None:
    c = cfg["correlation"]
    if c["min_edge"] <= 0:
        raise ValueError("correlation.min_edge must be positive; 0 would merge everything")
    if c["min_kinds"] < 1:
        raise ValueError("correlation.min_kinds must be at least 1")
    for name, k in c["kinds"].items():
        if k["class"] not in ("strong", "medium", "weak"):
            raise ValueError(f"correlation.kinds.{name}.class must be strong|medium|weak")
        if k["max_df"] < 2 or k["base"] < 0:
            raise ValueError(f"correlation.kinds.{name}: max_df >= 2 and base >= 0 required")
    if cfg["collection"]["pace_s"] < 1:
        raise ValueError("collection.pace_s below 1 s would hammer a free shared service")


def canonical(obj) -> str:
    """The one serialisation used for every fingerprint in the project."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_of(obj) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()
