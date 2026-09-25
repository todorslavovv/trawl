"""crt.sh - a public search index over Certificate Transparency logs.

Why an index and not the logs: following a single CT log in full is roughly
27 GB/day at ~5.5 kB per entry, which a home connection cannot sustain. crt.sh has
already indexed the same logs and answers a keyword query in one request, so
bandwidth scales with matches rather than with global issuance.

What this module guarantees: every request ends in exactly one classified outcome.
A failure is never reported as "no results". Specifically:

    ok           HTTP 200, valid JSON list, at least one record
    ok_empty     HTTP 200, valid empty JSON list (may later be re-classified as
                 'abandoned' by the collector's consistency check)
    timeout      no complete response within the timeout, after all attempts
    http_error   non-200 status after all attempts (5xx, 429, 4xx)
    network_error connection/TLS/DNS failure after all attempts
    parse_error  200 but the body is not a JSON list (crt.sh serves HTML error
                 pages with status 200 when overloaded)
    too_large    body exceeded the configured cap; nothing from it is used

The only host ever contacted is BASE_URL. Query text is URL-encoded into the
query string; no caller can make this module fetch another URL.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import random
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .. import VERSION

BASE_URL = "https://crt.sh/"
USER_AGENT = f"trawl/{VERSION} (CT keyword collector; 1 request per few seconds)"

SOURCE = {
    "id": "crtsh",
    "name": "crt.sh Certificate Transparency search",
    "kind": "certificate-transparency",
    "endpoint": BASE_URL + "?q=<pattern>&output=json",
    "description": (
        "Public search index over Certificate Transparency logs, operated by Sectigo. "
        "Queried by keyword with SQL LIKE patterns. Each JSON record describes one "
        "logged certificate (precertificate and final certificate are separate "
        "records) and lists only the identities on it that matched the query."),
    "provenance": (
        "Every response is stored verbatim per record (canonical JSON + SHA-256), "
        "with the run, query, pattern, HTTP status, attempt count, byte count and "
        "response hash that produced it. No API key or account is used."),
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the collector talks to crt.sh and nothing else.
    A 3xx surfaces as an HTTPError and is classified like any other failure."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))


@dataclass
class QueryResult:
    outcome: str
    http_status: int | None = None
    attempts: int = 0
    records: list = field(default_factory=list)
    bytes: int | None = None
    response_sha256: str | None = None
    error: str | None = None
    duration_s: float = 0.0


class Client:
    """Paced, retrying crt.sh client. One instance per collection run.

    `opener` and `sleep`/`clock` are injectable so tests exercise every failure
    path without touching the network.
    """

    def __init__(self, *, timeout_s: float, max_attempts: int, backoff_base_s: float,
                 backoff_max_s: float, pace_s: float, max_bytes: int,
                 opener=None, sleep=time.sleep, clock=time.monotonic, rng=None):
        self.timeout_s = timeout_s
        self.max_attempts = max(1, max_attempts)
        self.backoff_base_s = backoff_base_s
        self.backoff_max_s = backoff_max_s
        self.pace_s = pace_s
        self.max_bytes = max_bytes
        self._open = opener or self._default_open
        self._sleep = sleep
        self._clock = clock
        self._rng = rng or random.Random()
        self._last_request = None

    # -- transport -------------------------------------------------------
    @staticmethod
    def _default_open(url: str, timeout: float):
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT, "Accept": "application/json"})
        return _OPENER.open(req, timeout=timeout)

    def _pace(self) -> None:
        if self._last_request is not None:
            wait = self.pace_s - (self._clock() - self._last_request)
            if wait > 0:
                self._sleep(wait)
        self._last_request = self._clock()

    def _backoff(self, attempt: int, retry_after: float | None) -> None:
        if retry_after is not None:
            delay = min(retry_after, self.backoff_max_s)
        else:
            delay = min(self.backoff_base_s * (2 ** attempt), self.backoff_max_s)
            delay *= 0.75 + self._rng.random() / 2      # jitter, +-25 %
        self._sleep(delay)

    # -- one query -------------------------------------------------------
    def search(self, pattern: str) -> QueryResult:
        url = BASE_URL + "?" + urllib.parse.urlencode({"q": pattern, "output": "json"})
        t0 = self._clock()
        res = QueryResult(outcome="network_error")
        for attempt in range(self.max_attempts):
            res.attempts = attempt + 1
            self._pace()
            retry_after = None
            try:
                with self._open(url, self.timeout_s) as resp:
                    status = getattr(resp, "status", 200)
                    body = resp.read(self.max_bytes + 1)
                res.http_status = status
                if len(body) > self.max_bytes:
                    res.outcome, res.error = "too_large", f"body over {self.max_bytes} bytes"
                    res.bytes = len(body)
                    break                                # retrying will not shrink it
                res.bytes = len(body)
                res.response_sha256 = hashlib.sha256(body).hexdigest()
                outcome, error, data = None, None, None
                if not body.strip():
                    # An empty body is not an empty list: crt.sh gave us nothing.
                    outcome, error = "parse_error", "empty body"
                else:
                    try:
                        data = json.loads(body)
                    except (ValueError, UnicodeDecodeError) as e:
                        outcome, error = "parse_error", f"invalid JSON: {str(e)[:100]}"
                if outcome is None and not isinstance(data, list):
                    outcome, error = "parse_error", "JSON is not a list"
                if outcome is None:
                    res.records = data
                    res.outcome = "ok" if data else "ok_empty"
                    res.error = None
                    break
                res.outcome, res.error = outcome, error
            except urllib.error.HTTPError as e:
                res.http_status = e.code
                res.outcome, res.error = "http_error", f"HTTP {e.code}"
                ra = e.headers.get("Retry-After") if e.headers else None
                if ra and ra.strip().isdigit():
                    retry_after = float(ra.strip())
                if e.code in (400, 414):
                    break                                # our request is malformed; do not retry
                # Everything else is retried: crt.sh has been observed answering a
                # valid search with 404 and then 200 for the same URL minutes later.
            except (TimeoutError, socket.timeout) as e:
                res.outcome, res.error = "timeout", f"no response within {self.timeout_s:.0f} s"
            except urllib.error.URLError as e:
                if isinstance(e.reason, (TimeoutError, socket.timeout)):
                    res.outcome, res.error = "timeout", f"no response within {self.timeout_s:.0f} s"
                else:
                    res.outcome, res.error = "network_error", str(e.reason)[:160]
            except (OSError, ValueError, http.client.HTTPException) as e:
                res.outcome, res.error = "network_error", f"{type(e).__name__}: {str(e)[:140]}"
            if attempt + 1 < self.max_attempts:
                self._backoff(attempt, retry_after)
        res.duration_s = round(self._clock() - t0, 3)
        return res
