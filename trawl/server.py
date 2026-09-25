"""Read-only web UI and JSON API.

Attack-surface decisions, each deliberate:
  * stdlib ThreadingHTTPServer bound to 127.0.0.1 by default; public access, if any,
    goes through a tunnel to that loopback port;
  * GET/HEAD only - every other method is 405; there is no write endpoint at all;
  * the database is opened read-only (mode=ro + PRAGMA query_only);
  * static assets are three files loaded into memory at start-up, looked up by exact
    path - no URL is ever mapped onto the filesystem, so traversal has nothing to reach;
  * every parameter is length-limited and parsed into int / enum / validated name;
    all SQL is parameterised; LIKE wildcards in user text are escaped;
  * errors return a fixed message; tracebacks go to the service log only;
  * a strict Content-Security-Policy: the page may load nothing and connect nowhere
    except this origin - no fonts, CDNs, analytics or inline script.
"""
from __future__ import annotations

import json
import sys
import threading
import traceback
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import VERSION, rules
from .db import connect
from .names import normalise

WEB = Path(__file__).parent / "web"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8")}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}

NETWORK = [
    {"from": "collector", "to": "https://crt.sh/ (TLS, certificate verified)",
     "purpose": "Certificate Transparency keyword queries", "when": "each collection run",
     "note": "the only HTTP destination in the code; paced, retried with backoff"},
    {"from": "collector", "to": "host DNS resolver (systemd-resolved stub, then its upstream)",
     "purpose": "re-check whether flagged names resolve", "when": "each cycle",
     "note": "name lookups only; no connection is made to resolved addresses"},
    {"from": "browser", "to": "this server (same origin)", "purpose": "UI assets and JSON API",
     "when": "always", "note": "enforced by Content-Security-Policy; no fonts, CDNs or analytics"},
    {"from": "browser", "to": "https://crt.sh/", "purpose": "outbound certificate links",
     "when": "only if the investigator clicks one", "note": "rel=noopener noreferrer"},
    {"from": "deployment", "to": "Cloudflare edge (trycloudflare.com Quick Tunnel)",
     "purpose": "temporary public demo access", "when": "only where the tunnel service runs",
     "note": "Cloudflare terminates TLS and sees the traffic it relays"},
]

GLOSSARY = [
    ["Observation", "A recorded fact about a public record: crt.sh returned certificate X "
                    "listing name Y in run Z; the resolver answered NXDOMAIN at time T."],
    ["Signal", "A named scoring rule that fired on a name, with its points and the text it matched."],
    ["Relationship", "Two flagged names sharing indicators, with the evidence and a weight. "
                     "Accepted only if strong, or corroborated by several independent kinds."],
    ["Campaign hypothesis", "A connected group of accepted relationships. A lead for an "
                            "investigator - not proof of common ownership, and never attribution."],
    ["Verified fact", "Nothing this system outputs. Verification (content capture, registrar or "
                      "hosting records, legal process) happens outside it."],
]


class BadRequest(Exception):
    pass


class NotFound(Exception):
    pass


# -- parameter parsing ---------------------------------------------------------------
def _one(p: dict, key: str) -> str | None:
    v = p.get(key)
    return v[0] if v else None


def p_int(p, key, default, lo, hi) -> int:
    v = _one(p, key)
    if v is None or v == "":
        return default
    if not v.isdigit() or len(v) > 9:
        raise BadRequest(f"{key} must be an integer")
    n = int(v)
    if not lo <= n <= hi:
        raise BadRequest(f"{key} must be between {lo} and {hi}")
    return n


def p_enum(p, key, allowed, default=None):
    v = _one(p, key)
    if v is None or v == "":
        return default
    if v not in allowed:
        raise BadRequest(f"{key} must be one of: {', '.join(sorted(allowed))}")
    return v


def p_text(p, key, maxlen=100) -> str:
    v = (_one(p, key) or "").strip().lower()
    if len(v) > maxlen:
        raise BadRequest(f"{key} too long")
    return v


def p_name(p, key="name") -> str:
    v = p_text(p, key, 253)
    norm = normalise(v)
    if not norm:
        raise BadRequest(f"{key} is not a valid domain name")
    return norm[0]


def like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# -- API -------------------------------------------------------------------------------
class Api:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()

    @property
    def db(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = connect(self.db_path, readonly=True)
            self._local.conn = c
        return c

    def q(self, sql, *args):
        return self.db.execute(sql, args).fetchall()

    def one(self, sql, *args):
        return self.db.execute(sql, args).fetchone()

    def analysis(self):
        a = self.one("SELECT * FROM analysis_runs WHERE status='complete' AND derived_pruned=0"
                     " ORDER BY id DESC LIMIT 1")
        if a is None:
            raise NotFound("no analysis has completed yet")
        return a

    def provenance(self, a) -> dict:
        return {"analysis_id": a["id"], "as_of": a["as_of"], "created_at": a["created_at"],
                "software_version": a["software_version"], "rules_version": a["rules_version"],
                "correlation_sha256": a["correlation_sha256"],
                "dataset_sha256": a["dataset_sha256"], "results_sha256": a["results_sha256"],
                "cutoffs": {"run": a["cutoff_run_id"], "record": a["cutoff_record_id"],
                            "dns": a["cutoff_dns_id"]}}

    # /api/meta ---------------------------------------------------------------------
    def meta(self, p):
        a = self.analysis()
        return {"version": VERSION, "provenance": self.provenance(a),
                "brands": {b: {"label": s["label"], "sector": s["sector"]}
                           for b, s in rules.BRANDS.items()},
                "verdicts": rules.VERDICT_TEXT}

    # /api/overview -----------------------------------------------------------------
    def overview(self, p):
        a = self.analysis()
        aid = a["id"]
        verdicts = {r[0]: r[1] for r in self.q(
            "SELECT verdict, COUNT(*) FROM decisions WHERE analysis_id=? GROUP BY verdict", aid)}
        pop = ("likely", "possible", "lead")
        now = datetime.now(timezone.utc)
        d7 = (now - timedelta(days=7)).isoformat()
        d30 = (now - timedelta(days=30)).isoformat()[:10]
        new7 = self.one(
            "SELECT COUNT(*) FROM decisions x JOIN domains d ON d.id=x.domain_id WHERE"
            " x.analysis_id=? AND x.verdict IN ('likely','possible','lead') AND d.first_seen_at>=?",
            aid, d7)[0]
        issued30 = self.one(
            "SELECT COUNT(*) FROM decisions WHERE analysis_id=? AND verdict IN"
            " ('likely','possible','lead') AND first_issued>=?", aid, d30)[0]
        dns = {r[0] or "unchecked": r[1] for r in self.q(
            "WITH latest AS (SELECT domain, outcome, MAX(id) FROM dns_observations GROUP BY domain)"
            " SELECT l.outcome, COUNT(*) FROM decisions x JOIN domains d ON d.id=x.domain_id"
            " LEFT JOIN latest l ON l.domain=d.name WHERE x.analysis_id=? AND x.verdict IN"
            " ('likely','possible','lead') GROUP BY l.outcome", aid)}
        tiers = {r[0]: r[1] for r in self.q(
            "SELECT tier, COUNT(*) FROM campaigns WHERE analysis_id=? GROUP BY tier", aid)}
        # weekly issuance of flagged names' first certificate, last 52 weeks
        start = (now - timedelta(weeks=52)).date()
        start = start - timedelta(days=start.weekday())
        weeks = defaultdict(lambda: {"likely": 0, "possible": 0, "lead": 0})
        for fi, v in self.q("SELECT first_issued, verdict FROM decisions WHERE analysis_id=?"
                            " AND verdict IN ('likely','possible','lead') AND first_issued>=?",
                            aid, start.isoformat()):
            d = datetime.fromisoformat(fi[:10]).date()
            wk = d - timedelta(days=d.weekday())
            weeks[wk.isoformat()][v] += 1
        series = []
        wk = start
        while wk <= now.date():
            series.append({"week": wk.isoformat(), **weeks[wk.isoformat()]})
            wk += timedelta(weeks=1)
        brands = defaultdict(lambda: {"likely": 0, "possible": 0})
        for b, v in self.q("SELECT brands, verdict FROM decisions WHERE analysis_id=?"
                           " AND verdict IN ('likely','possible')", aid):
            for x in json.loads(b):
                brands[x][v] += 1
        brand_rows = sorted(({"brand": k, "label": rules.BRANDS[k]["label"], **v}
                             for k, v in brands.items()),
                            key=lambda r: -(r["likely"] + r["possible"]))
        recent = self._domain_rows(aid, "x.verdict IN ('likely','possible','lead')", (),
                                   "d.first_seen_at DESC, x.score DESC", 12, 0)
        return {"provenance": self.provenance(a),
                "verdicts": verdicts, "flagged": sum(verdicts.get(v, 0) for v in pop),
                "new_7d": new7, "issued_30d": issued30, "dns": dns, "campaign_tiers": tiers,
                "weekly_issuance": series, "brands": brand_rows, "recent": recent,
                "collection": self._health(),
                "top_campaigns": [dict(r) | {"brands": json.loads(r["brands"])} for r in self.q(
                    "SELECT id, rank, size, tier, density, cohesion, brands, first_issued,"
                    " last_issued FROM campaigns WHERE analysis_id=? ORDER BY rank LIMIT 6", aid)]}

    def _health(self):
        runs = [dict(r) for r in self.q(
            "SELECT id, source_id, started_at, finished_at, status, queries_requested,"
            " queries_ok, queries_empty, queries_failed, queries_timeout, queries_abandoned,"
            " queries_skipped, records_received, records_new, note FROM collection_runs"
            " ORDER BY id DESC LIMIT 40")]
        for r in runs:
            r["duration_s"] = _dur(r["started_at"], r["finished_at"])
            r["note"] = _json_or_none(r["note"])
        crt = [r for r in runs if r["source_id"] == "crtsh"]
        return {"runs": runs, "last_crtsh": crt[0] if crt else None}

    # /api/domains ------------------------------------------------------------------
    def _domain_rows(self, aid, where, args, order, limit, offset):
        rows = self.q(
            "WITH latest AS (SELECT domain, outcome, checked_at, MAX(id) FROM dns_observations"
            " GROUP BY domain)"
            " SELECT d.name, d.registrable, d.first_seen_at, x.score, x.verdict, x.brands,"
            " x.first_issued, l.outcome dns, l.checked_at dns_at, cm.campaign_id"
            " FROM decisions x JOIN domains d ON d.id=x.domain_id"
            " LEFT JOIN latest l ON l.domain=d.name"
            " LEFT JOIN campaign_members cm ON cm.analysis_id=x.analysis_id AND cm.domain_id=d.id"
            f" WHERE x.analysis_id=? AND {where} ORDER BY {order} LIMIT ? OFFSET ?",
            aid, *args, limit, offset)
        return [dict(r) | {"brands": json.loads(r["brands"])} for r in rows]

    def domains(self, p):
        a = self.analysis()
        verdicts = [v for v in (p_text(p, "verdict", 80) or "likely,possible,lead").split(",") if v]
        if not verdicts or any(v not in rules.VERDICTS for v in verdicts):
            raise BadRequest("verdict must be a comma list of: " + ", ".join(rules.VERDICTS))
        where = [f"x.verdict IN ({','.join('?' * len(verdicts))})"]
        args: list = list(verdicts)
        q = p_text(p, "q", 100)
        if q:
            where.append("d.name LIKE ? ESCAPE '\\'")
            args.append(f"%{like_escape(q)}%")
        brand = p_enum(p, "brand", set(rules.BRANDS))
        if brand:
            where.append("x.brands LIKE ?")
            args.append(f'%"{brand}"%')
        dns = p_enum(p, "dns", {"resolved", "nxdomain", "no_address", "failed", "unchecked"})
        if dns == "unchecked":
            where.append("l.outcome IS NULL")
        elif dns == "failed":
            where.append("l.outcome IN ('temporary_failure','failure','timeout')")
        elif dns:
            where.append("l.outcome = ?")
            args.append(dns)
        days = p_int(p, "since_days", 0, 0, 36500)
        if days:
            field = p_enum(p, "since_field", {"first_seen", "first_issued"}, "first_seen")
            col = "d.first_seen_at" if field == "first_seen" else "x.first_issued"
            where.append(f"{col} >= ?")
            args.append((datetime.now(timezone.utc) - timedelta(days=days)).isoformat()[:19])
        if p_enum(p, "campaign", {"yes", "no"}) == "yes":
            where.append("cm.campaign_id IS NOT NULL")
        sort = p_enum(p, "sort", {"score", "first_seen", "first_issued", "name"}, "score")
        order = p_enum(p, "order", {"asc", "desc"}, "desc").upper()
        col = {"score": "x.score", "first_seen": "d.first_seen_at",
               "first_issued": "x.first_issued", "name": "d.name"}[sort]
        order_sql = f"{col} {order}, d.name ASC"
        limit = p_int(p, "limit", 100, 1, 500)
        offset = p_int(p, "offset", 0, 0, 10_000_000)
        w = " AND ".join(where)
        total = self.one(
            "WITH latest AS (SELECT domain, outcome, MAX(id) FROM dns_observations GROUP BY domain)"
            " SELECT COUNT(*) FROM decisions x JOIN domains d ON d.id=x.domain_id"
            " LEFT JOIN latest l ON l.domain=d.name"
            " LEFT JOIN campaign_members cm ON cm.analysis_id=x.analysis_id AND cm.domain_id=d.id"
            f" WHERE x.analysis_id=? AND {w}", a["id"], *args)[0]
        return {"total": total, "limit": limit, "offset": offset,
                "rows": self._domain_rows(a["id"], w, tuple(args), order_sql, limit, offset)}

    # /api/domain -------------------------------------------------------------------
    def domain(self, p):
        a = self.analysis()
        aid = a["id"]
        name = p_name(p)
        d = self.one("SELECT * FROM domains WHERE name=?", name)
        if d is None:
            raise NotFound("unknown domain")
        dec = self.one("SELECT * FROM decisions WHERE analysis_id=? AND domain_id=?", aid, d["id"])
        sig = [dict(r) for r in self.q(
            "SELECT rule, points, corroborating, detail FROM signals WHERE analysis_id=? AND"
            " domain_id=? ORDER BY points DESC, rule", aid, d["id"])]
        for s in sig:
            s["text"] = rules.RULES.get(s["rule"], {}).get("text", "")
        certs = [dict(r) for r in self.q(
            "SELECT c.id, c.cert_key, c.issuer_name, c.serial, c.common_name, c.not_before,"
            " c.not_after, c.first_seen_at, MAX(cn.wildcard) wildcard,"
            " GROUP_CONCAT(DISTINCT cn.via) via,"
            " (SELECT COUNT(DISTINCT domain_id) FROM cert_names WHERE certificate_id=c.id) names"
            " FROM cert_names cn JOIN certificates c ON c.id=cn.certificate_id"
            " WHERE cn.domain_id=? GROUP BY c.id ORDER BY c.not_before DESC", d["id"])]
        for c in certs:
            c["crtsh_ids"] = [r[0] for r in self.q(
                "SELECT crtsh_id FROM cert_records WHERE certificate_id=? ORDER BY crtsh_id", c["id"])]
        dns = [dict(r) | {"addresses": json.loads(r["addresses"])} for r in self.q(
            "SELECT id, run_id, checked_at, resolver, outcome, addresses, error"
            " FROM dns_observations WHERE domain=? ORDER BY id DESC LIMIT 200", name)]
        records = [dict(r) for r in self.q(
            "SELECT DISTINCT s.id, s.external_id crtsh_id, s.run_id, s.fetched_at, s.payload_sha256,"
            " q.query, q.role, q.outcome FROM cert_names cn"
            " JOIN cert_records cr ON cr.certificate_id=cn.certificate_id"
            " JOIN source_records s ON s.id=cr.record_id JOIN queries q ON q.id=s.query_id"
            " WHERE cn.domain_id=? ORDER BY s.id LIMIT 200", d["id"])]
        rels = self._relationships(aid, "(r.a_domain_id=? OR r.b_domain_id=?)", (d["id"], d["id"]),
                                   limit=120)
        camp = self.one("SELECT c.* FROM campaign_members m JOIN campaigns c ON"
                        " c.analysis_id=m.analysis_id AND c.id=m.campaign_id"
                        " WHERE m.analysis_id=? AND m.domain_id=?", aid, d["id"])
        inds = [dict(r) for r in self.q(
            "SELECT i.kind, i.value, i.class, i.df, i.weight, i.status FROM domain_indicators di"
            " JOIN indicators i ON i.analysis_id=di.analysis_id AND i.id=di.indicator_id"
            " WHERE di.analysis_id=? AND di.domain_id=? ORDER BY i.class, i.kind, i.value",
            aid, d["id"])]
        return {"provenance": self.provenance(a), "domain": dict(d),
                "decision": (dict(dec) | {"brands": json.loads(dec["brands"])}) if dec else None,
                "signals": sig, "certificates": certs, "dns": dns, "records": records,
                "relationships": rels, "indicators": inds,
                "campaign": (dict(camp) | {"brands": json.loads(camp["brands"])}) if camp else None}

    def _relationships(self, aid, where, args, limit=500):
        rows = self.q(
            "SELECT r.id, da.name a, db.name b, r.weight, r.kinds, r.accepted, r.strength, r.reason"
            " FROM relationships r JOIN domains da ON da.id=r.a_domain_id"
            " JOIN domains db ON db.id=r.b_domain_id"
            f" WHERE r.analysis_id=? AND {where} ORDER BY r.accepted DESC, r.weight DESC, a, b"
            " LIMIT ?", aid, *args, limit)
        out = []
        for r in rows:
            ev = [dict(e) for e in self.q(
                "SELECT i.kind, i.value, i.class, i.df, e.weight FROM relationship_evidence e"
                " JOIN indicators i ON i.analysis_id=e.analysis_id AND i.id=e.indicator_id"
                " WHERE e.analysis_id=? AND e.relationship_id=? ORDER BY e.weight DESC, i.kind",
                aid, r["id"])]
            out.append(dict(r) | {"kinds": json.loads(r["kinds"]), "evidence": ev,
                                  "accepted": bool(r["accepted"])})
        return out

    # /api/certificates ---------------------------------------------------------------
    def certificates(self, p):
        a = self.analysis()
        q = p_text(p, "q", 100)
        flagged = p_enum(p, "flagged", {"yes", "all"}, "yes")
        limit = p_int(p, "limit", 100, 1, 500)
        offset = p_int(p, "offset", 0, 0, 10_000_000)
        where, args = ["1=1"], []
        if q:
            where.append("(d.name LIKE ? ESCAPE '\\' OR c.issuer_name LIKE ? ESCAPE '\\'"
                         " OR c.serial LIKE ? ESCAPE '\\')")
            args += [f"%{like_escape(q)}%"] * 3
        having = "HAVING flagged > 0" if flagged == "yes" else ""
        base = ("SELECT c.id, c.issuer_name, c.serial, c.common_name, c.not_before, c.not_after,"
                " c.first_seen_at, COUNT(DISTINCT cn.domain_id) names,"
                " SUM(x.verdict IN ('likely','possible','lead')) flagged,"
                " MAX(x.score) max_score, GROUP_CONCAT(DISTINCT CASE WHEN x.verdict IN"
                " ('likely','possible','lead') THEN d.name END) flagged_names"
                " FROM certificates c JOIN cert_names cn ON cn.certificate_id=c.id"
                " JOIN domains d ON d.id=cn.domain_id"
                " LEFT JOIN decisions x ON x.analysis_id=? AND x.domain_id=d.id"
                f" WHERE {' AND '.join(where)} GROUP BY c.id {having}")
        total = self.one(f"SELECT COUNT(*) FROM ({base})", a["id"], *args)[0]
        rows = self.q(base + " ORDER BY c.not_before DESC, c.id LIMIT ? OFFSET ?",
                      a["id"], *args, limit, offset)
        return {"total": total, "limit": limit, "offset": offset,
                "rows": [dict(r) | {"flagged_names": sorted((r["flagged_names"] or "").split(",")
                                                            if r["flagged_names"] else [])}
                         for r in rows]}

    def certificate(self, p):
        a = self.analysis()
        cid = p_int(p, "id", None, 1, 10**12)
        if cid is None:
            raise BadRequest("id required")
        c = self.one("SELECT * FROM certificates WHERE id=?", cid)
        if c is None:
            raise NotFound("unknown certificate")
        names = [dict(r) for r in self.q(
            "SELECT d.name, cn.wildcard, cn.via, x.verdict, x.score FROM cert_names cn"
            " JOIN domains d ON d.id=cn.domain_id LEFT JOIN decisions x ON x.analysis_id=?"
            " AND x.domain_id=d.id WHERE cn.certificate_id=? ORDER BY x.score DESC, d.name",
            a["id"], cid)]
        recs = [dict(r) for r in self.q(
            "SELECT s.id, s.external_id crtsh_id, s.run_id, s.fetched_at, s.payload_sha256,"
            " s.payload, q.query FROM cert_records cr JOIN source_records s ON s.id=cr.record_id"
            " JOIN queries q ON q.id=s.query_id WHERE cr.certificate_id=? ORDER BY s.id", cid)]
        for r in recs:
            r["payload"] = json.loads(r["payload"])
        return {"provenance": self.provenance(a), "certificate": dict(c), "names": names,
                "records": recs}

    # /api/campaigns --------------------------------------------------------------------
    def campaigns(self, p):
        a = self.analysis()
        tier = p_enum(p, "tier", {"strong", "corroborated", "chained"})
        rows = self.q("SELECT * FROM campaigns WHERE analysis_id=?"
                      + (" AND tier=?" if tier else "") + " ORDER BY rank",
                      a["id"], *([tier] if tier else []))
        out = []
        for r in rows:
            members = [m[0] for m in self.q(
                "SELECT d.name FROM campaign_members m JOIN domains d ON d.id=m.domain_id"
                " WHERE m.analysis_id=? AND m.campaign_id=? ORDER BY d.name", a["id"], r["id"])]
            out.append(dict(r) | {"brands": json.loads(r["brands"]), "members": members})
        return {"provenance": self.provenance(a), "rows": out,
                "config": json.loads(a["correlation_config"])}

    def campaign(self, p):
        a = self.analysis()
        aid = a["id"]
        cid = _one(p, "id") or ""
        if not (cid.startswith("C-") and len(cid) == 12 and all(ch in "0123456789abcdef" for ch in cid[2:])):
            raise BadRequest("id must look like C-xxxxxxxxxx")
        c = self.one("SELECT * FROM campaigns WHERE analysis_id=? AND id=?", aid, cid)
        if c is None:
            raise NotFound("unknown campaign in the current analysis")
        members = [dict(r) | {"brands": json.loads(r["brands"])} for r in self.q(
            "WITH latest AS (SELECT domain, outcome, checked_at, MAX(id) FROM dns_observations"
            " GROUP BY domain)"
            " SELECT d.id, d.name, d.first_seen_at, x.score, x.verdict, x.brands, x.first_issued,"
            " l.outcome dns, l.checked_at dns_at FROM campaign_members m"
            " JOIN domains d ON d.id=m.domain_id JOIN decisions x ON x.analysis_id=m.analysis_id"
            " AND x.domain_id=d.id LEFT JOIN latest l ON l.domain=d.name"
            " WHERE m.analysis_id=? AND m.campaign_id=? ORDER BY x.first_issued, d.name", aid, cid)]
        ids = [m["id"] for m in members]
        marks = ",".join("?" * len(ids))
        edges = self._relationships(aid, f"r.accepted=1 AND r.a_domain_id IN ({marks})"
                                    f" AND r.b_domain_id IN ({marks})", (*ids, *ids), limit=2000)
        shared = [dict(r) for r in self.q(
            "SELECT i.kind, i.value, i.class, i.df, i.weight, i.status, COUNT(*) members"
            " FROM domain_indicators di JOIN indicators i ON i.analysis_id=di.analysis_id"
            f" AND i.id=di.indicator_id WHERE di.analysis_id=? AND di.domain_id IN ({marks})"
            " GROUP BY i.id HAVING members > 1 ORDER BY i.weight DESC, members DESC", aid, *ids)]
        return {"provenance": self.provenance(a),
                "campaign": dict(c) | {"brands": json.loads(c["brands"])},
                "members": members, "edges": edges, "shared_indicators": shared,
                "config": json.loads(a["correlation_config"])}

    # /api/timeline ---------------------------------------------------------------------
    def timeline(self, p):
        a = self.analysis()
        aid = a["id"]
        days = p_int(p, "days", 90, 1, 3650)
        kinds = {"issued", "first_seen", "dns_change"}
        want = p_enum(p, "kind", kinds | {"all"}, "all")
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()[:19]
        ev = []
        flagged = "x.analysis_id=? AND x.verdict IN ('likely','possible','lead')"
        if want in ("all", "issued"):
            for r in self.q(
                    "SELECT c.not_before t, d.name, x.verdict, c.issuer_name, c.id FROM decisions x"
                    " JOIN domains d ON d.id=x.domain_id JOIN cert_names cn ON cn.domain_id=d.id"
                    f" JOIN certificates c ON c.id=cn.certificate_id WHERE {flagged}"
                    " AND c.not_before>=? GROUP BY c.id, d.id", aid, since):
                ev.append({"t": r["t"], "type": "issued", "domain": r["name"],
                           "verdict": r["verdict"], "detail": r["issuer_name"], "cert": r["id"]})
        if want in ("all", "first_seen"):
            for r in self.q("SELECT d.first_seen_at t, d.name, x.verdict FROM decisions x"
                            f" JOIN domains d ON d.id=x.domain_id WHERE {flagged}"
                            " AND d.first_seen_at>=?", aid, since):
                ev.append({"t": r["t"], "type": "first_seen", "domain": r["name"],
                           "verdict": r["verdict"], "detail": "first collected"})
        if want in ("all", "dns_change"):
            prev: dict = {}
            for r in self.q("SELECT o.domain, o.checked_at t, o.outcome, x.verdict"
                            " FROM dns_observations o JOIN domains d ON d.name=o.domain"
                            f" JOIN decisions x ON x.domain_id=d.id WHERE {flagged}"
                            " ORDER BY o.id", aid):
                if prev.get(r["domain"]) != r["outcome"] and r["t"] >= since:
                    ev.append({"t": r["t"], "type": "dns_change", "domain": r["domain"],
                               "verdict": r["verdict"],
                               "detail": f"{prev.get(r['domain']) or 'first check'} -> {r['outcome']}"})
                prev[r["domain"]] = r["outcome"]
        ev.sort(key=lambda e: (e["t"], e["type"], e["domain"]), reverse=True)
        daily: dict = defaultdict(lambda: {"issued": 0, "first_seen": 0, "dns_change": 0})
        for e in ev:
            daily[e["t"][:10]][e["type"]] += 1
        start = datetime.fromisoformat(since[:10]).date()
        series, dday = [], start
        while dday <= datetime.now(timezone.utc).date():
            series.append({"day": dday.isoformat(), **daily[dday.isoformat()]})
            dday += timedelta(days=1)
        return {"provenance": self.provenance(a), "days": days, "total": len(ev),
                "events": ev[:600], "daily": series}

    # /api/sources, /api/runs -------------------------------------------------------------
    def sources(self, p):
        out = []
        now = datetime.now(timezone.utc)
        for s in self.q("SELECT * FROM sources ORDER BY id"):
            runs = self.q("SELECT * FROM collection_runs WHERE source_id=? ORDER BY id DESC", s["id"])
            recent = [r for r in runs if r["started_at"] >= (now - timedelta(days=7)).isoformat()]
            req = sum(r["queries_requested"] - r["queries_skipped"] for r in recent)
            ans = sum(r["queries_ok"] + r["queries_empty"] for r in recent)
            status = defaultdict(int)
            for r in runs:
                status[r["status"]] += 1
            last_ok = next((r["finished_at"] for r in runs if r["status"] == "complete"), None)
            out.append(dict(s) | {
                "runs": len(runs), "status_counts": dict(status),
                "last_run": dict(runs[0]) if runs else None, "last_complete": last_ok,
                "answer_rate_7d": round(ans / req, 4) if req else None,
                "records": self.one("SELECT COUNT(*) FROM source_records WHERE source_id=?",
                                    s["id"])[0] if s["id"] == "crtsh" else
                           self.one("SELECT COUNT(*) FROM dns_observations")[0]})
        return {"sources": out, "network": NETWORK}

    def runs(self, p):
        src = p_enum(p, "source", {"crtsh", "dns"})
        limit = p_int(p, "limit", 50, 1, 500)
        offset = p_int(p, "offset", 0, 0, 10_000_000)
        rows = self.q("SELECT * FROM collection_runs" + (" WHERE source_id=?" if src else "")
                      + " ORDER BY id DESC LIMIT ? OFFSET ?", *([src] if src else []), limit, offset)
        total = self.one("SELECT COUNT(*) FROM collection_runs" + (" WHERE source_id=?" if src else ""),
                         *([src] if src else []))[0]
        out = []
        for r in rows:
            d = dict(r)
            d["duration_s"] = _dur(r["started_at"], r["finished_at"])
            d["note"] = _json_or_none(r["note"])
            d["config_json"] = _json_or_none(r["config_json"])
            out.append(d)
        return {"total": total, "rows": out}

    def run(self, p):
        rid = p_int(p, "id", None, 1, 10**12)
        if rid is None:
            raise BadRequest("id required")
        r = self.one("SELECT * FROM collection_runs WHERE id=?", rid)
        if r is None:
            raise NotFound("unknown run")
        d = dict(r) | {"duration_s": _dur(r["started_at"], r["finished_at"]),
                       "note": _json_or_none(r["note"]), "config_json": _json_or_none(r["config_json"])}
        qs = [dict(q) for q in self.q("SELECT * FROM queries WHERE run_id=? ORDER BY id", rid)]
        dns = [dict(o) | {"addresses": json.loads(o["addresses"])} for o in self.q(
            "SELECT domain, checked_at, outcome, addresses, error FROM dns_observations"
            " WHERE run_id=? ORDER BY domain LIMIT 1000", rid)]
        return {"run": d, "queries": qs, "dns": dns}

    # /api/analyses, /api/methodology -----------------------------------------------------
    def analyses(self, p):
        rows = [dict(r) for r in self.q(
            "SELECT id, created_at, as_of, status, software_version, rules_version,"
            " correlation_sha256, cutoff_run_id, cutoff_record_id, cutoff_dns_id, dataset_sha256,"
            " results_sha256, domains_total, domains_flagged, campaigns_total, duration_s,"
            " derived_pruned FROM analysis_runs ORDER BY id DESC LIMIT 50")]
        snaps = [dict(r) for r in self.q(
            "SELECT id, created_at, analysis_id, dataset_sha256, file_name, file_sha256, bytes"
            " FROM snapshots ORDER BY id DESC LIMIT 50")]
        return {"analyses": rows, "snapshots": snaps}

    def methodology(self, p):
        a = self.analysis()
        return {
            "provenance": self.provenance(a),
            "rules_version": rules.RULES_VERSION,
            "rules": [{"id": k, **v} for k, v in rules.RULES.items()],
            "thresholds": rules.THRESHOLDS, "recent_days": rules.RECENT_DAYS,
            "verdicts": [{"id": v, "text": rules.VERDICT_TEXT[v]} for v in rules.VERDICTS],
            "brands": [{"id": b, "label": s["label"], "sector": s["sector"],
                        "ambiguous": s["ambiguous"], "official": s["official"],
                        "query_keys": s["query_keys"],
                        "phrases": ["-".join(ph) for ph in s["phrases"]]}
                       for b, s in rules.BRANDS.items()],
            "namesakes": rules.NAMESAKES,
            "tld_high": sorted(rules.TLD_HIGH), "tld_moderate": sorted(rules.TLD_MODERATE),
            "lures_bg": sorted(rules.BG_LURES), "lures_en": sorted(rules.EN_LURES),
            "bg_markers": sorted(rules.BG_MARKERS),
            "correlation": json.loads(a["correlation_config"]),
            "network": NETWORK, "glossary": GLOSSARY,
        }

    ROUTES = {"/api/meta": "meta", "/api/overview": "overview", "/api/domains": "domains",
              "/api/domain": "domain", "/api/certificates": "certificates",
              "/api/certificate": "certificate", "/api/campaigns": "campaigns",
              "/api/campaign": "campaign", "/api/timeline": "timeline", "/api/sources": "sources",
              "/api/runs": "runs", "/api/run": "run", "/api/analyses": "analyses",
              "/api/methodology": "methodology"}


def _dur(a, b):
    if not (a and b):
        return None
    return round((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds(), 1)


def _json_or_none(s):
    try:
        return json.loads(s) if s else None
    except ValueError:
        return None


# -- HTTP ------------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "trawl"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    api: Api = None            # set by serve()
    assets: dict = {}

    timeout = 20                     # idle/slow connections are dropped

    def version_string(self):
        return "trawl"               # no Python/OS version disclosure

    def _send(self, status: int, body: bytes, ctype: str, head: bool = False, cache: str = "no-store"):
        self.send_response(status)
        # This server never reads request bodies. If a client sent one, the unread
        # bytes would be parsed as the next request on a kept-alive connection - a
        # desync a reverse proxy could expose to other clients. Close instead.
        if self.headers.get("Content-Length", "0") != "0" or self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            self.send_header("Connection", "close")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _json(self, status: int, obj, head=False):
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str).encode()
        self._send(status, body, "application/json; charset=utf-8", head)

    def _handle(self, head: bool):
        if len(self.path) > 2048:
            return self._json(414, {"error": "request line too long"}, head)
        url = urlsplit(self.path)
        path = url.path
        if path in self.assets:
            body, ctype = self.assets[path]
            return self._send(200, body, ctype, head, cache="no-cache")
        method = Api.ROUTES.get(path)
        if method is None:
            return self._json(404, {"error": "not found"}, head)
        try:
            params = parse_qs(url.query, keep_blank_values=False, max_num_fields=24)
            return self._json(200, getattr(self.api, method)(params), head)
        except BadRequest as e:
            return self._json(400, {"error": str(e)}, head)
        except NotFound as e:
            return self._json(404, {"error": str(e)}, head)
        except ValueError:
            return self._json(400, {"error": "malformed query string"}, head)
        except Exception:
            traceback.print_exc(file=sys.stderr)
            return self._json(500, {"error": "internal error"}, head)

    def do_GET(self):
        self._handle(False)

    def do_HEAD(self):
        self._handle(True)

    def _refuse(self):
        self._json(405, {"error": "method not allowed"})

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _refuse

    def log_message(self, fmt, *args):
        # Method, path without query string, status. No client addresses are logged.
        line = self.requestline.split(" ")
        path = urlsplit(line[1]).path if len(line) > 1 else "-"
        sys.stderr.write(f"{self.log_date_time_string()} {line[0][:8]} {path[:120]} {args[1] if len(args) > 1 else ''}\n")

    def log_error(self, fmt, *args):
        pass                     # malformed requests: the status line in log_message suffices


def make_server(db_path: str, host: str = "127.0.0.1", port: int = 8790) -> ThreadingHTTPServer:
    assets = {route: ((WEB / fname).read_bytes(), ctype) for route, (fname, ctype) in STATIC.items()}
    handler = type("TrawlHandler", (Handler,), {"api": Api(db_path), "assets": assets})
    srv = ThreadingHTTPServer((host, port), handler)
    srv.daemon_threads = True
    return srv


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8790) -> None:
    if host not in ("127.0.0.1", "::1", "localhost"):
        print(f"warning: binding to {host} exposes the UI beyond this machine", file=sys.stderr)
    srv = make_server(db_path, host, port)
    print(f"trawl {VERSION} serving http://{host}:{port}/ (read-only)", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
