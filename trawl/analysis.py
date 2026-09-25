"""An analysis run: score every name, correlate the flagged ones, record provenance.

Inputs are fixed by cut-offs over the append-only observations, the time reference
is an explicit `as_of` (never the wall clock inside rules), and every output list is
sorted - so the same cut-offs, as_of, rules and configuration always produce the
same results fingerprint. Replay from a snapshot checks exactly that.
"""
from __future__ import annotations

import ipaddress
import json
import sqlite3
import time
from collections import defaultdict

from . import VERSION, rules
from .config import canonical, sha256_of
from .correlate import build
from .db import utcnow
from .names import parse
from .scoring import Facts, brands_of, kit_shape, score, view
from .snapshot import cutoffs_now, dataset_sha256

# Shared CDN edge addresses carry no ownership signal: thousands of unrelated sites
# answer from the same anycast IPs. Cloudflare's published ranges (cloudflare.com/ips).
CDN_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"))

# Certificates issued to a CDN on behalf of many unrelated customers.
MULTI_TENANT_CN = ("cloudflaressl.com", "sni.cloudflaressl.com", "ssl.cloudflare.com",
                   "kinstacdn.com", "incapsula.com", "wpengine.com")


def ip_usable(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return ip.is_global and not any(ip in n for n in CDN_NETWORKS if n.version == ip.version)


def multi_tenant(common_name: str | None) -> bool:
    cn = (common_name or "").lower()
    return any(cn == s or cn.endswith("." + s) for s in MULTI_TENANT_CN)


def load_facts(conn: sqlite3.Connection, cutoff_record: int):
    """Per name: Facts, plus certificate membership for correlation."""
    rows = conn.execute(
        "SELECT d.name, cn.wildcard, c.id, c.cert_key, c.not_before, c.issuer_ca_id, c.common_name"
        " FROM cert_names cn JOIN domains d ON d.id = cn.domain_id"
        " JOIN certificates c ON c.id = cn.certificate_id"
        " WHERE cn.first_record_id <= ? ORDER BY d.name, c.not_before, c.id", (cutoff_record,))
    wildcard: dict = defaultdict(bool)
    first: dict = {}
    certs_of: dict = defaultdict(set)
    names_on: dict = defaultdict(set)
    cert_info: dict = {}
    for name, wc, cid, key, nb, issuer, cn in rows:
        wildcard[name] |= bool(wc)
        if nb and (name not in first or nb < first[name][0]):
            first[name] = (nb, issuer)
        certs_of[name].add(cid)
        names_on[cid].add(name)
        cert_info[cid] = (key, cn)
    facts = {}
    for name in sorted(certs_of):
        sib = set()
        for cid in certs_of[name]:
            for other in names_on[cid]:
                if other != name:
                    sib |= brands_of(other)
        facts[name] = Facts(name, wildcard[name], first.get(name, (None,))[0], frozenset(sib))
    return facts, first, certs_of, cert_info


def score_all(facts: dict, as_of: str) -> dict:
    return {n: score(f, as_of) for n, f in facts.items()}


def flagged_by_priority(conn: sqlite3.Connection, cfg: dict) -> list[str]:
    """Current flagged names, highest score first - the DNS re-check work list."""
    facts, *_ = load_facts(conn, cutoffs_now(conn)["record"])
    decs = score_all(facts, utcnow())
    pop = set(cfg["correlation"]["population"])
    flagged = [d for d in decs.values() if d.verdict in pop]
    flagged.sort(key=lambda d: (-d.score, d.name))
    return [d.name for d in flagged]


def _latest_dns(conn, cutoff_dns: int) -> dict:
    out = {}
    for name, outcome, addrs in conn.execute(
            "SELECT domain, outcome, addresses FROM dns_observations WHERE id <= ? ORDER BY id",
            (cutoff_dns,)):
        out[name] = (outcome, json.loads(addrs))
    return out


def indicators_for(name: str, dec, facts_first, certs, cert_info, dns_latest) -> set:
    p = parse(name)
    v = view(name)
    out = set()
    if not (p.platform and p.registrable == p.platform):
        out.add(("same_registrable", p.registrable))
    for cid in certs:
        key, cn = cert_info[cid]
        if not multi_tenant(cn):
            out.add(("shared_certificate", key))
    outcome, addrs = dns_latest.get(name, (None, []))
    if outcome == "resolved":
        out |= {("shared_ip", a) for a in addrs if ip_usable(a)}
    shape = kit_shape(name)
    if shape:
        out.add(("kit_shape", shape))
    if name in facts_first:
        nb, issuer = facts_first[name]
        out.add(("issuance_day", f"{nb[:10]}|ca{issuer}"))
    out |= {("brand", b) for b in dec.brands}
    words = {w for ws in v.words for w in ws}
    out |= {("lure", w) for w in words & (rules.BG_LURES | rules.EN_LURES)}
    if p.platform:
        out.add(("platform", p.platform))
    else:
        out.add(("tld", p.tld))
    return out


def run_analysis(conn: sqlite3.Connection, cfg: dict, *, as_of: str | None = None,
                 cutoffs: dict | None = None, log=print) -> int:
    t0 = time.monotonic()
    corr = cfg["correlation"]
    cut = cutoffs or cutoffs_now(conn)
    as_of = as_of or utcnow()
    cur = conn.execute(
        "INSERT INTO analysis_runs(created_at, as_of, status, software_version, rules_version,"
        " correlation_config, correlation_sha256, cutoff_run_id, cutoff_record_id, cutoff_dns_id)"
        " VALUES (?,?,'running',?,?,?,?,?,?,?)",
        (utcnow(), as_of, VERSION, rules.RULES_VERSION, canonical(corr), sha256_of(corr),
         cut["run"], cut["record"], cut["dns"]))
    aid = cur.lastrowid
    conn.commit()

    facts, first, certs_of, cert_info = load_facts(conn, cut["record"])
    decs = score_all(facts, as_of)
    ids = dict(conn.execute("SELECT name, id FROM domains"))

    conn.executemany(
        "INSERT INTO decisions(analysis_id, domain_id, score, verdict, brands, corroborated,"
        " first_issued) VALUES (?,?,?,?,?,?,?)",
        [(aid, ids[n], d.score, d.verdict, json.dumps(d.brands), int(d.corroborated),
          facts[n].first_issued) for n, d in decs.items()])
    conn.executemany(
        "INSERT INTO signals(analysis_id, domain_id, rule, points, corroborating, detail)"
        " VALUES (?,?,?,?,?,?)",
        [(aid, ids[n], s[0], s[1], int(s[2]), s[3]) for n, d in decs.items() for s in d.signals])

    pop = set(corr["population"])
    dns_latest = _latest_dns(conn, cut["dns"])
    nodes = {n: indicators_for(n, d, first, certs_of[n], cert_info, dns_latest)
             for n, d in decs.items() if d.verdict in pop}
    res = build(nodes, corr)
    for w in res.warnings:
        log("  warning: " + w)

    ind_ids = {}
    for i, key in enumerate(sorted(res.indicators), 1):
        ind = res.indicators[key]
        ind_ids[key] = i
        conn.execute("INSERT INTO indicators(analysis_id, id, kind, value, class, df, weight, status)"
                     " VALUES (?,?,?,?,?,?,?,?)",
                     (aid, i, ind.kind, ind.value, ind.cls, ind.df, ind.weight, ind.status))
    conn.executemany("INSERT INTO domain_indicators(analysis_id, domain_id, indicator_id)"
                     " VALUES (?,?,?)",
                     [(aid, ids[n], ind_ids[iv]) for n in sorted(nodes) for iv in sorted(nodes[n])])
    for i, r in enumerate(res.relationships, 1):
        conn.execute("INSERT INTO relationships(analysis_id, id, a_domain_id, b_domain_id, weight,"
                     " kinds, accepted, strength, reason) VALUES (?,?,?,?,?,?,?,?,?)",
                     (aid, i, ids[r.a], ids[r.b], r.weight, json.dumps(r.kinds), int(r.accepted),
                      r.strength, r.reason))
        conn.executemany("INSERT INTO relationship_evidence(analysis_id, relationship_id,"
                         " indicator_id, weight) VALUES (?,?,?,?)",
                         [(aid, i, ind_ids[(k, v)], w) for k, v, w in r.evidence])
    for c in res.campaigns:
        issued = sorted(facts[m].first_issued for m in c.members if facts[m].first_issued)
        brands = sorted({b for m in c.members for b in decs[m].brands})
        conn.execute("INSERT INTO campaigns(analysis_id, id, rank, size, edges, density, cohesion,"
                     " min_weight, tier, brands, first_issued, last_issued)"
                     " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     (aid, c.id, c.rank, len(c.members), len(c.edges), c.density, c.cohesion,
                      c.min_weight, c.tier, json.dumps(brands),
                      issued[0] if issued else None, issued[-1] if issued else None))
        conn.executemany("INSERT INTO campaign_members(analysis_id, campaign_id, domain_id)"
                         " VALUES (?,?,?)", [(aid, c.id, ids[m]) for m in c.members])

    results = results_document(decs, res)
    ds_sha, _ = dataset_sha256(conn, cut)
    counts = defaultdict(int)
    for d in decs.values():
        counts[d.verdict] += 1
    conn.execute(
        "UPDATE analysis_runs SET status='complete', dataset_sha256=?, results_sha256=?,"
        " domains_total=?, domains_flagged=?, campaigns_total=?, duration_s=? WHERE id=?",
        (ds_sha, sha256_of(results), len(decs), sum(counts[v] for v in pop),
         len(res.campaigns), round(time.monotonic() - t0, 2), aid))
    conn.commit()
    _prune_derived(conn, cfg["analysis"]["keep_derived"])
    log(f"  analysis {aid}: {len(decs)} names, " +
        ", ".join(f"{v}={counts[v]}" for v in rules.VERDICTS if counts[v]) +
        f"; {len(res.campaigns)} campaign hypotheses")
    return aid


def results_document(decs: dict, res) -> dict:
    """The canonical results body. Its SHA-256 is the analysis' results fingerprint."""
    r4 = lambda x: round(x, 4)
    return {
        "decisions": [[d.name, d.score, d.verdict, d.brands,
                       [[s[0], s[1], s[3]] for s in d.signals]]
                      for d in sorted(decs.values(), key=lambda d: d.name) if d.verdict != "none"],
        "suppressed_indicators": sorted([i.kind, i.value, i.df] for i in res.indicators.values()
                                        if i.status == "suppressed_hub"),
        "relationships": [[r.a, r.b, r4(r.weight), r.strength,
                           [[k, v, r4(w)] for k, v, w in r.evidence]]
                          for r in res.relationships if r.accepted],
        "campaigns": [[c.id, c.rank, c.tier, len(c.members), r4(c.density), r4(c.cohesion),
                       c.members] for c in res.campaigns],
    }


def _prune_derived(conn: sqlite3.Connection, keep: int) -> None:
    old = [r[0] for r in conn.execute(
        "SELECT id FROM analysis_runs WHERE status='complete' AND derived_pruned=0"
        " ORDER BY id DESC LIMIT -1 OFFSET ?", (keep,))]
    for aid in old:
        for t in ("decisions", "signals", "indicators", "domain_indicators", "relationships",
                  "relationship_evidence", "campaigns", "campaign_members"):
            conn.execute(f"DELETE FROM {t} WHERE analysis_id=?", (aid,))
        conn.execute("UPDATE analysis_runs SET derived_pruned=1 WHERE id=?", (aid,))
    conn.commit()


def report(conn: sqlite3.Connection, analysis_id: int, cfg: dict) -> dict:
    """Regenerate the full, deterministic report of a past analysis from observations."""
    a = conn.execute("SELECT * FROM analysis_runs WHERE id=? AND status='complete'",
                     (analysis_id,)).fetchone()
    if a is None:
        raise ValueError(f"no complete analysis {analysis_id}")
    cut = {"run": a["cutoff_run_id"], "record": a["cutoff_record_id"], "dns": a["cutoff_dns_id"]}
    facts, first, certs_of, cert_info = load_facts(conn, cut["record"])
    decs = score_all(facts, a["as_of"])
    corr = json.loads(a["correlation_config"])
    dns_latest = _latest_dns(conn, cut["dns"])
    nodes = {n: indicators_for(n, d, first, certs_of[n], cert_info, dns_latest)
             for n, d in decs.items() if d.verdict in set(corr["population"])}
    results = results_document(decs, build(nodes, corr))
    runs = [dict(r) for r in conn.execute(
        "SELECT id, source_id, started_at, finished_at, status, queries_requested, queries_ok,"
        " queries_empty, queries_failed, queries_timeout, queries_abandoned, queries_skipped"
        " FROM collection_runs WHERE id <= ? ORDER BY id", (cut["run"],))]
    return {
        "provenance": {
            "analysis_id": analysis_id, "as_of": a["as_of"], "created_at": a["created_at"],
            "software_version": a["software_version"], "rules_version": a["rules_version"],
            "regenerated_by": f"trawl {VERSION}", "correlation_config": corr,
            "correlation_sha256": a["correlation_sha256"], "cutoffs": cut,
            "dataset_sha256": a["dataset_sha256"],
            "results_sha256_recorded": a["results_sha256"],
            "results_sha256_regenerated": sha256_of(results),
            "collection_runs": runs,
        },
        "results": results,
    }
