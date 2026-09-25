"""Correlation: which flagged names appear related, and why.

Vocabulary, used consistently in code, API and UI:

    indicator      an attribute a name carries (kind, value), e.g. (kit_shape, B.X4.cam)
    relationship   a pair of names sharing indicators, with the evidence and a weight
    campaign       a *hypothesis*: a connected group of accepted relationships

Rules (all configurable, see config.DEFAULTS["correlation"]):

1. A shared attribute is worth what it is rare. Medium/weak indicators weigh
   base * ln(N / df) over the flagged population; past max_df a value describes the
   ecosystem, not an actor, and is suppressed (and listed, so the step is auditable).
2. Strong indicators - the same registrable domain, or the same certificate - link
   on their own: one registrant controls every name under a registrable domain, and
   a DV certificate is issued to whoever controls every name on it. Multi-tenant CDN
   certificates are excluded before they get here.
3. Everything else needs corroboration: total weight >= min_edge, from at least
   min_kinds different kinds, at least one of them not 'weak'. The last clause is new
   in v2: the beta's largest campaign rested on "same brand + seen the same day",
   two weak coincidences.
4. Campaigns are connected components, which chain. Each carries density and a
   tier ('strong' / 'corroborated' / 'chained') so a group held together by a
   thread is shown as exactly that.
"""
from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations


@dataclass
class Indicator:
    kind: str
    value: str
    cls: str
    df: int
    weight: float
    status: str           # active | suppressed_hub | singleton


@dataclass
class Relationship:
    a: str
    b: str
    weight: float
    evidence: list        # [(kind, value, weight)] sorted
    kinds: list
    accepted: bool
    strength: str         # strong | corroborated | weak
    reason: str


@dataclass
class Campaign:
    id: str
    rank: int
    members: list
    edges: list           # accepted Relationships inside
    density: float
    cohesion: float
    min_weight: float
    tier: str


@dataclass
class Result:
    indicators: dict = field(default_factory=dict)     # (kind, value) -> Indicator
    relationships: list = field(default_factory=list)
    campaigns: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


def weigh(nodes: dict[str, set], cfg: dict) -> dict:
    """nodes: name -> {(kind, value)}. Returns (kind, value) -> Indicator."""
    n = len(nodes)
    df: dict = defaultdict(int)
    for inds in nodes.values():
        for iv in inds:
            df[iv] += 1
    out = {}
    for (kind, value), d in df.items():
        spec = cfg["kinds"][kind]
        if d < 2:
            status, w = "singleton", 0.0
        elif d > spec["max_df"]:
            status, w = "suppressed_hub", 0.0
        elif spec["class"] == "strong":
            status, w = "active", float(spec["base"])
        else:
            w = spec["base"] * math.log(n / d) if n > d else 0.0
            status = "active" if w > 0 else "suppressed_hub"
        out[(kind, value)] = Indicator(kind, value, spec["class"], d, round(w, 6), status)
    return out


def build(nodes: dict[str, set], cfg: dict) -> Result:
    res = Result()
    if len(nodes) < cfg["small_corpus"]:
        res.warnings.append(
            f"only {len(nodes)} names in the population; rarity weighting needs about "
            f"{cfg['small_corpus']} to be meaningful - treat an empty result as "
            "'too little data', not 'no campaigns'")
    inds = weigh(nodes, cfg)
    res.indicators = inds

    by_ind: dict = defaultdict(list)
    for name in sorted(nodes):
        for iv in nodes[name]:
            if inds[iv].status == "active":
                by_ind[iv].append(name)
    shared: dict = defaultdict(list)
    for iv in sorted(by_ind):
        for a, b in combinations(by_ind[iv], 2):     # names already sorted
            shared[(a, b)].append(iv)

    rels = []
    for (a, b) in sorted(shared):
        ev = sorted(shared[(a, b)])
        evidence = [(k, v, inds[(k, v)].weight) for k, v in ev]
        weight = round(sum(w for _, _, w in evidence), 6)
        kinds = sorted({k for k, _, _ in evidence})
        classes = {inds[iv].cls for iv in ev}
        if "strong" in classes:
            acc, strength, reason = True, "strong", "strong indicator: " + ", ".join(
                sorted({k for k, v, _ in evidence if inds[(k, v)].cls == "strong"}))
        elif weight < cfg["min_edge"]:
            acc, strength, reason = False, "weak", f"weight {weight:.2f} below min_edge {cfg['min_edge']}"
        elif len(kinds) < cfg["min_kinds"]:
            acc, strength, reason = False, "weak", f"only {len(kinds)} indicator kind(s); {cfg['min_kinds']} required"
        elif cfg["require_non_weak"] and "medium" not in classes:
            acc, strength, reason = False, "weak", "only weak indicator kinds (" + ", ".join(kinds) + ")"
        else:
            acc, strength, reason = True, "corroborated", f"{len(kinds)} kinds, weight {weight:.2f}"
        rels.append(Relationship(a, b, weight, evidence, kinds, acc, strength, reason))
    res.relationships = rels
    res.campaigns = _campaigns([r for r in rels if r.accepted], cfg)
    return res


def _campaigns(edges: list, cfg: dict) -> list:
    parent: dict = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)     # deterministic root

    for e in edges:
        union(e.a, e.b)
    groups: dict = defaultdict(list)
    for x in sorted(parent):
        groups[find(x)].append(x)
    by_root: dict = defaultdict(list)
    for e in edges:
        by_root[find(e.a)].append(e)

    out = []
    for root, members in groups.items():
        es = by_root[root]
        n = len(members)
        possible = n * (n - 1) / 2
        density = round(len(es) / possible, 4) if possible else 0.0
        cohesion = round(sum(e.weight for e in es) / len(es), 4)
        min_w = round(min(e.weight for e in es), 4)
        # strong tier: the strong edges alone already connect everyone
        sp: dict = {m: m for m in members}

        def sfind(x):
            while sp[x] != x:
                sp[x] = sp[sp[x]]
                x = sp[x]
            return x
        for e in es:
            if e.strength == "strong":
                sp[sfind(e.a)] = sfind(e.b)
        if len({sfind(m) for m in members}) == 1:
            tier = "strong"
        elif n >= 4 and density < cfg["chained_density"]:
            tier = "chained"
        else:
            tier = "corroborated"
        cid = "C-" + hashlib.sha256("\n".join(members).encode()).hexdigest()[:10]
        out.append(Campaign(cid, 0, members, es, density, cohesion, min_w, tier))
    out.sort(key=lambda c: (-len(c.members), -c.cohesion, c.id))
    for i, c in enumerate(out, 1):
        c.rank = i
    return out


def pairwise_scores(campaigns: list, truth: dict) -> tuple[float, float]:
    """Pairwise precision/recall of predicted co-membership against known truth.
    truth: name -> group id (noise gets a unique id). Used by the evaluation tests."""
    pred = {p for c in campaigns for p in combinations(sorted(c.members), 2)}
    groups: dict = defaultdict(list)
    for name, g in truth.items():
        groups[g].append(name)
    true = {p for ms in groups.values() for p in combinations(sorted(ms), 2)}
    tp = len(pred & true)
    return (tp / len(pred) if pred else 1.0, tp / len(true) if true else 1.0)
