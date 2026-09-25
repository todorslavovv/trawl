"""Correlation: weighting, suppression, corroboration, tiers, determinism, and a
synthetic evaluation with known ground truth."""
import copy
import random

import pytest

from trawl import config as C
from trawl.analysis import ip_usable, multi_tenant
from trawl.correlate import build, pairwise_scores, weigh

CFG = C.load()["correlation"]


def cfg(**over):
    c = copy.deepcopy(CFG)
    c.update(over)
    return c


def test_strong_indicator_links_alone():
    nodes = {"a.x.top": {("same_registrable", "x.top")}, "b.x.top": {("same_registrable", "x.top")}}
    res = build(nodes, cfg())
    [r] = res.relationships
    assert r.accepted and r.strength == "strong"
    assert res.campaigns[0].tier == "strong"


def test_single_weak_kind_never_links():
    nodes = {f"n{i}": {("brand", "econt")} for i in range(3)}
    nodes.update({f"z{i}": {("brand", "speedy")} for i in range(40)})
    res = build(nodes, cfg())
    assert not any(r.accepted for r in res.relationships)


def test_two_weak_kinds_are_rejected_in_v2_but_accepted_by_the_beta_rule():
    # REGRESSION (cobweb): the beta's largest campaign rested on brand + same-day only.
    base = {f"z{i}.top": {("tld", f"t{i % 9}")} for i in range(60)}
    pair = {"tollpass.a.cam": {("brand", "tollpass"), ("issuance_day", "2026-07-28|ca1")},
            "tollpass.b.cam": {("brand", "tollpass"), ("issuance_day", "2026-07-28|ca1")}}
    v2 = build({**base, **pair}, cfg())
    beta = build({**base, **pair}, cfg(require_non_weak=False))
    rel = [r for r in v2.relationships if r.a == "tollpass.a.cam"][0]
    assert not rel.accepted and "only weak" in rel.reason
    assert any(r.accepted for r in beta.relationships if r.a == "tollpass.a.cam")


def test_medium_plus_weak_links():
    base = {f"z{i}.top": {("tld", f"t{i % 9}")} for i in range(60)}
    pair = {"a": {("kit_shape", "B.X4.cam"), ("brand", "tollpass")},
            "b": {("kit_shape", "B.X4.cam"), ("brand", "tollpass")}}
    rel = [r for r in build({**base, **pair}, cfg()).relationships if r.a == "a"][0]
    assert rel.accepted and rel.strength == "corroborated" and rel.kinds == ["brand", "kit_shape"]


def test_hub_values_are_suppressed_and_listed():
    nodes = {f"n{i}": {("tld", "top"), ("brand", "econt")} for i in range(50)}
    ind = weigh(nodes, cfg())
    assert ind[("tld", "top")].status == "suppressed_hub"
    assert ind[("brand", "econt")].status == "suppressed_hub"
    assert all(i.weight == 0 for i in ind.values())


def test_idf_weighting_rarer_is_heavier():
    nodes = {f"n{i}": {("brand", "a" if i < 3 else "b" if i < 15 else f"u{i}")} for i in range(60)}
    ind = weigh(nodes, cfg())
    assert ind[("brand", "a")].weight > ind[("brand", "b")].weight > 0


def test_singletons_do_not_link():
    ind = weigh({"a": {("kit_shape", "X")}, "b": {("kit_shape", "Y")}}, cfg())
    assert {i.status for i in ind.values()} == {"singleton"}


def test_chained_tier_for_sparse_groups():
    # a-b, b-c, c-d, d-e : a path, density 4/10 = 0.4 -> corroborated; longer path is chained
    names = [f"p{i}" for i in range(7)]
    nodes = {n: set() for n in names}
    for i in range(len(names) - 1):
        nodes[names[i]].add(("same_registrable", f"r{i}.top"))
        nodes[names[i + 1]].add(("same_registrable", f"r{i}.top"))
    nodes.update({f"z{i}": {("tld", "cfd")} for i in range(5)})
    res = build(nodes, cfg())
    [c] = res.campaigns
    assert c.tier == "strong"          # all-strong paths are still strong...
    nodes2 = {n: set() for n in names}
    for i in range(len(names) - 1):
        for k in (("kit_shape", f"s{i}"), ("brand", f"b{i}")):
            nodes2[names[i]].add(k)
            nodes2[names[i + 1]].add(k)
    nodes2.update({f"z{i}": {("tld", f"t{i}")} for i in range(40)})
    [c2] = build(nodes2, cfg()).campaigns
    assert c2.tier == "chained" and c2.density < CFG["chained_density"]


def test_campaign_ids_are_content_derived_and_stable():
    nodes = {"a.x.top": {("same_registrable", "x.top")}, "b.x.top": {("same_registrable", "x.top")}}
    a = build(nodes, cfg()).campaigns[0].id
    b = build(dict(reversed(list(nodes.items()))), cfg()).campaigns[0].id
    assert a == b and a.startswith("C-") and len(a) == 12


def test_small_corpus_warning():
    assert build({"a": set(), "b": set()}, cfg()).warnings


def test_build_is_deterministic_regardless_of_input_order():
    rnd = random.Random(3)
    nodes, _ = synth(rnd)
    items = list(nodes.items())
    rnd.shuffle(items)
    a, b = build(nodes, cfg()), build(dict(items), cfg())
    assert [(r.a, r.b, r.weight, r.evidence) for r in a.relationships] == \
           [(r.a, r.b, r.weight, r.evidence) for r in b.relationships]
    assert [(c.id, c.members) for c in a.campaigns] == [(c.id, c.members) for c in b.campaigns]


# -- infrastructure filters used when extracting indicators ------------------------------
@pytest.mark.parametrize("ip,usable", [
    ("104.21.33.7", False),       # Cloudflare edge: shared by unrelated sites
    ("2606:4700::6810:1", False),
    ("127.0.0.1", False),         # sinkholed / parked
    ("0.0.0.0", False), ("10.1.2.3", False), ("198.51.100.7", False),   # non-global
    ("185.199.108.153", True), ("45.9.148.10", True),
])
def test_ip_usable(ip, usable):
    assert ip_usable(ip) is usable


def test_multi_tenant_cdn_certificates_are_excluded():
    assert multi_tenant("sni69959.cloudflaressl.com")
    assert not multi_tenant("econt-pay.top")


# -- synthetic evaluation ------------------------------------------------------------------
def synth(rnd):
    """Known campaigns + adversarial noise. Returns (nodes, truth)."""
    nodes, truth = {}, {}
    brands = ["econt", "speedy", "bgpost", "tollpass", "fibank", "dskbank"]
    tlds = ["cam", "cfd", "top", "sbs", "icu", "cyou"]
    g = 0
    # kit campaigns: one naming kit, deployed over two days, half the names on one IP,
    # plus one member with ONLY the shared shape (a partial signature - expected miss).
    for c in range(8):
        tld, brand = tlds[c % 6], brands[c % 6]
        shape = f"B.X{4 + c % 3}.{tld}"
        for i in range(7):
            n = f"{brand}.k{c}m{i}.{tld}"
            s = {("kit_shape", shape), ("brand", brand), ("tld", tld), ("same_registrable", f"k{c}m{i}.{tld}")}
            if i < 6:
                s.add(("issuance_day", f"2026-0{1 + c % 8}-{10 + (i >= 3)}|ca{c % 3}"))
            if i in (1, 2, 3, 4):
                s.add(("shared_ip", f"185.12.{c}.7"))
            nodes[n], truth[n] = s, g
        g += 1
    # shared-hosting campaigns: one IP and one distinctive lure word per operation
    for c in range(4):
        ip = f"45.9.{c}.10"
        for i in range(4):
            n = f"{brands[c]}-pay{c}{i}.{tlds[i]}"
            nodes[n] = {("shared_ip", ip), ("brand", brands[c]), ("tld", tlds[i]),
                        ("same_registrable", n), ("lure", f"lureword{c}")}
            truth[n] = g
        g += 1
    # shared registrable and shared certificate pairs
    for c in range(4):
        a, b = f"econt.r{c}.top", f"bgpost.r{c}.top"
        nodes[a] = {("same_registrable", f"r{c}.top"), ("brand", "econt"), ("tld", "top")}
        nodes[b] = {("same_registrable", f"r{c}.top"), ("brand", "bgpost"), ("tld", "top")}
        truth[a] = truth[b] = g
        g += 1
        a, b = f"fibank-c{c}.cfd", f"dskbank-c{c}.icu"
        nodes[a] = {("shared_certificate", f"1:c{c}"), ("brand", "fibank"), ("tld", "cfd"), ("same_registrable", a)}
        nodes[b] = {("shared_certificate", f"1:c{c}"), ("brand", "dskbank"), ("tld", "icu"), ("same_registrable", b)}
        truth[a] = truth[b] = g
        g += 1
    # adversarial: sibling operations - same brand, TLD and day, different kits
    for k, shape in enumerate(("B-H7.sbs", "B-H12.sbs")):
        for i in range(5):
            n = f"econt-sib{k}{i}.sbs"
            nodes[n] = {("kit_shape", shape), ("brand", "econt"), ("tld", "sbs"),
                        ("issuance_day", "2026-06-15|ca1"), ("same_registrable", n)}
            truth[n] = g
        g += 1
    # adversarial: coincidental noise sharing brand + day + TLD (all weak)
    for i in range(24):
        n = f"noise-day{i}.xyz"
        nodes[n] = {("brand", rnd.choice(brands)), ("issuance_day", "2026-02-02|ca1"), ("tld", "xyz"), ("same_registrable", n)}
        truth[n] = -1000 - i
    # background noise
    for i in range(200):
        n = f"bg{i}.{rnd.choice(tlds)}"
        s = {("brand", rnd.choice(brands)), ("tld", n.rsplit('.', 1)[1]), ("same_registrable", n),
             ("issuance_day", f"2026-{rnd.randint(1, 12):02d}-{rnd.randint(1, 28):02d}|ca{rnd.randint(0, 2)}")}
        if rnd.random() < 0.3:
            s.add(("lure", rnd.choice(["pay", "dostavka", "track", "taksa"])))
        nodes[n], truth[n] = s, -i - 1
    return nodes, truth


def test_synthetic_evaluation_v2_rules():
    nodes, truth = synth(random.Random(7))
    res = build(nodes, cfg())
    precision, recall = pairwise_scores(res.campaigns, truth)
    assert precision == 1.0, precision
    # measured 2026-09-26: recall 0.782 on seeds 7, 11, 23 - the missed pairs are exactly the
    # partial-signature members (shape only), which the corroboration rule is meant to skip
    assert recall >= 0.75, recall
    # sibling operations must never be merged
    for c in res.campaigns:
        assert len({truth[m] for m in c.members}) == 1


def test_ip_alone_does_not_link():
    """Design decision: one shared address (shared hosting) is one coincidence."""
    nodes = {f"h{i}": {("shared_ip", "45.9.1.1"), ("same_registrable", f"h{i}")} for i in range(3)}
    nodes.update({f"z{i}": {("tld", f"t{i}")} for i in range(40)})
    assert not any(r.accepted for r in build(nodes, cfg()).relationships)


def test_synthetic_evaluation_naive_rule_collapses():
    nodes, truth = synth(random.Random(7))
    precision, recall = pairwise_scores(build(nodes, cfg(min_kinds=1, require_non_weak=False, min_edge=0.1)).campaigns, truth)
    assert precision < 0.5 and recall == 1.0
