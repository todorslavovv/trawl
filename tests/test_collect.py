"""Collection runs: outcome bookkeeping, abandoned-scan detection, normalisation,
append-only history, interval enforcement and interrupted-run recovery."""
import json

import pytest

from trawl.collect import TooSoon, collect_crtsh, dnscheck, normalize
from trawl.db import recover_interrupted

from .conftest import FakeCrtsh, fake_resolver, rec


def run(conn, cfg, data, keywords, **kw):
    fake = FakeCrtsh(data)
    rid = collect_crtsh(conn, cfg, client=fake, keywords=keywords, log=lambda *_: None, **kw)
    return conn.execute("SELECT * FROM collection_runs WHERE id=?", (rid,)).fetchone(), fake


def outcomes(conn, rid):
    return {(r["keyword"], r["role"]): r["outcome"] for r in
            conn.execute("SELECT keyword, role, outcome FROM queries WHERE run_id=?", (rid,))}


def test_complete_run(conn, cfg):
    r, fake = run(conn, cfg, {"econt%": [rec(["econt-pay.top"])], "%econt%": [rec(["my-econt.top"]), rec(["x-econt.top"])]}, ["econt"])
    assert r["status"] == "complete"
    assert json.loads(r["note"])["coverage"] == {"econt": "full"}
    assert fake.calls == ["econt%", "%econt%"]                   # no fallback needed
    assert r["records_new"] == 3 and r["queries_ok"] == 2


def test_empty_superset_after_nonempty_prefix_is_abandoned(conn, cfg):
    # REGRESSION (certwatch + live run): %bgpost% answered [] while bgpost% had 3843 rows
    r, fake = run(conn, cfg, {"bgpost%": [rec(["bgpost-a.top"])], "%bgpost%": [],
                              "%.bgpost%": [rec(["www.bgpost-a.top"])]}, ["bgpost"])
    o = outcomes(conn, r["id"])
    assert o[("bgpost", "contains")] == "abandoned"
    assert o[("bgpost", "dotted")] == "ok"
    assert r["status"] == "partial" and r["queries_abandoned"] == 1
    assert json.loads(r["note"])["coverage"] == {"bgpost": "partial"}


def test_truncated_superset_is_abandoned_but_its_records_kept(conn, cfg):
    # REGRESSION (live run 2026-09-26): %econt% returned 15 rows while econt% returned 5103
    pre = [rec([f"econt-{i}.top"]) for i in range(5)]
    r, _ = run(conn, cfg, {"econt%": pre, "%econt%": [rec(["my-econt.top"])]}, ["econt"])
    assert outcomes(conn, r["id"])[("econt", "contains")] == "abandoned"
    assert conn.execute("SELECT COUNT(*) FROM source_records").fetchone()[0] == 6


def test_empty_superset_cannot_be_verified_when_prefix_failed(conn, cfg):
    r, _ = run(conn, cfg, {"euslugi%": "http_error", "%euslugi%": []}, ["euslugi"])
    o = outcomes(conn, r["id"])
    assert o[("euslugi", "contains")] == "abandoned"
    assert r["status"] == "failed"         # dotted empty is unverifiable too -> no coverage


def test_genuine_zero_is_accepted_only_when_prefix_is_empty(conn, cfg):
    r, _ = run(conn, cfg, {"nosuchbrand%": [], "%nosuchbrand%": []}, ["nosuchbrand"])
    assert outcomes(conn, r["id"])[("nosuchbrand", "contains")] == "ok_empty"
    assert r["status"] == "complete" and r["queries_empty"] == 2


def test_queries_ask_for_unexpired_certificates(conn, cfg):
    _, fake = run(conn, cfg, {"econt%": [rec(["econt-a.top"])], "%econt%": [rec(["econt-a.top"])]}, ["econt"])
    assert fake.exclude_expired == [True, True]
    assert json.loads(conn.execute("SELECT config_json FROM collection_runs").fetchone()[0])["exclude_expired"] is True


def test_capped_answer_with_stale_newest_certificate_is_truncated(conn, cfg):
    # REGRESSION (live run 2026-09-26): econt% returned 5103 rows, newest from 2018 -
    # crt.sh caps big answers to the OLDEST rows. That is not "everything".
    cfg["collection"]["truncation_min_records"] = 3
    old = [rec([f"econt-{i}.top"], nb="2018-06-01T00:00:00") for i in range(4)]
    fresh = [rec([f"my-econt-{i}.top"]) for i in range(5)]
    r, _ = run(conn, cfg, {"econt%": old, "%econt%": fresh}, ["econt"])
    q = {x["role"]: x for x in conn.execute("SELECT role, outcome, error, records, records_new FROM queries")}
    assert q["prefix"]["outcome"] == "abandoned" and "truncated" in q["prefix"]["error"]
    assert q["prefix"]["records_new"] == 4                    # truncated answers are still kept
    assert json.loads(r["note"])["coverage"] == {"econt": "full"}   # the superset answered


def test_small_or_recent_answers_are_not_called_truncated(conn, cfg):
    cfg["collection"]["truncation_min_records"] = 3
    r, _ = run(conn, cfg, {"econt%": [rec([f"econt-{i}.top"], nb="2018-01-01T00:00:00") for i in range(2)],
                           "%econt%": [rec([f"econt-{i}.top"]) for i in range(6)]}, ["econt"])
    assert r["queries_abandoned"] == 0 and r["status"] == "complete"


def test_failures_are_never_counted_as_empty(conn, cfg):
    r, _ = run(conn, cfg, {"a%": "timeout", "%a%": "timeout", "%.a%": "network_error"}, ["a"])
    assert r["status"] == "failed"
    assert r["queries_empty"] == 0 and r["queries_timeout"] == 2 and r["queries_failed"] == 1
    assert r["queries_ok"] == 0


def test_budget_exhaustion_records_skipped(conn, cfg):
    cfg["collection"]["max_run_minutes"] = 0.0
    fake = FakeCrtsh({})
    ticks = iter(range(0, 10_000, 100))
    rid = collect_crtsh(conn, cfg, client=fake, keywords=["econt"], clock=lambda: next(ticks),
                        log=lambda *_: None)
    r = conn.execute("SELECT * FROM collection_runs WHERE id=?", (rid,)).fetchone()
    assert r["queries_skipped"] == 3 and fake.calls == [] and r["status"] == "failed"


def test_min_interval_is_enforced_in_code(conn, cfg):
    cfg["collection"]["min_interval_hours"] = 6.0
    run(conn, cfg, {}, ["econt"])
    with pytest.raises(TooSoon):
        run(conn, cfg, {}, ["econt"])
    run(conn, cfg, {}, ["econt"], force=True)                   # explicit override works


def test_same_payload_is_stored_once_but_query_dependent_payloads_are_kept(conn, cfg):
    # crt.sh lists only the identities that matched the query, so one certificate id can
    # come back with different name_value for different queries: both must be kept.
    a = rec(["econt-x.top"], rid=777, serial="0abc")
    b = dict(a, name_value="bgpost-x.top")
    run(conn, cfg, {"econt%": [a], "%econt%": [a, a]}, ["econt"])
    run(conn, cfg, {"bgpost%": [b], "%bgpost%": [b]}, ["bgpost"])
    assert conn.execute("SELECT COUNT(*) FROM source_records").fetchone()[0] == 2
    names = {r[0] for r in conn.execute(
        "SELECT d.name FROM cert_names cn JOIN domains d ON d.id=cn.domain_id"
        " JOIN certificates c ON c.id=cn.certificate_id WHERE c.cert_key='1:abc'")}
    assert {"econt-x.top", "bgpost-x.top"} <= names


def test_precert_and_final_cert_merge_into_one_certificate(conn, cfg):
    pre = rec(["econt-pay.top"], serial="00ff01", rid=1)
    final = rec(["econt-pay.top"], serial="ff01", rid=2)
    run(conn, cfg, {"econt%": [pre, final], "%econt%": [pre, final]}, ["econt"])
    assert conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM cert_records").fetchone()[0] == 2


def test_non_dns_identities_and_wildcards(conn, cfg):
    r = rec(["*.econt-pay.top", "econt-pay.top", "speedy payroll limited", "a@b.com"], cn="econt-pay.top")
    run(conn, cfg, {"econt%": [r], "%econt%": [r]}, ["econt"])
    assert [x[0] for x in conn.execute("SELECT name FROM domains")] == ["econt-pay.top"]
    rows = {(w, v) for w, v in conn.execute("SELECT wildcard, via FROM cert_names")}
    assert rows == {(1, "matched_identity"), (0, "matched_identity"), (0, "common_name")}


def test_invalid_records_are_counted_not_stored(conn, cfg):
    r, _ = run(conn, cfg, {"econt%": [{"id": "x"}, "junk", rec(["econt-a.top"])], "%econt%": [rec(["econt-a.top"])] * 3}, ["econt"])
    q = conn.execute("SELECT records_invalid FROM queries WHERE role='prefix'").fetchone()[0]
    assert q == 2


def test_normalize_is_idempotent(conn, cfg):
    run(conn, cfg, {"econt%": [rec(["econt-a.top", "econt-b.top"])], "%econt%": [rec(["econt-c.top"])]}, ["econt"])
    before = conn.execute("SELECT COUNT(*) FROM cert_names").fetchone()[0]
    assert normalize(conn) == 0
    assert conn.execute("SELECT COUNT(*) FROM cert_names").fetchone()[0] == before


def test_dns_history_is_appended_not_overwritten(conn, cfg):
    cfg["dns"]["recheck_hours"] = 0.0
    import socket
    dnscheck(conn, cfg, ["a.top"], resolve=fake_resolver({"a.top": ["203.0.113.5"]}), log=lambda *_: None)
    dnscheck(conn, cfg, ["a.top"], resolve=fake_resolver({"a.top": socket.EAI_NONAME}), log=lambda *_: None)
    rows = [tuple(r) for r in conn.execute("SELECT outcome, addresses FROM dns_observations ORDER BY id")]
    assert rows == [("resolved", '["203.0.113.5"]'), ("nxdomain", "[]")]


def test_dns_outcomes_and_run_status(conn, cfg):
    import socket
    table = {"live.top": ["198.51.100.1", "2001:db8::1"], "gone.top": socket.EAI_NONAME,
             "flaky.top": socket.EAI_AGAIN}
    rid = dnscheck(conn, cfg, list(table), resolve=fake_resolver(table), log=lambda *_: None)
    got = dict(conn.execute("SELECT domain, outcome FROM dns_observations"))
    assert got == {"live.top": "resolved", "gone.top": "nxdomain", "flaky.top": "temporary_failure"}
    r = conn.execute("SELECT * FROM collection_runs WHERE id=?", (rid,)).fetchone()
    assert r["status"] == "partial" and r["queries_failed"] == 1 and r["queries_empty"] == 1


def test_dns_recheck_window_skips_recent(conn, cfg):
    cfg["dns"]["recheck_hours"] = 24.0
    res = fake_resolver({"a.top": ["203.0.113.5"]})
    assert dnscheck(conn, cfg, ["a.top"], resolve=res, log=lambda *_: None)
    assert dnscheck(conn, cfg, ["a.top"], resolve=res, log=lambda *_: None) is None


def test_interrupted_runs_are_marked(conn, cfg):
    conn.execute("INSERT INTO collection_runs(source_id, started_at, status, software_version,"
                 " config_json) VALUES ('crtsh','2026-01-01T00:00:00+00:00','running','x','{}')")
    conn.commit()
    assert recover_interrupted(conn) == 1
    assert conn.execute("SELECT status FROM collection_runs").fetchone()[0] == "interrupted"
