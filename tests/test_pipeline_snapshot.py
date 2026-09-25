"""End-to-end: collection -> DNS -> analysis -> snapshot -> verify -> replay.
Determinism and provenance are asserted, not assumed."""
import gzip
import json
import socket
from pathlib import Path

import pytest

from trawl.analysis import flagged_by_priority, report, run_analysis
from trawl.collect import collect_crtsh, dnscheck
from trawl.snapshot import cutoffs_now, dataset_sha256, export, replay, verify

from .conftest import FakeCrtsh, fake_resolver, rec

DATA = {
    "tollpass%": [rec([f"tollpass.{x}.cam"], nb="2026-07-28T08:00:00") for x in ("dvhl", "eknt", "isxd", "klgf")]
                 + [rec(["tollpass.bg"])],
    "%tollpass%": [],
    "%.tollpass%": [rec(["www.tollpass.bg"])],
    "econt%": [rec(["econt-7fa3b2.sbs", "*.econt-7fa3b2.sbs"]), rec(["econt-9c1d4e.sbs"]), rec(["econt.com"])],
    "%econt%": [rec(["econt-7fa3b2.sbs"]), rec(["my-econt-dostavka.top", "bgpost-dostavka.top"]),
                rec(["econt-pay.top"]), rec(["x-econt.top"])],
    "bgpost%": [rec(["bgpost-item-track.top"])],
    "%bgpost%": [rec(["bgpost-item-track.top"]), rec(["mybgpost.top"])],
}
DNS = {"tollpass.dvhl.cam": ["185.12.0.7"], "tollpass.eknt.cam": ["185.12.0.7"],
       "tollpass.isxd.cam": socket.EAI_NONAME, "econt-pay.top": ["104.21.3.3"],
       "bgpost-item-track.top": socket.EAI_AGAIN}


@pytest.fixture
def populated(conn, cfg):
    collect_crtsh(conn, cfg, client=FakeCrtsh(DATA), keywords=["bgpost", "econt", "tollpass"],
                  log=lambda *_: None)
    dnscheck(conn, cfg, flagged_by_priority(conn, cfg), resolve=fake_resolver(DNS), log=lambda *_: None)
    aid = run_analysis(conn, cfg, as_of="2026-09-26T00:00:00+00:00", log=lambda *_: None)
    return aid


def test_analysis_records_full_provenance(conn, cfg, populated):
    a = conn.execute("SELECT * FROM analysis_runs WHERE id=?", (populated,)).fetchone()
    assert a["status"] == "complete"
    assert len(a["dataset_sha256"]) == 64 and len(a["results_sha256"]) == 64
    assert a["rules_version"] and a["software_version"] == "2.0.0"
    assert json.loads(a["correlation_config"])["min_kinds"] == 2
    assert (a["cutoff_run_id"], a["cutoff_record_id"]) == (2, conn.execute("SELECT MAX(id) FROM source_records").fetchone()[0])


def test_every_signal_and_relationship_has_evidence(conn, populated):
    assert conn.execute("SELECT COUNT(*) FROM signals WHERE detail=''").fetchone()[0] == 0
    for (rid,) in conn.execute("SELECT id FROM relationships WHERE analysis_id=? AND accepted=1", (populated,)):
        n = conn.execute("SELECT COUNT(*) FROM relationship_evidence WHERE analysis_id=? AND relationship_id=?",
                         (populated, rid)).fetchone()[0]
        assert n >= 1


def test_expected_findings(conn, populated):
    v = dict(conn.execute("SELECT d.name, x.verdict FROM decisions x JOIN domains d ON d.id=x.domain_id"
                          " WHERE analysis_id=?", (populated,)))
    assert v["tollpass.dvhl.cam"] == "likely" and v["econt.com"] == "legitimate"
    assert v["tollpass.bg"] == "legitimate" and v["bgpost-item-track.top"] == "likely"
    camps = conn.execute("SELECT id, tier, size FROM campaigns WHERE analysis_id=?", (populated,)).fetchall()
    members = {c["id"]: {r[0] for r in conn.execute(
        "SELECT d.name FROM campaign_members m JOIN domains d ON d.id=m.domain_id WHERE m.campaign_id=?",
        (c["id"],))} for c in camps}
    assert {"tollpass.dvhl.cam", "tollpass.eknt.cam"} <= next(m for m in members.values() if "tollpass.dvhl.cam" in m)
    # a shared certificate across two brands is a strong link, and flags multi-brand
    shared = next(c for c in camps if members[c["id"]] == {"my-econt-dostavka.top", "bgpost-dostavka.top"})
    assert shared["tier"] == "strong"


def test_cdn_address_does_not_become_an_indicator(conn, populated):
    vals = [r[0] for r in conn.execute("SELECT value FROM indicators WHERE kind='shared_ip'")]
    assert "104.21.3.3" not in vals


def test_reanalysis_with_same_inputs_is_identical(conn, cfg, populated):
    a = conn.execute("SELECT * FROM analysis_runs WHERE id=?", (populated,)).fetchone()
    cut = {"run": a["cutoff_run_id"], "record": a["cutoff_record_id"], "dns": a["cutoff_dns_id"]}
    b = run_analysis(conn, cfg, as_of=a["as_of"], cutoffs=cut, log=lambda *_: None)
    bb = conn.execute("SELECT * FROM analysis_runs WHERE id=?", (b,)).fetchone()
    assert (bb["dataset_sha256"], bb["results_sha256"]) == (a["dataset_sha256"], a["results_sha256"])


def test_new_observations_do_not_change_a_past_analysis(conn, cfg, populated):
    before = conn.execute("SELECT dataset_sha256 FROM analysis_runs WHERE id=?", (populated,)).fetchone()[0]
    cfg["dns"]["recheck_hours"] = 0.0
    dnscheck(conn, cfg, ["tollpass.dvhl.cam"], resolve=fake_resolver({}), log=lambda *_: None)
    a = conn.execute("SELECT * FROM analysis_runs WHERE id=?", (populated,)).fetchone()
    cut = {"run": a["cutoff_run_id"], "record": a["cutoff_record_id"], "dns": a["cutoff_dns_id"]}
    assert dataset_sha256(conn, cut)[0] == before
    assert dataset_sha256(conn, cutoffs_now(conn))[0] != before


def test_report_is_byte_identical_across_regenerations(conn, cfg, populated):
    r1 = json.dumps(report(conn, populated, cfg)["results"], sort_keys=True)
    r2 = json.dumps(report(conn, populated, cfg)["results"], sort_keys=True)
    assert r1 == r2
    p = report(conn, populated, cfg)["provenance"]
    assert p["results_sha256_recorded"] == p["results_sha256_regenerated"]


def test_snapshot_verify_and_replay_reproduce(conn, cfg, populated, tmp_path):
    man = export(conn, populated, tmp_path / "snaps")
    assert verify(man) == {"file_sha256_ok": True, "dataset_sha256_ok": True,
                           "dataset_sha256": json.loads(Path(man).read_text())["dataset_sha256"]}
    res = replay(man, cfg, work_dir=str(tmp_path))
    assert res["reproduced"] is True, res


def test_snapshot_file_is_byte_deterministic(conn, cfg, populated, tmp_path):
    a = Path(export(conn, populated, tmp_path / "a"))
    b = Path(export(conn, populated, tmp_path / "b"))
    ga = a.with_name(a.name.replace(".manifest.json", ".jsonl.gz"))
    gb = b.with_name(b.name.replace(".manifest.json", ".jsonl.gz"))
    assert ga.read_bytes() == gb.read_bytes()


def test_tampered_snapshot_is_detected_and_not_replayed(conn, cfg, populated, tmp_path):
    man = Path(export(conn, populated, tmp_path / "s"))
    data = man.with_name(man.name.replace(".manifest.json", ".jsonl.gz"))
    lines = gzip.decompress(data.read_bytes()).decode().splitlines()
    i = next(k for k, ln in enumerate(lines) if '"t":"record"' in ln and "tollpass" in ln)
    lines[i] = lines[i].replace("tollpass", "tollpasz", 1)
    data.write_bytes(gzip.compress(("\n".join(lines) + "\n").encode(), mtime=0))
    v = verify(man)
    assert not v["file_sha256_ok"] and not v["dataset_sha256_ok"]
    assert replay(man, cfg, work_dir=str(tmp_path))["reproduced"] is False


def test_manifest_cannot_point_outside_its_directory(conn, cfg, populated, tmp_path):
    man = Path(export(conn, populated, tmp_path / "s"))
    m = json.loads(man.read_text())
    m["file"] = "../../etc/passwd"
    man.write_text(json.dumps(m))
    with pytest.raises(ValueError):
        verify(man)


def test_export_refuses_if_observations_were_altered(conn, cfg, populated, tmp_path):
    conn.execute("UPDATE source_records SET payload=payload || ' ' WHERE id=1")
    conn.commit()
    with pytest.raises(RuntimeError):
        export(conn, populated, tmp_path / "s")


def test_derived_rows_are_pruned_but_metadata_kept(conn, cfg, populated):
    cfg["analysis"]["keep_derived"] = 1
    for _ in range(2):
        run_analysis(conn, cfg, log=lambda *_: None)
    rows = conn.execute("SELECT id, derived_pruned FROM analysis_runs ORDER BY id").fetchall()
    assert len(rows) == 3 and [r[1] for r in rows] == [1, 1, 0]
    assert conn.execute("SELECT COUNT(*) FROM decisions WHERE analysis_id=?", (rows[0][0],)).fetchone()[0] == 0
    # ...and a pruned analysis can still be regenerated from the observations
    p = report(conn, rows[0][0], cfg)["provenance"]
    assert p["results_sha256_recorded"] == p["results_sha256_regenerated"]
