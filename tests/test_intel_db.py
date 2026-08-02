import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subdomain_recon.intel_db import IntelDB


def _fake_report(domain, hosts, generated_at):
    return {
        "domain": domain,
        "generated_at": generated_at,
        "hosts": [{
            "host": h, "sources": ["crt.sh"], "confidence": 80, "confidence_label": "High",
            "records": {"ips": ["1.2.3.4"]}, "cloud": {}, "wildcard": False,
            "recursive_depth": 1, "discovery_path": [], "tags": [],
            "metadata": {"first_seen": generated_at, "last_seen": generated_at},
        } for h in hosts],
    }


def test_store_and_list_runs(tmp_path):
    db = IntelDB(str(tmp_path / "intel.sqlite3"))
    db.store_run(_fake_report("example.com", ["a.example.com"], 1000), profile="fast")
    db.store_run(_fake_report("example.com", ["a.example.com", "b.example.com"], 2000), profile="fast")

    runs = db.list_runs("example.com")
    assert len(runs) == 2
    assert runs[0]["started_at"] == 2000  # most recent first
    db.close()


def test_latest_run_id_and_before(tmp_path):
    db = IntelDB(str(tmp_path / "intel.sqlite3"))
    r1 = db.store_run(_fake_report("example.com", ["a.example.com"], 1000))
    r2 = db.store_run(_fake_report("example.com", ["b.example.com"], 2000))

    assert db.latest_run_id("example.com") == r2
    assert db.latest_run_id("example.com", before=2000) == r1
    assert db.latest_run_id("nonexistent.com") is None
    db.close()


def test_hosts_for_run(tmp_path):
    db = IntelDB(str(tmp_path / "intel.sqlite3"))
    run_id = db.store_run(_fake_report("example.com", ["a.example.com", "b.example.com"], 1000))
    assert db.hosts_for_run(run_id) == {"a.example.com", "b.example.com"}
    db.close()


def test_host_history_across_runs(tmp_path):
    db = IntelDB(str(tmp_path / "intel.sqlite3"))
    db.store_run(_fake_report("example.com", ["a.example.com"], 1000))
    db.store_run(_fake_report("example.com", ["a.example.com"], 2000))
    history = db.host_history("example.com", "a.example.com")
    assert len(history) == 2
    db.close()


def test_duplicate_hosts_across_runs(tmp_path):
    db = IntelDB(str(tmp_path / "intel.sqlite3"))
    db.store_run(_fake_report("example.com", ["a.example.com", "b.example.com"], 1000))
    db.store_run(_fake_report("example.com", ["b.example.com", "c.example.com"], 2000))
    dup = db.duplicate_hosts_across_runs("example.com")
    assert dup == {"b.example.com": 2}
    db.close()


def test_search(tmp_path):
    db = IntelDB(str(tmp_path / "intel.sqlite3"))
    db.store_run(_fake_report("example.com", ["api.example.com", "dev.example.com"], 1000))
    results = db.search("example.com", "api")
    assert results == ["api.example.com"]
    db.close()
