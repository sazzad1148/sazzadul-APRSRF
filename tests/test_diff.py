import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subdomain_recon import diff


def test_compute_diff_new_and_removed():
    old = {"a.example.com", "beta.example.com"}
    new = {"a.example.com", "api2.example.com"}
    d = diff.compute_diff(old, new)
    assert d["new"] == ["api2.example.com"]
    assert d["removed"] == ["beta.example.com"]
    assert d["unchanged_count"] == 1
    assert d["old_count"] == 2
    assert d["new_count"] == 2


def test_compute_diff_no_changes():
    hosts = {"a.example.com", "b.example.com"}
    d = diff.compute_diff(hosts, hosts)
    assert d["new"] == []
    assert d["removed"] == []
    assert d["unchanged_count"] == 2


def test_render_diff_text_includes_new_and_removed():
    d = diff.compute_diff({"beta.example.com"}, {"api2.example.com"})
    text = diff.render_diff_text(d)
    assert "NEW" in text and "api2.example.com" in text
    assert "REMOVED" in text and "beta.example.com" in text


def test_load_hosts_from_report_json(tmp_path):
    report = {"domain": "example.com", "hosts": [{"host": "a.example.com"}, {"host": "b.example.com"}]}
    p = tmp_path / "report.json"
    p.write_text(json.dumps(report))
    hosts = diff.load_hosts_from_report_json(str(p))
    assert hosts == {"a.example.com", "b.example.com"}


def test_write_diff_files(tmp_path):
    d = diff.compute_diff({"old.example.com"}, {"new.example.com"})
    diff.write_diff_files(d, tmp_path)
    reports_dir = tmp_path / "reports"
    assert (reports_dir / "diff.json").exists()
    assert (reports_dir / "diff.md").exists()
    data = json.loads((reports_dir / "diff.json").read_text())
    assert data["new"] == ["new.example.com"]
    assert data["removed"] == ["old.example.com"]


def test_load_hosts_from_intel_db():
    class _FakeDB:
        def __init__(self, run_id, hosts):
            self._run_id = run_id
            self._hosts = hosts

        def latest_run_id(self, domain, before=None):
            return self._run_id

        def hosts_for_run(self, run_id):
            return self._hosts

    db = _FakeDB("example.com:1000", {"a.example.com"})
    hosts = diff.load_hosts_from_intel_db(db, "example.com")
    assert hosts == {"a.example.com"}

    empty_db = _FakeDB(None, set())
    assert diff.load_hosts_from_intel_db(empty_db, "example.com") is None
