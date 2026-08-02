import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subdomain_recon import normalize as norm
from subdomain_recon.config import PROFILES, apply_cli_overrides, load_profile
from subdomain_recon.metadata import confidence_for_host
from subdomain_recon import exporters


def test_normalize_hostname_basic():
    assert norm.normalize_hostname("Sub.Example.COM") == "sub.example.com"
    assert norm.normalize_hostname("*.example.com") == "example.com"
    assert norm.normalize_hostname("https://api.example.com/path?x=1") == "api.example.com"
    assert norm.normalize_hostname("api.example.com:8443") == "api.example.com"
    assert norm.normalize_hostname("") is None
    assert norm.normalize_hostname("not a host") is None


def test_in_scope_and_depth():
    assert norm.in_scope("api.example.com", "example.com")
    assert norm.in_scope("example.com", "example.com")
    assert not norm.in_scope("example.com.evil.com", "example.com")
    assert norm.depth_of("example.com", "example.com") == 0
    assert norm.depth_of("a.example.com", "example.com") == 1
    assert norm.depth_of("b.a.example.com", "example.com") == 2


def test_profiles_load_and_override():
    cfg = load_profile("fast")
    assert cfg["max_depth"] == PROFILES["fast"]["max_depth"]

    class Args:
        threads = 999
        max_depth = None
        perm_limit = None
        max_recursion_rounds = None

    merged = apply_cli_overrides(cfg, Args())
    assert merged["threads"] == 999
    assert merged["max_depth"] == PROFILES["fast"]["max_depth"]


def test_confidence_scoring():
    single = confidence_for_host(["permutation"], dns_valid=True, cloud=False)
    multi = confidence_for_host(["crt.sh", "recursive-github"], dns_valid=True, cloud=True)
    assert single["label"] == "Low"
    assert multi["label"] == "High"
    assert multi["score"] >= single["score"]


class _FakePipeline:
    """Minimal stand-in exposing stage_snapshots, for exporter tests."""
    def __init__(self, stage_snapshots):
        self.stage_snapshots = stage_snapshots


def _sample_report():
    return {
        "domain": "example.com",
        "generated_at": 0,
        "counts": {"final_validated_hosts": 1},
        "wildcard_ips": [],
        "reverse_dns_groups": {"by_asn": {}, "by_cloud_provider": {}},
        "metrics": {},
        "cache_stats": {},
        "hosts": [{
            "host": "api.example.com",
            "validated": True,
            "sources": ["crt.sh"],
            "provider_count": 1,
            "confidence": 1.0,
            "confidence_label": "High",
            "records": {"ips": ["1.2.3.4"], "ttl": 300, "resolver_used": "8.8.8.8",
                        "response_time_ms": 12.3, "dnssec": False, "dns_records": {}},
            "cloud": {},
            "wildcard": False,
            "recursive_depth": 1,
            "discovery_path": [],
            "tags": [],
            "metadata": {"first_seen": 0, "last_seen": 0, "validation_time": 0,
                         "ptr": {}, "asn": {}},
        }],
    }


def test_reports_export(tmp_path):
    report = _sample_report()
    exporters.write_all(report, str(tmp_path), profile="fast", max_depth=2)

    reports_dir = tmp_path / "reports"
    data = json.loads((reports_dir / "report.json").read_text())
    assert data["hosts"][0]["host"] == "api.example.com"
    assert data["hosts"][0]["records"]["ips"] == ["1.2.3.4"]
    assert (reports_dir / "report.csv").exists()
    assert (reports_dir / "report.html").exists()
    assert (reports_dir / "report.md").exists()


def test_stage_txt_and_json_export(tmp_path):
    report = _sample_report()
    snapshots = {
        "01_passive_sources": {"api.example.com": ["crt.sh"], "dev.example.com": ["wayback"]},
        "03_initial_dns_validation": {"api.example.com": ["1.2.3.4"]},
        "04_recursive_enumeration": {"api.example.com": ["1.2.3.4"]},
        "06_permutation_validation": {},
    }
    pipeline = _FakePipeline(snapshots)
    exporters.write_all(report, str(tmp_path), profile="fast", max_depth=2, pipeline=pipeline)

    txt_dir = tmp_path / "txt"
    assert sorted(txt_dir.glob("*.txt")) == sorted([
        txt_dir / "passive_hosts.txt", txt_dir / "validated_hosts.txt",
        txt_dir / "recursive_hosts.txt", txt_dir / "permutation_hosts.txt",
        txt_dir / "final_hosts.txt",
    ])
    final_lines = (txt_dir / "final_hosts.txt").read_text().strip().splitlines()
    assert final_lines == ["api.example.com"]  # only hostname, nothing else

    json_dir = tmp_path / "json"
    expected = [
        "01_passive_sources.json", "02_wildcard_detection.json",
        "03_initial_dns_validation.json", "04_recursive_enumeration.json",
        "05_word_extraction.json", "06_permutation_validation.json",
        "07_reverse_dns.json", "08_cloud_discovery.json",
        "09_dns_records.json", "10_final_filter_validation.json",
    ]
    for name in expected:
        assert (json_dir / name).exists(), name


def test_cleanup_removes_only_checkpoints(tmp_path):
    (tmp_path / "checkpoints").mkdir()
    (tmp_path / "checkpoints" / "stage.json").write_text("{}")
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "report.json").write_text("{}")

    exporters.cleanup_intermediate(str(tmp_path))

    assert not (tmp_path / "checkpoints").exists()
    assert (tmp_path / "reports" / "report.json").exists()


def test_cleanup_to_minimal_keeps_final_report_and_diff_output(tmp_path):
    """Regression test: --minimal used to silently delete reports/diff.json
    and reports/diff.md when --diff was used in the same run -- those are
    final output (the one thing --diff was asked to produce), not scratch,
    so cleanup_to_minimal must preserve them alongside report.json."""
    (tmp_path / "checkpoints").mkdir()
    (tmp_path / "checkpoints" / "stage.json").write_text("{}")
    (tmp_path / "json").mkdir()
    (tmp_path / "json" / "01_passive_sources.json").write_text("{}")
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "run.log").write_text("x")
    (tmp_path / "txt").mkdir()
    (tmp_path / "txt" / "final_hosts.txt").write_text("a.example.com\n")
    (tmp_path / "txt" / "passive_hosts.txt").write_text("a.example.com\n")
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "report.json").write_text("{}")
    (tmp_path / "reports" / "report.csv").write_text("x")
    (tmp_path / "reports" / "report.html").write_text("x")
    (tmp_path / "reports" / "report.md").write_text("x")
    (tmp_path / "reports" / "diff.json").write_text('{"new": [], "removed": []}')
    (tmp_path / "reports" / "diff.md").write_text("# Diff")
    (tmp_path / "cache.sqlite3").write_text("x")
    (tmp_path / "intel.sqlite3").write_text("x")
    (tmp_path / "metadata.json").write_text("{}")

    exporters.cleanup_to_minimal(str(tmp_path))

    # kept
    assert (tmp_path / "txt" / "final_hosts.txt").exists()
    assert (tmp_path / "reports" / "report.json").exists()
    assert (tmp_path / "reports" / "diff.json").exists()
    assert (tmp_path / "reports" / "diff.md").exists()
    # removed
    assert not (tmp_path / "checkpoints").exists()
    assert not (tmp_path / "json").exists()
    assert not (tmp_path / "logs").exists()
    assert not (tmp_path / "txt" / "passive_hosts.txt").exists()
    assert not (tmp_path / "reports" / "report.csv").exists()
    assert not (tmp_path / "reports" / "report.html").exists()
    assert not (tmp_path / "reports" / "report.md").exists()
    assert not (tmp_path / "cache.sqlite3").exists()
    assert not (tmp_path / "intel.sqlite3").exists()
    assert not (tmp_path / "metadata.json").exists()
