import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subdomain_recon.cli import _load_domain_list, _resolve_domains


def test_load_domain_list_skips_blank_and_comment_lines(tmp_path):
    p = tmp_path / "example.txt"
    p.write_text("# a comment\na.com\n\n  b.com  \n#skip\nc.com\n")
    domains = _load_domain_list(str(p))
    assert domains == ["a.com", "b.com", "c.com"]


def test_load_domain_list_dedupes_case_insensitively(tmp_path):
    p = tmp_path / "example.txt"
    p.write_text("a.com\nA.com\nB.COM\nb.com\n")
    domains = _load_domain_list(str(p))
    assert domains == ["a.com", "b.com"]


def test_load_domain_list_missing_file_raises(tmp_path):
    missing = tmp_path / "nope.txt"
    try:
        _load_domain_list(str(missing))
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass


def test_resolve_domains_combines_dash_d_and_domain_list(tmp_path):
    p = tmp_path / "example.txt"
    p.write_text("b.com\nc.com\n")

    class Args:
        domain = "A.com"
        domain_list = str(p)

    domains = _resolve_domains(Args())
    assert domains == ["a.com", "b.com", "c.com"]


def test_resolve_domains_dash_d_only():
    class Args:
        domain = "Example.COM"
        domain_list = None

    assert _resolve_domains(Args()) == ["example.com"]


def test_resolve_domains_no_dupe_when_domain_also_in_list(tmp_path):
    p = tmp_path / "example.txt"
    p.write_text("a.com\nb.com\n")

    class Args:
        domain = "a.com"
        domain_list = str(p)

    assert _resolve_domains(Args()) == ["a.com", "b.com"]


def test_resolve_domains_empty_when_nothing_given():
    class Args:
        domain = None
        domain_list = None

    assert _resolve_domains(Args()) == []
