import subprocess
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subdomain_recon.sources._cli_helpers import CLISourceError, run_cli_and_get_lines
from subdomain_recon.pipeline import Pipeline
from subdomain_recon.sources.base import Source, SourceContext


def _fake_completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["x"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_run_cli_and_get_lines_returns_lines_on_clean_success():
    with mock.patch("subprocess.run", return_value=_fake_completed(0, "a.example.com\nb.example.com\n")):
        lines = run_cli_and_get_lines(["subfinder", "-d", "example.com"], 30, "subfinder")
    assert lines == ["a.example.com", "b.example.com"]


def test_run_cli_and_get_lines_empty_stdout_is_a_valid_result_not_an_error():
    """Exit 0 + empty stdout is a legitimate 'found nothing' -- must NOT raise."""
    with mock.patch("subprocess.run", return_value=_fake_completed(0, "")):
        lines = run_cli_and_get_lines(["subfinder", "-d", "example.com"], 30, "subfinder")
    assert lines == []


def test_run_cli_and_get_lines_raises_on_nonzero_exit_with_stderr_detail():
    with mock.patch("subprocess.run", return_value=_fake_completed(1, "", "rate limited by provider X\n")):
        try:
            run_cli_and_get_lines(["subfinder", "-d", "example.com"], 30, "subfinder")
            assert False, "expected CLISourceError"
        except CLISourceError as e:
            assert "exited with code 1" in str(e)
            assert "rate limited by provider X" in str(e)


def test_run_cli_and_get_lines_raises_on_timeout():
    with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="subfinder", timeout=30)):
        try:
            run_cli_and_get_lines(["subfinder", "-d", "example.com"], 30, "subfinder")
            assert False, "expected CLISourceError"
        except CLISourceError as e:
            assert "timed out" in str(e)


def test_run_cli_and_get_lines_raises_when_binary_disappears():
    with mock.patch("subprocess.run", side_effect=FileNotFoundError()):
        try:
            run_cli_and_get_lines(["subfinder", "-d", "example.com"], 30, "subfinder")
            assert False, "expected CLISourceError"
        except CLISourceError as e:
            assert "not found on PATH" in str(e)


# --------------------------------------------------------------------- #
# Integration: a source raising CLISourceError must show up as a real
# "error" entry in Pipeline.provider_health (Provider Health Summary),
# not a misleading "ok, 0 hosts" -- this is the actual bug the fix closes.
# --------------------------------------------------------------------- #
class _FakeErrorSource(Source):
    name = "fake_error_source"
    confidence = "Medium"

    def fetch(self, domain, ctx):
        raise CLISourceError("fake_error_source exited with code 1: simulated rate limit")


class _FakeOkSource(Source):
    name = "fake_ok_source"
    confidence = "Medium"

    def fetch(self, domain, ctx):
        return [f"host1.{domain}", f"host2.{domain}"]


def test_provider_health_surfaces_cli_error_not_silent_zero_hosts(tmp_path):
    cfg = {"threads": 5, "cache_ttl_seconds": 60}
    pipeline = Pipeline(domain="example.com", out_dir=str(tmp_path), config=cfg, api_keys={})

    fake_sources = {"fake_error_source": _FakeErrorSource(), "fake_ok_source": _FakeOkSource()}
    with mock.patch("subdomain_recon.pipeline.instantiate_all", return_value=fake_sources):
        pipeline.stage_passive_sources()

    assert pipeline.provider_health["fake_error_source"]["status"] == "error"
    assert "simulated rate limit" in pipeline.provider_health["fake_error_source"]["reason"]
    assert pipeline.provider_health["fake_ok_source"]["status"] == "ok"
    assert pipeline.provider_health["fake_ok_source"]["hosts"] == 2
