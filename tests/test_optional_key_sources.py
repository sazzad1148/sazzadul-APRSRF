import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subdomain_recon.pipeline import Pipeline
from subdomain_recon.sources import SourceContext, instantiate_all

OPTIONAL_KEY_SOURCES = {
    "github": ["github"],
    "censys": ["censys_id", "censys_secret"],
    "virustotal": ["virustotal"],
    "fullhunt": ["fullhunt"],
    "chaos": ["chaos"],
}


def test_optional_key_sources_unavailable_without_any_keys():
    """key absent -> available() is False, source gets skipped, never runs."""
    sources = instantiate_all()
    ctx = SourceContext(config={}, cache=None, api_keys={})
    for name in OPTIONAL_KEY_SOURCES:
        assert not sources[name].available(ctx), f"{name} should be unavailable with no keys"


def test_optional_key_sources_available_once_keyed():
    """key present -> available() is True."""
    sources = instantiate_all()
    for name, required_keys in OPTIONAL_KEY_SOURCES.items():
        api_keys = {k: "dummy-value" for k in required_keys}
        ctx = SourceContext(config={}, cache=None, api_keys=api_keys)
        assert sources[name].available(ctx), f"{name} should be available once keyed"


def test_censys_needs_both_id_and_secret_not_just_one():
    sources = instantiate_all()
    ctx_id_only = SourceContext(config={}, cache=None, api_keys={"censys_id": "x"})
    ctx_secret_only = SourceContext(config={}, cache=None, api_keys={"censys_secret": "y"})
    assert not sources["censys"].available(ctx_id_only)
    assert not sources["censys"].available(ctx_secret_only)


def test_pipeline_runs_to_completion_with_zero_optional_keys(tmp_path):
    """The concrete end-to-end guarantee: with NO optional keys configured
    at all, stage_passive_sources must complete without raising, every
    optional-key source shows up as 'skipped' (not 'error') in provider
    health, and the keyless sources are still attempted normally."""
    import requests

    def _no_net(*a, **k):
        raise requests.exceptions.ConnectionError("mocked: no network in unit tests")

    with mock.patch("requests.request", side_effect=_no_net):
        cfg = {"threads": 5, "cache_ttl_seconds": 60}
        pipeline = Pipeline(domain="example.com", out_dir=str(tmp_path), config=cfg, api_keys={})
        pipeline.stage_passive_sources()

    for name in OPTIONAL_KEY_SOURCES:
        assert pipeline.provider_health[name]["status"] == "skipped"
        assert "Missing key" in pipeline.provider_health[name]["reason"]

    # keyless HTTP sources were at least attempted -- present in
    # provider_health as "error" (mocked network failure) rather than
    # silently absent. CLI-tool sources (subfinder etc.) show "skipped"
    # instead since the binary won't be on PATH in a bare test environment
    # -- both are legitimate "was actually attempted" outcomes.
    for keyless in ("crt.sh", "wayback", "rapiddns"):
        assert keyless in pipeline.provider_health
        assert pipeline.provider_health[keyless]["status"] == "error"
