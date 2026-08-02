import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subdomain_recon.metadata import (
    DEFAULT_CONFIDENCE_WEIGHTS,
    confidence_for_host,
    resolve_confidence_weights,
)
from subdomain_recon.exporters import format_provider_summary
from subdomain_recon.sources import instantiate_all, SourceContext


def test_confidence_breakdown_is_additive_and_explainable():
    r = confidence_for_host(["crt.sh", "recursive-github"], dns_valid=True, cloud=True)
    assert r["breakdown"]["multi_provider"] == DEFAULT_CONFIDENCE_WEIGHTS["multi_provider"]
    assert r["breakdown"]["dns_valid"] == DEFAULT_CONFIDENCE_WEIGHTS["dns_valid"]
    assert r["breakdown"]["recursive"] == DEFAULT_CONFIDENCE_WEIGHTS["recursive"]
    assert r["breakdown"]["cloud"] == DEFAULT_CONFIDENCE_WEIGHTS["cloud"]
    assert r["breakdown"]["github"] == DEFAULT_CONFIDENCE_WEIGHTS["github"]
    assert r["breakdown"]["crt"] == DEFAULT_CONFIDENCE_WEIGHTS["crt"]
    assert r["score"] == sum(r["breakdown"].values())


def test_confidence_permutation_only_gets_penalized():
    r = confidence_for_host(["permutation"], dns_valid=True, cloud=False)
    assert "permutation_penalty" in r["breakdown"]
    assert r["breakdown"]["permutation_penalty"] < 0


def test_confidence_score_clamped_to_0_100():
    weights = resolve_confidence_weights({"multi_provider": 1000, "dns_valid": 1000})
    r = confidence_for_host(["a", "b"], dns_valid=True, cloud=False, weights=weights)
    assert r["score"] == 100

    weights2 = resolve_confidence_weights({"permutation_penalty": -1000, "dns_valid": 0})
    r2 = confidence_for_host(["permutation"], dns_valid=False, cloud=False, weights=weights2)
    assert r2["score"] == 0


def test_confidence_weights_overridable_per_run():
    custom = resolve_confidence_weights({"cloud": 99})
    assert custom["cloud"] == 99
    # unspecified keys keep their default
    assert custom["dns_valid"] == DEFAULT_CONFIDENCE_WEIGHTS["dns_valid"]


def test_provider_summary_formatting():
    report = {
        "provider_health": {
            "crt.sh": {"status": "ok", "hosts": 114, "reason": None},
            "github": {"status": "skipped", "hosts": 0, "reason": "Missing key (github)"},
            "chaos": {"status": "error", "hosts": 0, "reason": "timeout"},
        },
        "duplicates": {"unique_hosts": 421, "duplicate_mentions": 198, "raw_mentions": 619},
    }
    out = format_provider_summary(report)
    assert "crt.sh" in out and "114 hosts" in out
    assert "Missing key (github)" in out
    assert "Error: timeout" in out
    assert "Unique Hosts : 421" in out
    assert "Duplicates   : 198" in out
    assert "Errors       : 1" in out


def test_plugin_auto_discovery_finds_every_source_file():
    """Confirms the auto-loader (sources/__init__.py) discovers every
    Source subclass without any manual registration list."""
    sources = instantiate_all()
    expected_names = {
        "crt.sh", "censys", "certspotter", "chaos",
        "github", "bufferover", "subfinder", "findomain", "assetfinder",
        "sublist3r", "virustotal", "alienvault_otx", "rapiddns", "wayback",
        "urlscan", "hackertarget", "fullhunt", "anubisdb", "threatminer",
    }
    assert expected_names == set(sources.keys()), (
        "source registry changed -- update this test's expected set "
        "(and the '19 production-ready sources' claim in README/ARCHITECTURE) "
        "if a source was intentionally added or removed"
    )

    ctx = SourceContext(config={}, cache=None, api_keys={})
    for name, src in sources.items():
        assert isinstance(src.available(ctx), bool), f"{name}.available() must return bool"
