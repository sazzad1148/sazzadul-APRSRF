import sys
import time
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subdomain_recon.pipeline import Pipeline
from subdomain_recon.sources.base import Source, SourceContext


def _make_pipeline(tmp_path, **config_overrides):
    cfg = {"threads": 5, "cache_ttl_seconds": 60, "source_threads": 15}
    cfg.update(config_overrides)
    return Pipeline(domain="example.com", out_dir=str(tmp_path), config=cfg, api_keys={})


def _make_slow_source(name, sleep_s, host_count, call_log):
    class _SlowSource(Source):
        def __init__(self):
            self.name = name
            self.confidence = "Medium"

        def available(self, ctx):
            return True

        def fetch(self, domain, ctx):
            time.sleep(sleep_s)
            call_log.append(name)
            return [f"h{i}.{name}.{domain}" for i in range(host_count)]
    return _SlowSource()


def test_passive_sources_run_in_parallel_not_sequentially(tmp_path):
    """Regression test mirroring the recursion-stage fix: stage 1 used to
    query every source one at a time. With 21 sources x 0.1s each,
    sequential would take >= 2.1s; parallel with 15 workers should finish
    in a couple hundred ms."""
    call_log = []
    fake_sources = {
        f"source{i}": _make_slow_source(f"source{i}", 0.1, 3, call_log) for i in range(21)
    }
    pipeline = _make_pipeline(tmp_path, source_threads=15)

    with mock.patch("subdomain_recon.pipeline.instantiate_all", return_value=fake_sources):
        t0 = time.time()
        pipeline.stage_passive_sources()
        elapsed = time.time() - t0

    assert len(call_log) == 21
    assert elapsed < 1.2, f"stage 1 took {elapsed:.2f}s -- looks sequential again, not parallel"
    assert len(pipeline.host_sources) == 21 * 3  # every source's hosts made it through


def test_passive_sources_provider_health_populated_correctly(tmp_path):
    call_log = []
    ok_source = _make_slow_source("ok-source", 0.0, 5, call_log)

    class _ErrorSource(Source):
        name = "error-source"
        confidence = "Medium"

        def fetch(self, domain, ctx):
            raise RuntimeError("simulated failure")

    fake_sources = {"ok-source": ok_source, "error-source": _ErrorSource()}
    pipeline = _make_pipeline(tmp_path, source_threads=5)

    with mock.patch("subdomain_recon.pipeline.instantiate_all", return_value=fake_sources):
        pipeline.stage_passive_sources()

    assert pipeline.provider_health["ok-source"]["status"] == "ok"
    assert pipeline.provider_health["ok-source"]["hosts"] == 5
    assert pipeline.provider_health["error-source"]["status"] == "error"
    assert "simulated failure" in pipeline.provider_health["error-source"]["reason"]


def test_passive_sources_skipped_when_unavailable(tmp_path):
    class _UnavailableSource(Source):
        name = "unavailable_source"
        confidence = "Medium"
        requires_key = "some_key"

        def fetch(self, domain, ctx):
            raise AssertionError("fetch() should never be called for an unavailable source")

    pipeline = _make_pipeline(tmp_path)
    with mock.patch("subdomain_recon.pipeline.instantiate_all",
                     return_value={"unavailable_source": _UnavailableSource()}):
        pipeline.stage_passive_sources()

    assert pipeline.provider_health["unavailable_source"]["status"] == "skipped"
    assert "Missing key" in pipeline.provider_health["unavailable_source"]["reason"]


def test_source_stage_timeout_does_not_wait_for_one_pathologically_slow_source(tmp_path):
    """Same class of bug as the recursion-round fix: a single abnormally
    slow/huge source response must not hold up the whole stage 1 forever."""
    pipeline = _make_pipeline(tmp_path, source_threads=10, source_stage_timeout=1)

    def _make_source(name, sleep_s):
        class _S(Source):
            def __init__(self):
                self.name = name
                self.confidence = "Medium"

            def available(self, ctx):
                return True

            def fetch(self, domain, ctx):
                time.sleep(sleep_s)
                return [f"h.{name}.{domain}"]
        return _S()

    fake_sources = {f"fast{i}": _make_source(f"fast{i}", 0.0) for i in range(5)}
    fake_sources["pathologically-slow"] = _make_source("pathologically-slow", 30)

    with mock.patch("subdomain_recon.pipeline.instantiate_all", return_value=fake_sources):
        t0 = time.time()
        pipeline.stage_passive_sources()
        elapsed = time.time() - t0

    assert elapsed < 5, (
        f"stage 1 took {elapsed:.1f}s -- source_stage_timeout isn't being enforced"
    )
    for i in range(5):
        assert pipeline.provider_health[f"fast{i}"]["status"] == "ok"


def test_passive_sources_tracks_raw_rejected_duplicate_breakdown(tmp_path):
    """The concrete fix for the 'subfinder: 0 hosts but works fine by hand'
    class of confusion: every source's provider_health entry now carries
    raw/rejected/duplicate_in_source counts, so a real parsing/scope
    problem (raw>0, hosts==0) is visibly distinguishable from a source
    that just legitimately found nothing (raw==0)."""

    class _MixedSource(Source):
        name = "mixed-source"
        confidence = "Medium"

        def fetch(self, domain, ctx):
            return [
                "a.example.com",       # valid, unique
                "b.example.com",       # valid, unique
                "a.example.com",       # valid, but duplicate within this source
                "not a host!!",        # invalid -- rejected by normalize_hostname
                "totally-off-scope.other-domain.com",  # valid syntax, wrong domain -- rejected
            ]

    pipeline = _make_pipeline(tmp_path)
    with mock.patch("subdomain_recon.pipeline.instantiate_all",
                     return_value={"mixed-source": _MixedSource()}):
        pipeline.stage_passive_sources()

    info = pipeline.provider_health["mixed-source"]
    assert info["status"] == "ok"
    assert info["raw"] == 5
    assert info["hosts"] == 2          # a.example.com, b.example.com
    assert info["duplicate_in_source"] == 1
    assert info["rejected"] == 2       # "not a host!!" + off-scope domain


def test_passive_sources_flags_raw_data_but_zero_normalized_as_anomaly(tmp_path):
    """The exact symptom from the bug report: a source returns real data
    but none of it survives normalization -- this must be visibly
    different from a source that genuinely found nothing."""

    class _AllRejectedSource(Source):
        name = "all-rejected-source"
        confidence = "Medium"

        def fetch(self, domain, ctx):
            return ["not-a-valid-host!!!", "###also-bad###", "wrong.other-domain.com"]

    pipeline = _make_pipeline(tmp_path)
    with mock.patch("subdomain_recon.pipeline.instantiate_all",
                     return_value={"all-rejected-source": _AllRejectedSource()}):
        pipeline.stage_passive_sources()

    info = pipeline.provider_health["all-rejected-source"]
    assert info["status"] == "ok"      # not an error -- the source itself ran fine
    assert info["raw"] == 3
    assert info["hosts"] == 0
    assert info["rejected"] == 3       # <- this is what makes it diagnosable
