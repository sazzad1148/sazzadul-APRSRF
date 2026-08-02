import sys
import time
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subdomain_recon import recursion_expanders
from subdomain_recon.pipeline import Pipeline


def _make_pipeline(tmp_path, domain="example.com", **config_overrides):
    cfg = {
        "threads": 5, "dns_timeout": 1, "http_timeout": 1, "retries": 0,
        "cache_ttl_seconds": 60, "max_recursion_rounds": 1,
        "backoff_base_seconds": 0.1, "backoff_max_seconds": 0.2,
        "recursion_threads": 15, "max_recursion_frontier_per_round": None,
    }
    cfg.update(config_overrides)
    return Pipeline(domain=domain, out_dir=str(tmp_path), config=cfg, api_keys={})


def _slow_noop_expander(sleep_s, tag, call_log):
    """Returns an (host, ctx) -> (raw_hosts, tag) function that sleeps
    briefly and records the call -- stands in for a real expander in
    recursion_expanders.py without touching the network."""
    def _expand(host, ctx):
        time.sleep(sleep_s)
        call_log.append(host)
        return [], tag
    return _expand


def _patch_expanders(sleep_s, call_log):
    return mock.patch.multiple(
        recursion_expanders,
        expand_via_crtsh=_slow_noop_expander(sleep_s, "recursive-crt.sh", call_log),
        expand_via_wayback=_slow_noop_expander(sleep_s, "recursive-wayback", call_log),
        expand_via_github=_slow_noop_expander(sleep_s, "recursive-github", call_log),
    )


def test_recursive_enumeration_runs_in_parallel_not_sequentially(tmp_path):
    """Regression test for the "stuck for an hour" bug: expansion across
    (host, source) pairs must overlap, not block one at a time. With 30
    hosts x 3 sources x 0.05s each, sequential would take >= 4.5s; with 15
    parallel workers it should finish in a couple hundred ms."""
    pipeline = _make_pipeline(tmp_path, recursion_threads=15)
    hosts = {f"h{i}.example.com": ["1.2.3.4"] for i in range(30)}
    pipeline.validated = dict(hosts)

    call_log = []
    with _patch_expanders(0.05, call_log):
        t0 = time.time()
        pipeline.stage_recursive_enumeration()
        elapsed = time.time() - t0

    assert len(call_log) == 30 * 3  # every (host, source) pair was called exactly once
    # Generous upper bound: sequential would be ~4.5s minimum; parallel with
    # 15 workers should comfortably finish well under half that.
    assert elapsed < 2.5, f"recursion took {elapsed:.2f}s -- looks sequential again, not parallel"


def test_recursive_enumeration_frontier_cap_limits_round_size(tmp_path):
    """With a small max_recursion_frontier_per_round, only that many hosts
    (not the full frontier) get expanded in the round."""
    pipeline = _make_pipeline(tmp_path, recursion_threads=10,
                               max_recursion_frontier_per_round=5)
    hosts = {f"h{i}.example.com": ["1.2.3.4"] for i in range(20)}
    pipeline.validated = dict(hosts)

    call_log = []
    with _patch_expanders(0.0, call_log):
        pipeline.stage_recursive_enumeration()

    # Capped to 5 hosts x 3 sources = 15 calls, not 20 x 3 = 60
    assert len(call_log) == 5 * 3
    assert len(set(call_log)) == 5


def test_recursive_enumeration_no_cap_when_disabled(tmp_path):
    pipeline = _make_pipeline(tmp_path, recursion_threads=10,
                               max_recursion_frontier_per_round=0)
    hosts = {f"h{i}.example.com": ["1.2.3.4"] for i in range(10)}
    pipeline.validated = dict(hosts)

    call_log = []
    with _patch_expanders(0.0, call_log):
        pipeline.stage_recursive_enumeration()

    assert len(call_log) == 10 * 3  # all 10 hosts expanded, cap==0 means disabled


def test_build_expanders_excludes_js_csp_by_default():
    expanders = recursion_expanders.build_expanders({}, active_recursion=False)
    assert len(expanders) == 3


def test_build_expanders_includes_js_csp_when_active_recursion_on():
    expanders = recursion_expanders.build_expanders({}, active_recursion=True)
    assert len(expanders) == 4


def test_recursion_round_timeout_does_not_wait_for_one_pathologically_slow_call(tmp_path):
    """The actual "stuck for hours despite parallelization" bug: a
    `with ThreadPoolExecutor(...) as ex:` block's implicit shutdown(wait=True)
    on exit blocks until EVERY submitted task finishes, no matter how many
    already completed -- so one abnormally slow response (e.g. a host
    sharing a wildcard cert with thousands of unrelated crt.sh entries)
    could hold an entire round hostage even though everything else was
    running in parallel correctly. round_timeout must cap total wait time
    regardless of how slow the slowest straggler is."""
    pipeline = _make_pipeline(tmp_path, recursion_threads=10, recursion_round_timeout=1)
    hosts = {f"h{i}.example.com": ["1.2.3.4"] for i in range(10)}
    pipeline.validated = dict(hosts)

    call_log = []

    def _fast(host, ctx):
        call_log.append(host)
        return [], "recursive-crt.sh"

    def _pathologically_slow(host, ctx):
        time.sleep(30)  # far longer than the 1s round_timeout
        call_log.append(host)
        return [], "recursive-wayback"

    def _fast2(host, ctx):
        call_log.append(host)
        return [], "recursive-github"

    with mock.patch.multiple(
        recursion_expanders,
        expand_via_crtsh=_fast,
        expand_via_wayback=_pathologically_slow,
        expand_via_github=_fast2,
    ):
        t0 = time.time()
        pipeline.stage_recursive_enumeration()
        elapsed = time.time() - t0

    # Must return close to round_timeout (1s), NOT wait ~30s for the
    # pathologically slow call to finish.
    assert elapsed < 5, (
        f"round took {elapsed:.1f}s -- round_timeout isn't being enforced, "
        f"a single slow call is still blocking the whole round"
    )
    # The fast calls (crt.sh, github -- 10 hosts each) should have completed
    # well within the timeout; only the slow wayback calls get abandoned.
    fast_call_count = sum(1 for h in call_log if True)  # crude: just confirm some fast work finished
    assert fast_call_count >= 10, "fast expanders should have completed before the timeout hit"
