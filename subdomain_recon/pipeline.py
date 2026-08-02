"""
Pipeline orchestrator. Wires together: sources (plugins) -> normalize ->
merge/dedupe -> smart wildcard detection -> DNS validate -> multi-source
recursive enumeration (crt.sh SAN chaining, Wayback, GitHub, optional
active JS/CSP scraping) -> word extraction -> permutation -> re-validate ->
reverse DNS + ASN -> cloud discovery -> DNS records -> enrichment
(TTL/resolver/RTT/DNSSEC) -> final filter/validate -> export.

Every stage is checkpointed; with --resume, completed stages are loaded
from disk instead of recomputed.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from pathlib import Path

from . import dns_utils, enrichment, recursion_expanders, report_builder, wordgen
from .cache import Cache
from .checkpoint import CheckpointManager
from .metadata import MetadataStore
from .metrics import MetricsCollector
from .normalize import normalize_hostname, is_excluded, in_scope, depth_of
from .progress import ProgressReporter, log_stage_progress
from .sources import instantiate_all, SourceContext


class Pipeline:
    def __init__(self, domain: str, out_dir: str, config: dict, api_keys: dict,
                 resume: bool = False, disable_permutations: bool = False,
                 record_types=None):
        self.domain = domain.strip().lower()
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.config = config
        self.api_keys = api_keys
        self.disable_permutations = disable_permutations
        self.record_types = record_types

        self.cache = Cache(str(self.out_dir / "cache.sqlite3"),
                            default_ttl=config.get("cache_ttl_seconds", 21600))
        self.checkpoints = CheckpointManager(str(self.out_dir), resume=resume)
        self.metadata = MetadataStore(str(self.out_dir / "metadata.json"))
        self.metrics = MetricsCollector()

        self.host_sources: dict[str, set] = defaultdict(set)
        self.wildcard_ips: set = set()
        self.per_level_wildcard_hosts: set = set()
        self.validated: dict[str, list] = {}
        self.perm_validated: dict[str, list] = {}
        self.ptr_map: dict[str, str] = {}
        self.asn_map: dict[str, dict] = {}
        self.cloud_findings: dict = {}
        self.dns_records: dict = {}
        self.enrichment: dict[str, dict] = {}
        self.final_resolved: dict[str, list] = {}
        # Raw output of every pipeline stage, kept around so the exporter
        # can dump one JSON file per stage into output/json/ after the run.
        self.stage_snapshots: dict[str, object] = {}
        # Per-source status ("ok"/"skipped"/"error"), host count, and skip
        # reason -- the Provider Health Summary at the end of a run.
        self.provider_health: dict[str, dict] = {}
        self.raw_mention_count = 0  # total (pre-dedupe) host mentions across all sources

    # ------------------------------------------------------------------ #
    def _stage_cached(self, stage_name: str, compute_fn):
        if self.checkpoints.has(stage_name):
            logging.info(f"[resume] loading checkpoint for {stage_name}")
            data = self.checkpoints.load(stage_name)
            with self.metrics.track(stage_name) as sm:
                sm.success = 1
            self.stage_snapshots[stage_name] = data
            return data
        with self.metrics.track(stage_name) as sm:
            data = compute_fn(sm)
        self.checkpoints.save(stage_name, data)
        self.stage_snapshots[stage_name] = data
        return data

    # ------------------------------------------------------------------ #
    def stage_passive_sources(self):
        def compute(sm):
            import concurrent.futures

            sources = instantiate_all()
            ctx = SourceContext(config=self.config, cache=self.cache, api_keys=self.api_keys)
            result = defaultdict(list)
            health: dict[str, dict] = {}
            total_mentions = 0

            available = []
            for name, src in sorted(sources.items()):
                if not src.available(ctx):
                    if src.requires_key and not ctx.api_keys.get(src.requires_key):
                        reason = f"Missing key ({src.requires_key})"
                    elif src.requires_cli:
                        reason = f"Missing binary ({src.requires_cli})"
                    else:
                        reason = "Not available"
                    health[name] = {"status": "skipped", "hosts": 0, "reason": reason}
                    logging.info(f"[skip] source '{name}' not available: {reason}")
                    continue
                available.append((name, src))

            # Every source used to be queried one at a time -- with 21
            # sources, several of them slow/rate-limited free APIs (crt.sh
            # in particular) or subprocess-spawning CLI tools, that alone
            # could take 10+ minutes before DNS validation, recursion, or
            # permutation even start. Parallelize like every other batch
            # stage in this pipeline; each source's own retry/backoff still
            # applies, but they now overlap instead of stacking serially.
            source_threads = self.config.get("source_threads", 10)
            logging.info(f"[stage] querying {len(available)} available source(s) in parallel "
                         f"({source_threads} workers)")

            def _fetch_one(name, src):
                try:
                    return name, src.fetch(self.domain, ctx), None
                except Exception as e:
                    return name, [], e

            reporter = ProgressReporter(len(available), "Passive sources",
                                         quiet=self.config.get("quiet", False))
            # Same fix as recursion: don't use `with ThreadPoolExecutor(...) as ex:`
            # -- its blocking shutdown on exit would still wait forever for one
            # abnormally slow/huge source response even with a timeout on
            # as_completed(). Explicit non-blocking shutdown + a hard ceiling
            # for the whole stage instead.
            stage_timeout = self.config.get("source_stage_timeout", 180)
            ex = concurrent.futures.ThreadPoolExecutor(max_workers=source_threads)
            try:
                futures = [ex.submit(_fetch_one, name, src) for name, src in available]
                done = 0
                try:
                    for fut in concurrent.futures.as_completed(futures, timeout=stage_timeout):
                        name, raw_hosts, err = fut.result()
                        done += 1
                        reporter.update(1)
                        if err is not None:
                            health[name] = {"status": "error", "hosts": 0, "reason": str(err),
                                             "raw": 0, "rejected": 0, "duplicate_in_source": 0}
                            sm.failure += 1
                            sm.errors.append(f"{name}: {err}")
                            if self.config.get("debug"):
                                logging.error(f"[!] source {name} failed (--debug traceback):",
                                              exc_info=err)
                            else:
                                logging.warning(f"[!] source {name} failed: {err}")
                            continue

                        # Full loss visibility: raw lines this source returned,
                        # how many failed normalize_hostname()/scope/exclusion
                        # (a real parsing problem would show up here as a large
                        # rejected count), how many were the same host repeated
                        # by this source itself, and the final usable count --
                        # so "source X: 0 hosts" is never a black box again.
                        raw_count = 0
                        rejected_count = 0
                        seen_this_source: set[str] = set()
                        duplicate_in_source = 0
                        for raw in raw_hosts:
                            raw_count += 1
                            h = normalize_hostname(raw)
                            if not (h and in_scope(h, self.domain) and not is_excluded(h)):
                                rejected_count += 1
                                continue
                            if h in seen_this_source:
                                duplicate_in_source += 1
                                continue
                            seen_this_source.add(h)
                            result[h].append(name)
                            total_mentions += 1
                        count = len(seen_this_source)

                        health[name] = {
                            "status": "ok", "hosts": count, "reason": None,
                            "raw": raw_count, "rejected": rejected_count,
                            "duplicate_in_source": duplicate_in_source,
                        }
                        if raw_count and count == 0:
                            # Every raw line came back but none survived --
                            # this is the exact symptom this metric exists to
                            # catch: worth a WARNING, not a quiet INFO, so it
                            # doesn't blend into a normal "found nothing" line.
                            logging.warning(f"[!] {name}: got {raw_count} raw line(s) but 0 "
                                            f"normalized -- likely a real parsing/scope issue, "
                                            f"not \"found nothing\". Run with --debug for detail.")
                        else:
                            logging.info(f"[+] {name}: {count} normalized hosts "
                                         f"(raw={raw_count}, rejected={rejected_count}, "
                                         f"dup={duplicate_in_source})")
                        sm.success += 1
                except concurrent.futures.TimeoutError:
                    remaining = len(available) - done
                    logging.warning(
                        f"[stage] hit the {stage_timeout}s stage timeout with {remaining}/"
                        f"{len(available)} source(s) still running (likely one source "
                        f"returning an abnormally large/slow response). Continuing with the "
                        f"{done} that finished in time. Raise --source-stage-timeout if you "
                        f"want to wait longer for slow sources."
                    )
            finally:
                ex.shutdown(wait=False, cancel_futures=True)
            reporter.close()

            self.provider_health = health
            self.raw_mention_count = total_mentions
            return {h: sorted(set(srcs)) for h, srcs in result.items()}

        data = self._stage_cached("01_passive_sources", compute)
        for h, srcs in data.items():
            self.host_sources[h] = set(srcs)
            self.metadata.touch(h, srcs)
        logging.info(f"[stage] total unique candidates: {len(self.host_sources)}")

    def stage_wildcard_detection(self):
        def compute(sm):
            ips = dns_utils.detect_wildcard(
                self.domain, cache=self.cache,
                ttl=self.config.get("cache_ttl_seconds"),
                timeout=self.config.get("dns_timeout", 5),
                resolvers=self.config.get("dns_resolvers"),
            )
            sm.success = 1
            return sorted(ips)

        data = self._stage_cached("02_wildcard_detection", compute)
        self.wildcard_ips = set(data)
        if self.wildcard_ips:
            resolvers = self.config.get("dns_resolvers")
            mode = f"cross-checked across {len(resolvers)} resolvers" if resolvers else "single resolver"
            logging.info(f"[!] wildcard DNS detected ({mode}) -> {sorted(self.wildcard_ips)}")
        else:
            logging.info("[stage] no root wildcard DNS detected (majority-vote, multi-resolver, multi-probe)")

    def stage_initial_validation(self):
        def compute(sm):
            resolved = dns_utils.dns_validate_batch(
                set(self.host_sources.keys()),
                threads=self.config.get("threads", 50),
                cache=self.cache, ttl=self.config.get("cache_ttl_seconds"),
                timeout=self.config.get("dns_timeout", 5),
                retries=self.config.get("retries", 1),
                resolvers=self.config.get("dns_resolvers"),
                progress_desc="Initial DNS validation", quiet=self.config.get("quiet", False),
            )
            resolved = dns_utils.filter_wildcards(resolved, self.wildcard_ips)
            sm.success = len(resolved)
            sm.failure = len(self.host_sources) - len(resolved)
            return resolved

        data = self._stage_cached("03_initial_dns_validation", compute)
        self.validated = data
        for h, ips in data.items():
            self.metadata.mark_validated(h, ips)
        logging.info(f"[stage] initially validated: {len(self.validated)}")

    # ------------------------------------------------------------------ #
    # Multi-source recursive enumeration: expanders live in
    # recursion_expanders.py (crt.sh SAN chaining, Wayback URL mining,
    # GitHub code search, and opt-in active JS/CSP scraping). Each
    # expander returns raw hostname strings; the parent host that
    # produced each candidate is recorded as its discovery_path entry.
    # ------------------------------------------------------------------ #
    def stage_recursive_enumeration(self):
        def compute(sm):
            import concurrent.futures

            ctx = SourceContext(config=self.config, cache=self.cache, api_keys=self.api_keys)

            expanders = recursion_expanders.build_expanders(
                self.config, self.config.get("active_recursion", False)
            )

            # Recursion hits external, often rate-limited APIs (crt.sh in
            # particular) per (host, source) pair -- running these one at a
            # time was the bug: 425 hosts x 3 sources = 1275+ sequential
            # blocking HTTP calls, each carrying its own retry/backoff, so a
            # single slow/rate-limited round could stall for an hour+.
            # Parallelize with a bounded worker pool instead -- deliberately
            # capped lower than the general DNS-validation thread count so
            # we don't hammer a free-tier API hard enough to get IP-banned,
            # but still overlap every call's retry/backoff wait time instead
            # of paying it serially host-by-host.
            recursion_threads = self.config.get("recursion_threads", 15)

            all_validated = dict(self.validated)
            seen = set(all_validated.keys())
            frontier = set(seen)
            discovery = defaultdict(set)  # child -> set(parents)
            max_rounds = self.config.get("max_recursion_rounds", 6)
            round_num = 0

            def _expand_one(h, expand_fn):
                try:
                    raw_hosts, tag = expand_fn(h, ctx)
                    return h, tag, raw_hosts, None
                except Exception as e:
                    return h, None, [], e

            while frontier and round_num < max_rounds:
                round_num += 1

                frontier_cap = self.config.get("max_recursion_frontier_per_round")
                if frontier_cap and len(frontier) > frontier_cap:
                    logging.warning(
                        f"[recursion] round {round_num}: frontier has {len(frontier)} hosts, "
                        f"capping to {frontier_cap} for this round (raise/disable via "
                        f"--config-file: {{\"max_recursion_frontier_per_round\": null}}) -- "
                        f"the rest stay validated, just aren't expanded further this run."
                    )
                    frontier = set(sorted(frontier)[:frontier_cap])

                logging.info(f"[recursion] round {round_num}: expanding {len(frontier)} hosts "
                             f"via {len(expanders)} source(s) ({recursion_threads} parallel workers)")
                candidates = set()
                work_items = [(h, fn) for h in frontier for fn in expanders]

                # CRITICAL: don't use `with ThreadPoolExecutor(...) as ex:` here.
                # Exiting that block calls ex.shutdown(wait=True), which blocks
                # until EVERY submitted task finishes -- so even with a
                # per-future timeout below, a single pathologically slow call
                # (e.g. one host's crt.sh SAN query returning a multi-MB
                # response because it shares a wildcard cert with thousands
                # of unrelated names) would still hold the entire round
                # hostage on the way out of the `with` block. This was the
                # actual "stuck for hours despite parallelization" bug --
                # parallel execution was working, but the exit path silently
                # re-serialized on the slowest straggler.
                round_timeout = self.config.get("recursion_round_timeout", 180)
                ex = concurrent.futures.ThreadPoolExecutor(max_workers=recursion_threads)
                try:
                    futures = [ex.submit(_expand_one, h, fn) for h, fn in work_items]
                    done = 0
                    try:
                        for fut in concurrent.futures.as_completed(futures, timeout=round_timeout):
                            h, tag, raw_hosts, err = fut.result()
                            done += 1
                            if err is not None:
                                sm.failure += 1
                                sm.errors.append(str(err))
                                continue
                            sm.success += 1
                            for raw in raw_hosts:
                                nh = normalize_hostname(raw)
                                if nh and in_scope(nh, self.domain) and not is_excluded(nh) and nh not in seen:
                                    candidates.add(nh)
                                    self.host_sources[nh].add(tag)
                                    self.metadata.touch(nh, [tag])
                                    discovery[nh].add(h)
                            if done % 100 == 0 or done == len(work_items):
                                logging.info(f"[recursion] round {round_num}: {done}/{len(work_items)} "
                                             f"(host, source) calls done, {len(candidates)} new candidates so far")
                    except concurrent.futures.TimeoutError:
                        remaining = len(work_items) - done
                        logging.warning(
                            f"[recursion] round {round_num}: hit the {round_timeout}s round timeout "
                            f"with {remaining}/{len(work_items)} (host, source) calls still running "
                            f"(likely one or two abnormally large/slow responses -- e.g. a host sharing "
                            f"a wildcard certificate with thousands of unrelated SANs on crt.sh). "
                            f"Continuing with the {done} that finished in time rather than waiting "
                            f"indefinitely. Raise --recursion-round-timeout if you want to wait longer."
                        )
                finally:
                    # wait=False + cancel_futures: return immediately, drop any
                    # not-yet-started work, and don't block on already-running
                    # threads -- they'll finish in the background and their
                    # results are simply discarded. Threads can't be forcibly
                    # killed in Python, so this is the correct non-blocking
                    # shutdown rather than a true cancellation.
                    ex.shutdown(wait=False, cancel_futures=True)

                if not candidates:
                    logging.info("[recursion] no new hosts, stopping")
                    break

                newly_resolved = dns_utils.dns_validate_batch(
                    candidates, threads=self.config.get("threads", 50),
                    cache=self.cache, ttl=self.config.get("cache_ttl_seconds"),
                    timeout=self.config.get("dns_timeout", 5),
                    retries=self.config.get("retries", 1),
                    resolvers=self.config.get("dns_resolvers"),
                    progress_desc=f"Recursion round {round_num} DNS validation",
                    quiet=self.config.get("quiet", False),
                )
                newly_resolved = dns_utils.filter_wildcards(newly_resolved, self.wildcard_ips)
                new_valid = {h: ips for h, ips in newly_resolved.items() if h not in seen}
                if not new_valid:
                    logging.info("[recursion] candidates found but none validated, stopping")
                    break

                for nh in new_valid:
                    for parent in discovery.get(nh, ()):
                        self.metadata.add_discovery_path(nh, parent)

                all_validated.update(new_valid)
                seen.update(new_valid.keys())
                frontier = set(new_valid.keys())

            return all_validated

        data = self._stage_cached("04_recursive_enumeration", compute)
        self.validated = data
        for h, ips in data.items():
            self.metadata.mark_validated(h, ips)
        logging.info(f"[stage] validated after recursion: {len(self.validated)}")

    def stage_word_extraction(self):
        def compute(sm):
            words = wordgen.extract_words(set(self.validated.keys()), self.domain)
            sm.success = len(words)
            return sorted(words)

        data = self._stage_cached("05_word_extraction", compute)
        self.words = set(data)
        logging.info(f"[stage] extracted {len(self.words)} words")

    def stage_permutation_validation(self):
        if self.disable_permutations:
            self.perm_validated = {}
            return

        def compute(sm):
            import concurrent.futures

            max_depth = self.config.get("max_depth", 5)
            limit = self.config.get("perm_limit_per_level", 3000)
            resolvers = self.config.get("dns_resolvers")

            candidate_bases = {h for h in self.validated if depth_of(h, self.domain) < max_depth}

            per_host_wildcard = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.get("threads", 50)) as ex:
                futures = {
                    ex.submit(
                        dns_utils.detect_wildcard_for_host, h, resolvers, self.cache,
                        self.config.get("cache_ttl_seconds"), self.config.get("dns_timeout", 5), 2,
                    ): h
                    for h in candidate_bases
                }
                for fut in concurrent.futures.as_completed(futures):
                    h = futures[fut]
                    ips = fut.result()
                    if ips:
                        per_host_wildcard[h] = ips

            self.per_level_wildcard_hosts = set(per_host_wildcard.keys())
            usable_bases = candidate_bases - self.per_level_wildcard_hosts
            if per_host_wildcard:
                preview = sorted(per_host_wildcard.keys())[:10]
                logging.info(f"[stage] {len(per_host_wildcard)} host(s) have their own wildcard DNS "
                             f"and won't be expanded further: {preview}"
                             f"{'...' if len(per_host_wildcard) > 10 else ''}")

            perms = wordgen.generate_deep_permutations(
                usable_bases, self.domain, self.words, max_depth, limit
            )
            perm_parent = {}
            for base in usable_bases:
                bd = depth_of(base, self.domain)
                if bd < 0 or bd >= max_depth:
                    continue
                for w in list(self.words)[:limit]:
                    perm_parent[f"{w}.{base}"] = base

            logging.info(f"[stage] generated {len(perms)} permutations (max_depth={max_depth})")
            resolved = dns_utils.dns_validate_batch(
                perms, threads=self.config.get("threads", 50),
                cache=self.cache, ttl=self.config.get("cache_ttl_seconds"),
                timeout=self.config.get("dns_timeout", 5),
                retries=self.config.get("retries", 1),
                resolvers=resolvers,
                progress_desc="Permutation DNS validation", quiet=self.config.get("quiet", False),
            )
            resolved = dns_utils.filter_wildcards(resolved, self.wildcard_ips)
            extra_wildcard_ips = set()
            for ips in per_host_wildcard.values():
                extra_wildcard_ips |= set(ips)
            resolved = dns_utils.filter_wildcards(resolved, extra_wildcard_ips)

            for nh in resolved:
                parent = perm_parent.get(nh)
                if parent:
                    self.metadata.add_discovery_path(nh, parent)

            sm.success = len(resolved)
            sm.failure = len(perms) - len(resolved)
            return resolved

        data = self._stage_cached("06_permutation_validation", compute)
        self.perm_validated = data
        for h, ips in data.items():
            self.host_sources[h].add("permutation")
            self.metadata.touch(h, ["permutation"])
            self.metadata.mark_validated(h, ips)
        logging.info(f"[stage] new hosts from permutations: {len(self.perm_validated)}")

    def stage_reverse_dns(self):
        all_validated = {**self.validated, **self.perm_validated}
        all_ips = {ip for ips in all_validated.values() for ip in ips}

        def compute(sm):
            ptr = dns_utils.reverse_dns_batch(
                all_ips, threads=self.config.get("threads", 50),
                cache=self.cache, ttl=self.config.get("cache_ttl_seconds"),
                timeout=self.config.get("dns_timeout", 5),
                quiet=self.config.get("quiet", False),
            )
            sm.success = len(ptr)
            return ptr

        data = self._stage_cached("07_reverse_dns", compute)
        self.ptr_map = data
        self._all_validated = all_validated

        def compute_asn(sm):
            asn_map = {}
            for ip in all_ips:
                info = enrichment.asn_lookup(
                    ip, cache=self.cache, ttl=self.config.get("cache_ttl_seconds"),
                    timeout=self.config.get("dns_timeout", 5),
                )
                if info:
                    asn_map[ip] = info
            sm.success = len(asn_map)
            return asn_map

        asn_data = self._stage_cached("07b_asn_lookup", compute_asn)
        self.asn_map = asn_data
        logging.info(f"[stage] PTR records found: {len(self.ptr_map)}, ASN records found: {len(self.asn_map)}")

    def stage_cloud_discovery(self):
        all_validated = getattr(self, "_all_validated", {**self.validated, **self.perm_validated})

        def compute(sm):
            findings = enrichment.cloud_asset_discovery(
                set(all_validated.keys()), threads=self.config.get("threads", 50),
                cache=self.cache, ttl=self.config.get("cache_ttl_seconds"),
                timeout=self.config.get("dns_timeout", 5),
                quiet=self.config.get("quiet", False),
            )
            sm.success = len(findings)
            return findings

        data = self._stage_cached("08_cloud_discovery", compute)
        self.cloud_findings = data
        for h, info in data.items():
            self.metadata.set_cloud(h, info)
        logging.info(f"[stage] cloud-hosted assets: {len(self.cloud_findings)}")

    def stage_dns_records(self):
        all_validated = getattr(self, "_all_validated", {**self.validated, **self.perm_validated})

        def compute(sm):
            records = enrichment.collect_dns_records(
                set(all_validated.keys()), record_types=self.record_types,
                threads=self.config.get("threads", 30),
                cache=self.cache, ttl=self.config.get("cache_ttl_seconds"),
                timeout=self.config.get("dns_timeout", 5),
                quiet=self.config.get("quiet", False),
            )
            sm.success = len(records)
            return records

        data = self._stage_cached("09_dns_records", compute)
        self.dns_records = data
        for h, recs in data.items():
            self.metadata.set_dns_records(h, recs)
        logging.info(f"[stage] DNS record sets collected: {len(self.dns_records)}")

    def stage_enrichment(self):
        """TTL / resolver used / response time / best-effort DNSSEC, per
        final-candidate host."""
        all_validated = getattr(self, "_all_validated", {**self.validated, **self.perm_validated})

        def compute(sm):
            enriched = dns_utils.dns_validate_batch(
                set(all_validated.keys()), threads=self.config.get("threads", 30),
                cache=self.cache, ttl=self.config.get("cache_ttl_seconds"),
                timeout=self.config.get("dns_timeout", 5),
                retries=self.config.get("retries", 1),
                resolvers=self.config.get("dns_resolvers"),
                enrich=True, progress_desc="DNS enrichment", quiet=self.config.get("quiet", False),
            )
            out = {}
            for h, payload in enriched.items():
                out[h] = {k: v for k, v in payload.items() if k != "ips"}
            sm.success = len(out)
            return out

        data = self._stage_cached("10_enrichment", compute)
        self.enrichment = data
        for h, info in data.items():
            self.metadata.set_enrichment(h, info)
        logging.info(f"[stage] DNS enrichment (TTL/resolver/RTT/DNSSEC) collected: {len(self.enrichment)}")

    def stage_final_filter_validation(self):
        all_validated = getattr(self, "_all_validated", {**self.validated, **self.perm_validated})

        def compute(sm):
            candidates = {h for h in all_validated if in_scope(h, self.domain) and not is_excluded(h)}
            final = dns_utils.dns_validate_batch(
                candidates, threads=self.config.get("threads", 50),
                cache=self.cache, ttl=self.config.get("cache_ttl_seconds"),
                timeout=self.config.get("dns_timeout", 5),
                retries=self.config.get("retries", 1),
                resolvers=self.config.get("dns_resolvers"),
                progress_desc="Final DNS validation", quiet=self.config.get("quiet", False),
            )
            final = dns_utils.filter_wildcards(final, self.wildcard_ips)
            sm.success = len(final)
            sm.failure = len(candidates) - len(final)
            return final

        data = self._stage_cached("11_final_filter_validation", compute)
        self.final_resolved = data
        for h, ips in data.items():
            self.metadata.mark_validated(h, ips)
            self.metadata.set_ptr(h, {ip: self.ptr_map[ip] for ip in ips if ip in self.ptr_map})
            self.metadata.set_wildcard(h, h in self.per_level_wildcard_hosts)
        logging.info(f"[stage] final validated hosts: {len(self.final_resolved)}")

    # ------------------------------------------------------------------ #
    def run(self) -> dict:
        t0 = time.time()
        stages = [
            ("Passive sources (19 plugins)", self.stage_passive_sources),
            ("Wildcard detection", self.stage_wildcard_detection),
            ("Initial DNS validation", self.stage_initial_validation),
            ("Recursive enumeration", self.stage_recursive_enumeration),
            ("Word extraction", self.stage_word_extraction),
            ("Permutation validation", self.stage_permutation_validation),
            ("Reverse DNS + ASN", self.stage_reverse_dns),
            ("Cloud discovery", self.stage_cloud_discovery),
            ("DNS records", self.stage_dns_records),
            ("Enrichment (TTL/resolver/RTT/DNSSEC)", self.stage_enrichment),
            ("Final filter + validation", self.stage_final_filter_validation),
        ]
        total = len(stages)
        for i, (name, fn) in enumerate(stages, start=1):
            log_stage_progress(i, total, name)
            fn()

        self.metadata.save()
        self.cache.purge_expired()

        report = self.build_report()
        report["total_runtime_seconds"] = round(time.time() - t0, 2)
        return report

    # ------------------------------------------------------------------ #
    def build_report(self) -> dict:
        return report_builder.build_report(self)
