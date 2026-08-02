"""
Builds the final report dict from a completed Pipeline's accumulated
state (final_resolved, host_sources, cloud_findings, enrichment, asn_map,
ptr_map, provider_health, etc). Split out of pipeline.py -- this is pure
assembly/formatting logic with no stage-sequencing concerns, so it doesn't
need to live on the orchestrator itself.
"""
from __future__ import annotations

import time
from collections import defaultdict

from .metadata import confidence_for_host, resolve_confidence_weights
from .normalize import depth_of


def build_report(pipeline) -> dict:
    hosts = []
    asn_groups: dict[str, list] = defaultdict(list)
    provider_groups: dict[str, list] = defaultdict(list)
    confidence_weights = resolve_confidence_weights(pipeline.config.get("confidence_weights"))

    for h in sorted(pipeline.final_resolved.keys()):
        meta = pipeline.metadata.get(h) or {}
        sources = sorted(pipeline.host_sources.get(h, set()))
        ips = pipeline.final_resolved[h]
        cloud = pipeline.cloud_findings.get(h)
        wildcard_flag = h in pipeline.per_level_wildcard_hosts
        enrichment_data = pipeline.enrichment.get(h, {})
        ptr = {ip: pipeline.ptr_map[ip] for ip in ips if ip in pipeline.ptr_map}
        asn_info = {ip: pipeline.asn_map[ip] for ip in ips if ip in pipeline.asn_map}
        conf = confidence_for_host(sources, dns_valid=True, cloud=bool(cloud),
                                    weights=confidence_weights)

        tags = []
        if "permutation" in sources:
            tags.append("permutation")
        if wildcard_flag:
            tags.append("wildcard-suspect")
        if cloud:
            tags.append("cloud")
        if any(s.startswith("recursive-") for s in sources):
            tags.append("recursive")

        host_entry = {
            "host": h,
            "validated": True,
            "sources": sources,
            "provider_count": len(sources),
            "confidence": conf["score"],
            "confidence_label": conf["label"],
            "confidence_breakdown": conf["breakdown"],
            "records": {
                "ips": ips,
                "ttl": enrichment_data.get("ttl"),
                "resolver_used": enrichment_data.get("resolver_used"),
                "response_time_ms": enrichment_data.get("response_time_ms"),
                "dnssec": enrichment_data.get("dnssec", False),
                "dns_records": pipeline.dns_records.get(h, {}),
            },
            "cloud": cloud or {},
            "wildcard": wildcard_flag,
            "recursive_depth": depth_of(h, pipeline.domain),
            "discovery_path": meta.get("discovery_path", []),
            "tags": tags,
            "metadata": {
                "first_seen": meta.get("first_seen"),
                "last_seen": meta.get("last_seen"),
                "validation_time": meta.get("validation_time"),
                "ptr": ptr,
                "asn": asn_info,
            },
        }
        hosts.append(host_entry)

        for ip in ips:
            asn = pipeline.asn_map.get(ip, {}).get("asn")
            if asn:
                asn_groups[asn].append(h)
        if cloud:
            provider_groups[cloud["provider"]].append(h)

    unique_candidates = len(pipeline.host_sources)
    duplicates = max(0, pipeline.raw_mention_count - unique_candidates)

    return {
        "domain": pipeline.domain,
        "generated_at": time.time(),
        "counts": {
            "passive_candidates": unique_candidates,
            "validated_after_recursion": len(pipeline.validated),
            "validated_from_permutations": len(pipeline.perm_validated),
            "final_validated_hosts": len(pipeline.final_resolved),
            "cloud_assets": len(pipeline.cloud_findings),
            "per_level_wildcard_hosts": len(pipeline.per_level_wildcard_hosts),
        },
        "provider_health": pipeline.provider_health,
        "duplicates": {
            "raw_mentions": pipeline.raw_mention_count,
            "unique_hosts": unique_candidates,
            "duplicate_mentions": duplicates,
        },
        "confidence_weights": confidence_weights,
        "wildcard_ips": sorted(pipeline.wildcard_ips),
        "reverse_dns_groups": {
            "by_asn": {asn: sorted(set(hs)) for asn, hs in asn_groups.items()},
            "by_cloud_provider": {p: sorted(set(hs)) for p, hs in provider_groups.items()},
        },
        "metrics": pipeline.metrics.to_dict(),
        "cache_stats": pipeline.cache.stats(),
        "hosts": hosts,
    }
