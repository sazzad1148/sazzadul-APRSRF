"""Per-host metadata store (first/last seen, sources, discovery chain,
enrichment) and the configurable, points-based confidence engine.

Confidence engine
------------------
Score is built additively out of named, independently-tunable bonuses (and
one penalty), not a black-box source-reliability average. Every weight can
be overridden per-run via ``--config-file`` (key: ``confidence_weights``),
so anyone can tune "what counts as trustworthy" for their own engagement
without touching code::

    // myconfig.json
    { "confidence_weights": { "cloud": 20, "permutation_penalty": -25 } }

Overrides are merged on top of DEFAULT_CONFIDENCE_WEIGHTS -- you only need
to specify the keys you want to change.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

# Points awarded (or, for the one penalty, subtracted) per condition. Final
# score is clamped to [0, 100]. Thresholds below decide the High/Medium/Low
# label. All of this is a *default* -- see module docstring for overriding.
DEFAULT_CONFIDENCE_WEIGHTS: dict[str, int] = {
    "multi_provider": 20,        # 2+ independent sources reported this host
    "dns_valid": 20,              # host actually resolves (true for every final host)
    "recursive": 15,              # discovered via recursive expansion, not just root scan
    "cloud": 10,                  # CNAME chain matched a known cloud/CDN provider
    "github": 15,                 # a GitHub-based source (code search) found it
    "crt": 10,                    # crt.sh (direct or recursive) found it -- CT-log backed
    "permutation_penalty": -15,   # ONLY source is wordlist permutation -- guessed, not observed
}

HIGH_THRESHOLD = 70
MEDIUM_THRESHOLD = 40


def _label_for_score(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "High"
    if score >= MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def resolve_confidence_weights(overrides: dict | None) -> dict[str, int]:
    weights = dict(DEFAULT_CONFIDENCE_WEIGHTS)
    if overrides:
        weights.update(overrides)
    return weights


def confidence_for_host(sources, *, dns_valid: bool = True, cloud: bool = False,
                         weights: dict[str, int] | None = None) -> dict:
    """Additive, explainable confidence score for one host.

    Returns {"score": int 0-100, "label": "High"/"Medium"/"Low",
    "breakdown": {condition: points_awarded, ...}} -- the breakdown is what
    makes the score debuggable/auditable instead of a mystery number."""
    weights = weights or DEFAULT_CONFIDENCE_WEIGHTS
    sources = set(sources or [])
    breakdown: dict[str, int] = {}

    if len(sources) >= 2:
        breakdown["multi_provider"] = weights.get("multi_provider", 0)
    if dns_valid:
        breakdown["dns_valid"] = weights.get("dns_valid", 0)
    if any(s.startswith("recursive-") for s in sources):
        breakdown["recursive"] = weights.get("recursive", 0)
    if cloud:
        breakdown["cloud"] = weights.get("cloud", 0)
    if any("github" in s for s in sources):
        breakdown["github"] = weights.get("github", 0)
    if sources & {"crt.sh", "recursive-crt.sh"}:
        breakdown["crt"] = weights.get("crt", 0)
    if sources == {"permutation"}:
        breakdown["permutation_penalty"] = weights.get("permutation_penalty", 0)

    score = max(0, min(100, sum(breakdown.values())))
    return {"score": score, "label": _label_for_score(score), "breakdown": breakdown}


class MetadataStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self._data: dict[str, dict] = {}
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}

    def _entry(self, host: str) -> dict:
        return self._data.setdefault(host, {})

    def touch(self, host: str, sources) -> None:
        e = self._entry(host)
        now = time.time()
        e.setdefault("first_seen", now)
        e["last_seen"] = now
        existing = set(e.get("sources", []))
        existing.update(sources)
        e["sources"] = sorted(existing)
        e.setdefault("discovery_path", [])

    def add_discovery_path(self, host: str, parent: str | None) -> None:
        if not parent:
            return
        e = self._entry(host)
        path = e.setdefault("discovery_path", [])
        if parent not in path:
            path.append(parent)

    def mark_validated(self, host: str, ips: list[str]) -> None:
        e = self._entry(host)
        e["ips"] = ips
        e["validation_time"] = time.time()

    def set_cloud(self, host: str, info: dict | None) -> None:
        self._entry(host)["cloud"] = info

    def set_dns_records(self, host: str, records: dict) -> None:
        self._entry(host)["dns_records"] = records

    def set_ptr(self, host: str, ptr: dict) -> None:
        self._entry(host)["ptr"] = ptr

    def set_wildcard(self, host: str, flag: bool) -> None:
        self._entry(host)["wildcard"] = flag

    def set_enrichment(self, host: str, enrichment: dict) -> None:
        self._entry(host)["enrichment"] = enrichment

    def set_asn(self, host: str, asn_info: dict) -> None:
        self._entry(host)["asn"] = asn_info

    def get(self, host: str) -> dict:
        return self._data.get(host, {})

    def save(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2, default=list), encoding="utf-8")
