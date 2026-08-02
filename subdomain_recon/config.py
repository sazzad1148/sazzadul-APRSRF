"""
Configuration profiles.

Three built-in profiles control speed/thoroughness trade-offs. Any value can
be overridden on the CLI (--threads, --max-depth, ...) or via a custom
--config-file (JSON) that gets merged on top of the chosen profile.

max_depth = how many subdomain "levels" beyond the root domain the recursive
enumeration + permutation stage is allowed to reach, e.g.:
    depth 1: sub.example.com
    depth 2: a.sub.example.com
    ...
    depth 8: h.g.f.e.d.c.b.example.com
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

PROFILES = {
    "fast": {
        "threads": 30,
        "dns_timeout": 3,
        "http_timeout": 10,
        "retries": 1,
        "max_depth": 2,
        "perm_limit_per_level": 500,
        "recursive_crtsh_per_level": True,
        "cache_ttl_seconds": 3600,
        "max_recursion_rounds": 3,
        "recursion_threads": 10,
        "max_recursion_frontier_per_round": 100,
        "source_threads": 8,
        "recursion_round_timeout": 60,
        "source_stage_timeout": 60,
        "backoff_base_seconds": 0.5,
        "backoff_max_seconds": 8.0,
        "dns_resolvers": None,
    },
    "balanced": {
        "threads": 60,
        "dns_timeout": 5,
        "http_timeout": 20,
        "retries": 2,
        "max_depth": 5,
        "perm_limit_per_level": 3000,
        "recursive_crtsh_per_level": True,
        "cache_ttl_seconds": 21600,
        "max_recursion_rounds": 6,
        "recursion_threads": 20,
        "max_recursion_frontier_per_round": 250,
        "source_threads": 12,
        "recursion_round_timeout": 180,
        "source_stage_timeout": 180,
        "backoff_base_seconds": 1.0,
        "backoff_max_seconds": 20.0,
        "dns_resolvers": ["8.8.8.8", "1.1.1.1"],
    },
    "thorough": {
        "threads": 100,
        "dns_timeout": 8,
        "http_timeout": 30,
        "retries": 3,
        "max_depth": 8,
        "perm_limit_per_level": 20000,
        "recursive_crtsh_per_level": True,
        "cache_ttl_seconds": 86400,
        "max_recursion_rounds": 10,
        "recursion_threads": 30,
        "max_recursion_frontier_per_round": 600,
        "source_threads": 19,
        "recursion_round_timeout": 400,
        "source_stage_timeout": 400,
        "backoff_base_seconds": 1.5,
        "backoff_max_seconds": 45.0,
        "dns_resolvers": ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    },
}

DEFAULT_PROFILE = "balanced"


def load_profile(name: str) -> dict:
    if name not in PROFILES:
        raise ValueError(f"Unknown profile '{name}'. Choose from: {list(PROFILES)}")
    return copy.deepcopy(PROFILES[name])


def merge_config_file(cfg: dict, path: str) -> dict:
    """Loads config overrides from `path` and merges them on top of `cfg`.
    Format is picked by extension: .json (always available, stdlib),
    .toml (stdlib `tomllib`, Python 3.11+, read-only -- fine for loading
    overrides), or .yaml/.yml (needs PyYAML installed -- `pip install
    pyyaml`; raises a clear error if it's missing rather than a cryptic
    ImportError deep in a stack trace)."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    suffix = p.suffix.lower()
    text = p.read_text(encoding="utf-8")

    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as e:
            raise ImportError(
                "YAML config files need PyYAML: pip install pyyaml --break-system-packages"
            ) from e
        overrides = yaml.safe_load(text) or {}
    elif suffix == ".toml":
        import tomllib
        overrides = tomllib.loads(text)
    else:
        overrides = json.loads(text)

    cfg = copy.deepcopy(cfg)
    cfg.update(overrides)
    return cfg


def apply_cli_overrides(cfg: dict, args) -> dict:
    cfg = copy.deepcopy(cfg)
    mapping = {
        "threads": args.threads,
        "max_depth": args.max_depth,
        "perm_limit_per_level": args.perm_limit,
        "max_recursion_rounds": args.max_recursion_rounds,
        "recursion_threads": getattr(args, "recursion_threads", None),
        "source_threads": getattr(args, "source_threads", None),
        "recursion_round_timeout": getattr(args, "recursion_round_timeout", None),
        "source_stage_timeout": getattr(args, "source_stage_timeout", None),
        "max_recursion_frontier_per_round": getattr(args, "max_recursion_frontier", None),
    }
    for key, val in mapping.items():
        if val is not None:
            cfg[key] = val
    return cfg
