"""Hostname normalization, scope and exclusion checks."""
from __future__ import annotations

import re

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

DEFAULT_EXCLUDE_PATTERNS: list[str] = []


def normalize_hostname(raw: str) -> str | None:
    """Best-effort cleanup of a raw hostname string coming from any source
    (API JSON field, certificate SAN, HTML/regex scrape, CLI tool stdout
    line, CDX URL, etc.) into a canonical lowercase FQDN, or None if it
    can't be salvaged into something that looks like a real hostname."""
    if not raw:
        return None
    h = str(raw).strip().lower()
    if not h:
        return None
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h)  # strip scheme
    h = h.split("/")[0]                           # strip path/query
    h = h.split("?")[0]
    h = h.split(":")[0]                           # strip port
    h = h.lstrip("*.")                             # strip wildcard marker
    h = h.rstrip(".")                              # strip trailing dot
    h = h.strip("\"' \t\r\n")
    if not h or " " in h or "@" in h:
        return None
    if not _HOSTNAME_RE.match(h):
        return None
    return h


def is_excluded(host: str, extra_patterns: list[str] | None = None) -> bool:
    patterns = list(DEFAULT_EXCLUDE_PATTERNS) + (extra_patterns or [])
    return any(re.search(p, host) for p in patterns)


def in_scope(host: str, domain: str) -> bool:
    domain = domain.lower()
    host = host.lower()
    return host == domain or host.endswith("." + domain)


def depth_of(host: str, domain: str) -> int:
    """Number of subdomain levels `host` sits below `domain`. 0 means host
    == domain; -1 means host is not actually in scope."""
    domain = domain.lower()
    host = host.lower()
    if host == domain:
        return 0
    if not host.endswith("." + domain):
        return -1
    prefix = host[: -(len(domain) + 1)]
    return prefix.count(".") + 1
