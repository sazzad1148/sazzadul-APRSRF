"""
Base class for a passive source "plugin".

To add a new source WITHOUT touching any core pipeline code:
  1. Create a new file in subdomain_recon/sources/, e.g. my_source.py
  2. Subclass Source, set `name` and `confidence`
  3. Implement fetch(domain, ctx) -> iterable of raw hostname strings
  4. That's it -- the registry in sources/__init__.py auto-discovers any
     Source subclass defined in this package at import time.

`ctx` (SourceContext) gives plugins access to shared config, cache and API
keys without importing pipeline internals.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SourceContext:
    config: dict
    cache: object
    api_keys: dict = field(default_factory=dict)


class Source:
    name: str = "unnamed"
    confidence: str = "Low"           # High / Medium / Low
    requires_cli: str | None = None   # external binary this source needs, if any
    requires_key: str | None = None   # key in ctx.api_keys this source needs, if any

    def available(self, ctx: SourceContext) -> bool:
        """Override for custom availability checks (e.g. binary on PATH,
        or multiple required keys)."""
        if self.requires_key and not ctx.api_keys.get(self.requires_key):
            return False
        return True

    def fetch(self, domain: str, ctx: SourceContext):
        raise NotImplementedError
