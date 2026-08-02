import re

from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class RapidDNSSource(Source):
    """rapiddns.io passive DNS lookup. No official JSON API; we do a light,
    rate-limited HTML fetch and regex out hostnames. Free, no key needed."""
    name = "rapiddns"
    confidence = "Medium"

    def fetch(self, domain: str, ctx: SourceContext):
        cache_key = f"rapiddns:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = "https://rapiddns.io/subdomain/" + domain
        r = require_ok_response(
            request_with_retry("GET", url, ctx.config, params={"full": "1"}), self.name, url,
        )

        try:
            hosts = list(set(re.findall(rf"[a-zA-Z0-9._-]+\.{re.escape(domain)}", r.text)))
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
