from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class ChaosSource(Source):
    """ProjectDiscovery Chaos dataset. Free, but eligibility-gated signup
    (usually granted to active bug-bounty hunters); needs an API key."""
    name = "chaos"
    confidence = "High"
    requires_key = "chaos"

    def fetch(self, domain: str, ctx: SourceContext):
        api_key = ctx.api_keys.get("chaos")
        cache_key = f"chaos:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        r = require_ok_response(
            request_with_retry("GET", url, ctx.config, headers={"Authorization": api_key}),
            self.name, url,
        )

        try:
            hosts = [f"{sub}.{domain}" for sub in r.json().get("subdomains", [])]
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
