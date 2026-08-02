from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class AlienVaultOTXSource(Source):
    """AlienVault OTX's passive DNS endpoint for a domain. Free, no API key
    required, so it's always available."""
    name = "alienvault_otx"
    confidence = "Medium"

    def fetch(self, domain: str, ctx: SourceContext):
        cache_key = f"otx:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        r = require_ok_response(request_with_retry("GET", url, ctx.config), self.name, url)

        hosts = []
        try:
            for rec in r.json().get("passive_dns", []):
                hostname = rec.get("hostname")
                if hostname:
                    hosts.append(hostname)
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
