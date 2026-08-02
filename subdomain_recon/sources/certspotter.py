from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class CertSpotterSource(Source):
    """SSLMate's CertSpotter certificate-transparency API. Works keyless at
    a low rate limit; pass --certspotter-key for a higher quota."""
    name = "certspotter"
    confidence = "High"

    def available(self, ctx: SourceContext) -> bool:
        return True  # keyless tier available

    def fetch(self, domain: str, ctx: SourceContext):
        api_key = ctx.api_keys.get("certspotter")
        cache_key = f"certspotter:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = "https://api.certspotter.com/v1/issuances"
        auth = (api_key, "") if api_key else None
        r = require_ok_response(
            request_with_retry("GET", url, ctx.config,
                                params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
                                auth=auth),
            self.name, url,
        )

        try:
            hosts = list({h for entry in r.json() for h in entry.get("dns_names", [])})
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
