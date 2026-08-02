from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class AnubisDBSource(Source):
    """jldc.me AnubisDB certificate-transparency aggregator. Free, keyless.
    NOTE: this service has a history of going offline/being unreliable --
    if it's down, this now surfaces as a real Provider Health 'error'
    (e.g. connection refused / DNS failure / 5xx), not a silent 0-hosts."""
    name = "anubisdb"
    confidence = "Medium"

    def fetch(self, domain: str, ctx: SourceContext):
        cache_key = f"anubisdb:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = f"https://jldc.me/anubis/subdomains/{domain}"
        r = require_ok_response(request_with_retry("GET", url, ctx.config), self.name, url)

        try:
            hosts = r.json()
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
