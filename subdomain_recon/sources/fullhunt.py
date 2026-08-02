from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class FullHuntSource(Source):
    """FullHunt's subdomain discovery API. Needs an API key (free tier available)."""
    name = "fullhunt"
    confidence = "Medium"
    requires_key = "fullhunt"

    def fetch(self, domain: str, ctx: SourceContext):
        api_key = ctx.api_keys.get("fullhunt")
        cache_key = f"fullhunt:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
        r = require_ok_response(
            request_with_retry("GET", url, ctx.config, headers={"X-API-KEY": api_key}),
            self.name, url,
        )

        try:
            hosts = r.json().get("hosts", [])
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
