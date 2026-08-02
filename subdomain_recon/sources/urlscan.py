from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class UrlscanSource(Source):
    """urlscan.io search API. Works without a key at low volume/rate; pass
    --urlscan-key for higher limits and access to private scan history."""
    name = "urlscan"
    confidence = "Medium"

    def available(self, ctx: SourceContext) -> bool:
        return True  # works keyless at low volume

    def fetch(self, domain: str, ctx: SourceContext):
        api_key = ctx.api_keys.get("urlscan")
        cache_key = f"urlscan:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = "https://urlscan.io/api/v1/search/"
        headers = {"API-Key": api_key} if api_key else {}
        r = require_ok_response(
            request_with_retry("GET", url, ctx.config, params={"q": f"domain:{domain}", "size": 200},
                                headers=headers),
            self.name, url,
        )

        hosts = []
        try:
            for result in r.json().get("results", []):
                page = result.get("page", {})
                for field in ("domain", "apexDomain"):
                    val = page.get(field)
                    if val:
                        hosts.append(val)
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        hosts = list(set(hosts))
        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
