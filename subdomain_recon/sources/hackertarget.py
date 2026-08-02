from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class HackerTargetSource(Source):
    """HackerTarget's free hostsearch API. No key needed, but tightly rate
    limited (shared free-tier IP quota) -- relies on the shared retry/backoff
    helper to behave politely."""
    name = "hackertarget"
    confidence = "Medium"

    def fetch(self, domain: str, ctx: SourceContext):
        cache_key = f"hackertarget:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = "https://api.hackertarget.com/hostsearch/"
        r = require_ok_response(
            request_with_retry("GET", url, ctx.config, params={"q": domain}), self.name, url,
        )
        if "API count exceeded" in r.text:
            raise HTTPSourceError(f"{self.name}: API count exceeded (free-tier rate limit hit)")

        hosts = []
        for line in r.text.splitlines():
            host = line.split(",")[0].strip()
            if host:
                hosts.append(host)

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
