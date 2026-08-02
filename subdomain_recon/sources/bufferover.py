from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class BufferOverSource(Source):
    name = "bufferover"
    confidence = "Medium"

    def fetch(self, domain: str, ctx: SourceContext):
        cache_key = f"bufferover:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        r = require_ok_response(request_with_retry("GET", url, ctx.config), self.name, url)

        hosts = []
        try:
            data = r.json()
            for rec in (data.get("FDNS_A") or []) + (data.get("RDNS") or []):
                parts = rec.split(",")
                if len(parts) == 2:
                    hosts.append(parts[1])
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
