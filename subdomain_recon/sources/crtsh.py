from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class CrtShSource(Source):
    name = "crt.sh"
    confidence = "High"

    def fetch(self, domain: str, ctx: SourceContext):
        cache_key = f"crtsh:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = require_ok_response(request_with_retry("GET", url, ctx.config), self.name, url)

        hosts = []
        try:
            for entry in r.json():
                for line in entry.get("name_value", "").split("\n"):
                    hosts.append(line)
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
