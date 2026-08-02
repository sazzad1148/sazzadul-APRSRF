from urllib.parse import urlparse

from ..http_utils import require_ok_response, request_with_retry
from .base import Source, SourceContext


class WaybackSource(Source):
    """Wayback Machine CDX API: lists archived URLs under *.domain, from
    which we extract hostnames. Official API, free, no key needed."""
    name = "wayback"
    confidence = "Medium"

    def fetch(self, domain: str, ctx: SourceContext):
        cache_key = f"wayback:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = "https://web.archive.org/cdx/search/cdx"
        r = require_ok_response(
            request_with_retry("GET", url, ctx.config, params={
                "url": f"*.{domain}/*", "output": "text", "fl": "original",
                "collapse": "urlkey", "limit": "10000",
            }),
            self.name, url,
        )

        hosts = []
        for line in r.text.splitlines():
            try:
                host = urlparse(line if "://" in line else f"http://{line}").hostname
                if host:
                    hosts.append(host)
            except Exception:
                continue  # one malformed CDX line shouldn't sink the whole source

        hosts = list(set(hosts))
        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
