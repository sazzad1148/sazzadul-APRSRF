from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class VirusTotalSource(Source):
    """VirusTotal's domain-relationship endpoint lists observed subdomains.
    Needs a VirusTotal API key (free tier works, rate-limited)."""
    name = "virustotal"
    confidence = "Medium"
    requires_key = "virustotal"

    def fetch(self, domain: str, ctx: SourceContext):
        api_key = ctx.api_keys.get("virustotal")
        cache_key = f"virustotal:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        hosts = []
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        pages = 0
        while url and pages < 5:
            r = require_ok_response(
                request_with_retry("GET", url, ctx.config, headers={"x-apikey": api_key}),
                self.name, url,
            )
            pages += 1
            try:
                data = r.json()
                for item in data.get("data", []):
                    sub_id = item.get("id")
                    if sub_id:
                        hosts.append(sub_id)
                url = (data.get("links") or {}).get("next")
            except Exception as e:
                raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e
            if len(hosts) >= 500:
                break

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
