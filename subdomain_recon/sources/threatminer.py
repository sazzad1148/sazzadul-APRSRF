from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class ThreatMinerSource(Source):
    """ThreatMiner's free domain-intel API (rt=5 returns passive subdomains).
    No key required."""
    name = "threatminer"
    confidence = "Medium"

    def fetch(self, domain: str, ctx: SourceContext):
        cache_key = f"threatminer:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = "https://api.threatminer.org/v2/domain.php"
        r = require_ok_response(
            request_with_retry("GET", url, ctx.config, params={"q": domain, "rt": "5"}), self.name, url,
        )

        try:
            hosts = r.json().get("results", [])
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
