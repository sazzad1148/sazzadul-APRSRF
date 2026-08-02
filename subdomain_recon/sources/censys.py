import json
import re

from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class CensysSource(Source):
    """Searches Censys certificate data for names under the target domain.
    Needs a Censys API ID + Secret (censys.io account, Basic Auth)."""
    name = "censys"
    confidence = "High"
    requires_key = "censys_id"  # secondary key 'censys_secret' also required, checked in available()

    def available(self, ctx: SourceContext) -> bool:
        return bool(ctx.api_keys.get("censys_id")) and bool(ctx.api_keys.get("censys_secret"))

    def fetch(self, domain: str, ctx: SourceContext):
        api_id = ctx.api_keys.get("censys_id")
        api_secret = ctx.api_keys.get("censys_secret")
        cache_key = f"censys:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = "https://search.censys.io/api/v2/certificates/search"
        r = require_ok_response(
            request_with_retry("GET", url, ctx.config, params={"q": f"names: {domain}", "per_page": 100},
                                auth=(api_id, api_secret)),
            self.name, url,
        )

        try:
            blob = json.dumps(r.json())
            hosts = list(set(re.findall(rf"[a-zA-Z0-9._-]+\.{re.escape(domain)}", blob)))
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
