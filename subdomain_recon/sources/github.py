import json
import re

from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class GitHubSource(Source):
    name = "github"
    confidence = "Medium"
    requires_key = "github"

    def fetch(self, domain: str, ctx: SourceContext):
        token = ctx.api_keys.get("github")
        cache_key = f"github:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = "https://api.github.com/search/code"
        r = require_ok_response(
            request_with_retry("GET", url, ctx.config, params={"q": domain},
                                headers={"Authorization": f"token {token}"}),
            self.name, url,
        )

        hosts = []
        try:
            for item in r.json().get("items", []):
                blob = json.dumps(item)
                hosts.extend(re.findall(rf"[a-zA-Z0-9._-]+\.{re.escape(domain)}", blob))
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
