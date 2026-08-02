import shutil

from ._cli_helpers import run_cli_and_get_lines
from .base import Source, SourceContext


class FindomainSource(Source):
    """Wraps the findomain CLI (github.com/findomain/findomain) if
    installed and on PATH. Findomain is itself a passive-aggregation tool
    (crt.sh, several APIs, etc) -- used here purely as another candidate
    feed, deduped like everything else downstream."""
    name = "findomain"
    confidence = "Medium"
    requires_cli = "findomain"

    def available(self, ctx: SourceContext) -> bool:
        return shutil.which("findomain") is not None

    def fetch(self, domain: str, ctx: SourceContext):
        timeout = ctx.config.get("http_timeout", 20) * 10
        return run_cli_and_get_lines(["findomain", "-t", domain, "-q"], timeout, "findomain")
