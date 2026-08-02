import shutil

from ._cli_helpers import run_cli_and_get_lines
from .base import Source, SourceContext


class SubfinderSource(Source):
    """Wraps ProjectDiscovery's subfinder CLI if installed and on PATH."""
    name = "subfinder"
    confidence = "Medium"
    requires_cli = "subfinder"

    def available(self, ctx: SourceContext) -> bool:
        return shutil.which("subfinder") is not None

    def fetch(self, domain: str, ctx: SourceContext):
        timeout = ctx.config.get("http_timeout", 20) * 10
        return run_cli_and_get_lines(["subfinder", "-d", domain, "-silent"], timeout, "subfinder")
