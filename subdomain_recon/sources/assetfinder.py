import shutil

from ._cli_helpers import run_cli_and_get_lines
from .base import Source, SourceContext


class AssetfinderSource(Source):
    name = "assetfinder"
    confidence = "Medium"
    requires_cli = "assetfinder"

    def available(self, ctx: SourceContext) -> bool:
        return shutil.which("assetfinder") is not None

    def fetch(self, domain: str, ctx: SourceContext):
        timeout = ctx.config.get("http_timeout", 20) * 10
        return run_cli_and_get_lines(["assetfinder", "--subs-only", domain], timeout, "assetfinder")
