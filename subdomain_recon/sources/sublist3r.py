import os
import shutil
import subprocess
import tempfile

from ._cli_helpers import CLISourceError
from .base import Source, SourceContext


class Sublist3rSource(Source):
    """Wraps the Sublist3r CLI (github.com/aboul3la/Sublist3r) if installed
    and on PATH as `sublist3r`. Sublist3r writes results to a file rather
    than stdout, so we point it at a temp file and read that back."""
    name = "sublist3r"
    confidence = "Medium"
    requires_cli = "sublist3r"

    def available(self, ctx: SourceContext) -> bool:
        return shutil.which("sublist3r") is not None

    def fetch(self, domain: str, ctx: SourceContext):
        timeout = ctx.config.get("http_timeout", 20) * 15
        fd, tmp_path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        try:
            try:
                result = subprocess.run(
                    ["sublist3r", "-d", domain, "-o", tmp_path],
                    capture_output=True, text=True, timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                raise CLISourceError(f"sublist3r timed out after {timeout:.0f}s") from None
            except FileNotFoundError:
                raise CLISourceError("sublist3r binary not found on PATH") from None

            if result.returncode != 0:
                stderr_lines = (result.stderr or "").strip().splitlines()
                detail = stderr_lines[-1] if stderr_lines else f"exit code {result.returncode}"
                raise CLISourceError(f"sublist3r exited with code {result.returncode}: {detail}")

            with open(tmp_path) as f:
                return [line.strip() for line in f if line.strip()]
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
