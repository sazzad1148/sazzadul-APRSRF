"""
Shared helper for CLI-tool-based source plugins (subfinder, findomain,
assetfinder, sublist3r, ...).

The bug this fixes: every one of these used to wrap its subprocess call in
a bare `except Exception: return []`, which makes a real failure (timeout,
missing provider config, tool crash, non-zero exit) completely
indistinguishable from "the tool ran fine and legitimately found zero
subdomains". That's exactly what made a report like "subfinder: 0
normalized hosts" through the pipeline impossible to diagnose, even though
running the same `subfinder` command by hand found 558 results -- there
was no way to tell whether it timed out, crashed, or just found nothing.

`run_cli_and_get_lines` still returns an empty list for a genuinely clean
"found nothing" run (exit 0, empty stdout) -- that's a real, valid result.
It raises `CLISourceError` for everything else, which the pipeline's
per-source try/except in `stage_passive_sources` already catches and
surfaces as a proper `error` entry (with the real reason) in the Provider
Health Summary, instead of a misleading `ok, 0 hosts`.
"""
from __future__ import annotations

import subprocess


class CLISourceError(RuntimeError):
    """A wrapped external CLI tool failed in a way that should show up as
    a Provider Health 'error', not a silent 'ok, 0 hosts'."""


def run_cli_and_get_lines(argv: list[str], timeout: float, tool_name: str) -> list[str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise CLISourceError(f"{tool_name} timed out after {timeout:.0f}s") from None
    except FileNotFoundError:
        raise CLISourceError(f"{tool_name} binary not found on PATH") from None
    except Exception as e:
        raise CLISourceError(f"{tool_name} failed to start: {e}") from e

    if result.returncode != 0:
        stderr_lines = (result.stderr or "").strip().splitlines()
        detail = stderr_lines[-1] if stderr_lines else f"exit code {result.returncode}"
        raise CLISourceError(f"{tool_name} exited with code {result.returncode}: {detail}")

    return result.stdout.splitlines()
