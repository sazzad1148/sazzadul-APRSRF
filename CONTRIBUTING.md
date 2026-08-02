# Contributing

Thanks for considering a contribution. This project stays deliberately
scoped to **passive + lightly-active subdomain reconnaissance** -- finding
the maximum number of valid subdomains and enriching them (sources, DNS
records, ASN, cloud, confidence). Port scanning, vulnerability scanning,
screenshots, JS secret extraction, and similar are out of scope on purpose;
pipe this tool's output into `httpx`/`nuclei`/`gowitness`/etc. instead of
proposing them here.

## Development setup

```bash
git clone <this-repo>
cd <repo-folder>
python3 -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -r requirements-dev.txt   # runtime deps + pytest, black, ruff, mypy, pre-commit
pre-commit install                     # runs lint + format + tests before every commit
```

## Running the test suite

```bash
pytest tests/ -v
```

All tests must pass fully offline -- no test should depend on real network
access (mock `requests.request`, `subprocess.run`, or `socket.getaddrinfo`
as needed; see any existing test file for the pattern). This keeps the
suite fast, deterministic, and CI-safe regardless of egress restrictions.

## Code style

```bash
black .
ruff check .
mypy .
```

`pyproject.toml` holds the config for all three. New/modified modules
should carry full type hints (`from __future__ import annotations` +
per-function signatures); the codebase isn't 100% strict-`mypy`-clean yet
across every legacy module, but new code should be.

## Adding a new source (the most common contribution)

No core pipeline code needs to change -- drop a file in
`subdomain_recon/sources/`:

```python
# subdomain_recon/sources/my_source.py
from ..http_utils import HTTPSourceError, require_ok_response, request_with_retry
from .base import Source, SourceContext


class MySource(Source):
    name = "my_source"
    confidence = "Medium"          # High / Medium / Low -- informational label
    requires_key = "my_source"     # omit if keyless; must match the api_keys dict key
    # requires_cli = "mytool"      # instead, if this wraps an external CLI binary

    def fetch(self, domain: str, ctx: SourceContext):
        cache_key = f"my_source:{domain}"
        if ctx.cache is not None:
            cached = ctx.cache.get("api", cache_key)
            if cached is not None:
                return cached

        url = f"https://api.example.com/subdomains/{domain}"
        r = require_ok_response(
            request_with_retry("GET", url, ctx.config, headers={"Authorization": ctx.api_keys.get("my_source")}),
            self.name, url,
        )
        try:
            hosts = r.json().get("subdomains", [])
        except Exception as e:
            raise HTTPSourceError(f"{self.name}: failed to parse response: {e}") from e

        if ctx.cache is not None:
            ctx.cache.set("api", cache_key, hosts, ttl=ctx.config.get("cache_ttl_seconds"))
        return hosts
```

Rules of thumb, learned the hard way (see `CHANGELOG.md`):

- **Never swallow a real failure into an empty list.** A clean response
  with genuinely zero results (`2xx` / exit code `0`, empty body) should
  return `[]` -- that's a real answer. Anything else (timeout, non-2xx,
  connection failure, non-zero exit code, a parse exception) should
  **raise** (`HTTPSourceError` for HTTP-based sources via
  `require_ok_response`, `CLISourceError` for CLI-tool-based sources via
  `run_cli_and_get_lines` in `sources/_cli_helpers.py`). The pipeline
  catches it and reports the real reason in the Provider Health Summary;
  silently returning `[]` on a real error is indistinguishable from
  "found nothing" and actively hides bugs.
- Use the shared `request_with_retry` (HTTP) or `run_cli_and_get_lines`
  (CLI) helpers rather than calling `requests`/`subprocess` directly --
  they already handle retry/backoff/timeout consistently.
- Cache API responses via `ctx.cache` the same way every other source
  does (namespace `"api"`, key `f"{source_name}:{domain}"`).
- Don't normalize/filter hostnames yourself -- return raw strings from
  `fetch()`; `normalize_hostname()` in the pipeline handles cleanup.

Add the source's key to `KEY_FLAGS` in `cli.py` and `.env.example` if it
needs one. Verify it's picked up automatically:

```bash
python3 run.py --list-plugins
```

Add a paired unit test in `tests/` (see `test_http_source_error_surfacing.py`
or `test_cli_source_error_surfacing.py` for the pattern -- mock the
transport, assert both the happy path and the error-surfacing path).

## Pull requests

- Keep the scope of a PR focused -- one source, one bugfix, one feature.
- Run `pre-commit run --all-files` (or `black . && ruff check . && pytest
  tests/ -v`) before opening the PR; CI runs the same checks.
- Update `README.md`/`ARCHITECTURE.md` if you're changing documented
  behavior (config keys, CLI flags, output structure), and add a
  `CHANGELOG.md` entry under an `[Unreleased]` heading.
- If you're proposing something from the "explicitly out of scope" list
  above, it'll likely get redirected rather than merged -- worth checking
  `README.md`'s "Project scope" note first.
