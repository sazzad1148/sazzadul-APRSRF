"""Shared HTTP retry helper used by every source plugin.

Retries on 429 / 5xx / connection failures with exponential backoff + jitter,
honors Retry-After (both delta-seconds and HTTP-date forms), and never
retries plain 4xx errors (401/403 etc need a valid key, not a retry).
"""
from __future__ import annotations

import random
import time
from email.utils import parsedate_to_datetime

import requests

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class HTTPSourceError(RuntimeError):
    """An HTTP-based source failed in a way that should show up as a
    Provider Health 'error' (with the real reason), not a silent
    'ok, 0 hosts' -- mirrors CLISourceError for CLI-tool-based sources.
    Covers: every retry exhausted with a connection failure (request_with_retry
    returns None), or a non-2xx response that made it through retries
    (e.g. a persistent 4xx, or a 5xx that outlasted the retry budget)."""


def require_ok_response(response, source_name: str, url: str):
    """Raises HTTPSourceError if `response` is None (every retry attempt
    failed at the connection level) or not a 2xx. Otherwise returns the
    response unchanged, for the source to parse."""
    if response is None:
        raise HTTPSourceError(
            f"{source_name}: no response for {url} (connection failed after retries -- "
            f"network issue, DNS resolution failure, or the host is unreachable)"
        )
    if not (200 <= response.status_code < 300):
        snippet = (response.text or "")[:200].replace("\n", " ")
        raise HTTPSourceError(f"{source_name}: HTTP {response.status_code} for {url}: {snippet}")
    return response


def _retry_after_seconds(header_value: str | None) -> float | None:
    if not header_value:
        return None
    header_value = header_value.strip()
    if header_value.isdigit():
        return float(header_value)
    try:
        dt = parsedate_to_datetime(header_value)
        return max(0.0, dt.timestamp() - time.time())
    except Exception:
        return None


def request_with_retry(method, url, config, params=None, headers=None, auth=None,
                        data=None, json=None):
    """Returns a requests.Response, or None if every attempt failed with a
    connection-level error (never raises)."""
    config = config or {}
    retries = config.get("retries", 2)
    timeout = config.get("http_timeout", 20)
    base = config.get("backoff_base_seconds", 1.0)
    cap = config.get("backoff_max_seconds", 20.0)

    resp = None
    for attempt in range(1, retries + 2):
        try:
            resp = requests.request(
                method, url, params=params, headers=headers, auth=auth,
                data=data, json=json, timeout=timeout,
            )
        except requests.exceptions.RequestException:
            if attempt > retries:
                return None
            time.sleep(min(cap, base * (2 ** (attempt - 1))) + random.uniform(0, 0.5))
            continue

        if resp.status_code not in RETRYABLE_STATUS or attempt > retries:
            return resp

        wait = _retry_after_seconds(resp.headers.get("Retry-After"))
        if wait is None:
            wait = min(cap, base * (2 ** (attempt - 1))) + random.uniform(0, 0.5)
        time.sleep(wait)

    return resp
