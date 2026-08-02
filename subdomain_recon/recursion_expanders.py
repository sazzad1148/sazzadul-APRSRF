"""
Multi-source recursive-enumeration expanders: crt.sh SAN chaining, Wayback
URL mining, GitHub code search, and (opt-in) active JS/CSP scraping.

Split out of pipeline.py to keep the orchestrator focused on sequencing
stages rather than holding every expansion strategy's implementation
inline. Each expander is a plain function `(host, ctx) -> (raw_hosts, tag)`
(or `(host, ctx, config) -> (raw_hosts, tag)` for the one that needs extra
config) so `stage_recursive_enumeration` can put them in a list and call
them uniformly -- the parent host that produced each raw candidate is
recorded by the caller as that candidate's discovery_path entry.
"""
from __future__ import annotations

import re

from .http_utils import request_with_retry


def expand_via_crtsh(host, ctx):
    from .sources.crtsh import CrtShSource
    return CrtShSource().fetch(host, ctx), "recursive-crt.sh"


def expand_via_wayback(host, ctx):
    from .sources.wayback import WaybackSource
    return WaybackSource().fetch(host, ctx), "recursive-wayback"


def expand_via_github(host, ctx):
    if not ctx.api_keys.get("github"):
        return [], "recursive-github"
    from .sources.github import GitHubSource
    return GitHubSource().fetch(host, ctx), "recursive-github"


def expand_via_js_csp(host, ctx, config):
    """Active-recursion only: fetches the host's homepage and pulls
    candidate hostnames out of its Content-Security-Policy header and any
    linked .js file URLs. Off by default -- enable with --active-recursion,
    since this touches the target's own web server rather than only
    querying third-party OSINT APIs."""
    hosts = []
    for scheme in ("https", "http"):
        r = request_with_retry("GET", f"{scheme}://{host}/", config)
        if r is None:
            continue
        csp = r.headers.get("Content-Security-Policy", "")
        hosts += re.findall(r"[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}", csp)
        body = r.text or ""
        for js_url in re.findall(r'src=["\']([^"\']+\.js)["\']', body):
            hosts.append(js_url)
        break
    return hosts, "recursive-js"


def build_expanders(config: dict, active_recursion: bool):
    """Returns the ordered list of `(host, ctx) -> (raw_hosts, tag)`
    expander callables to use for this run -- JS/CSP scraping only
    included when --active-recursion is on."""
    expanders = [expand_via_crtsh, expand_via_wayback, expand_via_github]
    if active_recursion:
        expanders.append(lambda host, ctx: expand_via_js_csp(host, ctx, config))
    return expanders
