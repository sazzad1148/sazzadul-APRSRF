"""
Core DNS logic lives here -- wildcard detection and validation/PTR:

  * detect_wildcard / detect_wildcard_for_host -- multi-resolver, multi-probe
    wildcard DNS detection with a majority-vote quorum (root domain and
    per-level/per-host respectively).
  * dns_validate_batch -- threaded A/AAAA resolution, optionally enriched
    with TTL, which resolver answered, response time, and a best-effort
    DNSSEC (AD-flag) check.
  * reverse_dns_batch -- threaded PTR lookups.

ASN lookup, cloud/CDN fingerprinting, and full DNS record-set collection
live in enrichment.py instead -- those are enrichment layered on top of
already-validated hosts, not part of the validate/filter path itself.

Falls back to Python's stdlib `socket` module for basic A-lookups if
dnspython isn't installed, but AAAA/CNAME/MX/TXT/NS/PTR/TTL/DNSSEC all
require dnspython.
"""
from __future__ import annotations

import concurrent.futures
import random
import socket
import string
import time

from .progress import ProgressReporter

try:
    import dns.flags
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.resolver
    import dns.reversename
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


def _random_label(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _resolve_ips(host: str, resolver_ip: str | None, timeout: float) -> set:
    ips = set()
    try:
        if _HAS_DNSPYTHON:
            r = dns.resolver.Resolver()
            if resolver_ip:
                r.nameservers = [resolver_ip]
            r.lifetime = timeout
            r.timeout = timeout
            for rtype in ("A", "AAAA"):
                try:
                    ans = r.resolve(host, rtype)
                    ips.update(str(rr) for rr in ans)
                except Exception:
                    continue
        else:
            for info in socket.getaddrinfo(host, None):
                ips.add(info[4][0])
    except Exception:
        pass
    return ips


# --------------------------------------------------------------------- #
# Wildcard detection
# --------------------------------------------------------------------- #
def detect_wildcard(domain, cache=None, ttl=None, timeout=5, resolvers=None):
    """Probe several random, essentially-guaranteed-unregistered labels
    under `domain`, across every configured resolver. An IP only counts as
    part of the wildcard signature if it appears for a MAJORITY of
    probe/resolver combinations -- this filters out a single resolver's
    stale cache entry or a one-off transient answer, which a naive
    single-probe/single-resolver check would misreport as a real
    wildcard (or miss entirely)."""
    resolver_list = resolvers or [None]
    cache_key = f"wildcard:{domain}:{resolver_list}"
    if cache is not None:
        cached = cache.get("dns", cache_key)
        if cached is not None:
            return set(cached)

    probes = [f"{_random_label()}.{domain}" for _ in range(4)]
    votes: dict[str, int] = {}
    total_checks = 0
    for probe in probes:
        for resolver_ip in resolver_list:
            total_checks += 1
            for ip in _resolve_ips(probe, resolver_ip, timeout):
                votes[ip] = votes.get(ip, 0) + 1

    quorum = max(1, total_checks // 2)
    wildcard_ips = {ip for ip, v in votes.items() if v >= quorum}

    if cache is not None:
        cache.set("dns", cache_key, sorted(wildcard_ips), ttl=ttl)
    return wildcard_ips


def detect_wildcard_for_host(host, resolvers=None, cache=None, ttl=None, timeout=5, probe_count=2):
    """Same idea as detect_wildcard but scoped to a single already-validated
    host, to catch per-level wildcards (e.g. *.dev.example.com catching
    everything even though *.example.com does not)."""
    resolver_list = resolvers or [None]
    cache_key = f"wildcard_host:{host}:{resolver_list}"
    if cache is not None:
        cached = cache.get("dns", cache_key)
        if cached is not None:
            return set(cached)

    votes: set = set()
    for _ in range(probe_count):
        probe = f"{_random_label()}.{host}"
        for resolver_ip in resolver_list:
            votes |= _resolve_ips(probe, resolver_ip, timeout)

    if cache is not None:
        cache.set("dns", cache_key, sorted(votes), ttl=ttl)
    return votes


# --------------------------------------------------------------------- #
# Validation (+ optional enrichment: TTL / resolver used / RTT / DNSSEC)
# --------------------------------------------------------------------- #
def _validate_one(host, resolvers, timeout, retries):
    """Returns (ips, enrichment). Distinguishes DNS response types instead
    of treating every failure identically:

      - NXDOMAIN is a NAME-level authoritative answer ("this name does not
        exist," true for every record type per the DNS spec, not just the
        one queried) -- retrying it, trying the other record type, or
        trying another resolver cannot change the answer. Fast-pathed:
        returns immediately with an empty result. This is the fix for
        permutation validation being dominated by wasted retries -- most
        generated candidate hostnames are NXDOMAIN, and the old code
        retried each one up to (retries+1) x len(resolvers) x 2 times
        before giving up, which is where multi-hour "5000 permutations at
        4+ seconds each" runtimes came from.
      - NoAnswer means the name exists but has no record of the type just
        queried -- still worth trying the other type, still worth another
        resolver (a resolver-specific quirk is more plausible here).
      - Everything else (timeout, SERVFAIL, connection issues) is treated
        as transient and goes through the normal retry/other-resolver path.
    """
    resolver_list = resolvers or [None]
    enrichment = {"ttl": None, "resolver_used": None, "response_time_ms": None, "dnssec": False}
    ips: set = set()

    if not _HAS_DNSPYTHON:
        t0 = time.time()
        try:
            for info in socket.getaddrinfo(host, None):
                ips.add(info[4][0])
            enrichment["resolver_used"] = "system-default"
            enrichment["response_time_ms"] = round((time.time() - t0) * 1000, 1)
        except Exception:
            pass
        return ips, enrichment

    for resolver_ip in resolver_list:
        for attempt in range(retries + 1):
            t0 = time.time()
            r = dns.resolver.Resolver()
            if resolver_ip:
                r.nameservers = [resolver_ip]
            r.lifetime = timeout
            r.timeout = timeout

            answered = False
            for rtype in ("A", "AAAA"):
                try:
                    ans = r.resolve(host, rtype)
                    ips.update(str(rr) for rr in ans)
                    if ans.rrset is not None:
                        enrichment["ttl"] = ans.rrset.ttl
                    answered = True
                except dns.resolver.NXDOMAIN:
                    return set(), enrichment  # authoritative: stop everything, right now
                except dns.resolver.NoAnswer:
                    continue  # name exists, no record of this type -- try the other one
                except Exception:
                    continue  # transient -- may still succeed on retry/another resolver

            if answered:
                enrichment["resolver_used"] = resolver_ip or "system-default"
                enrichment["response_time_ms"] = round((time.time() - t0) * 1000, 1)
                try:
                    q = dns.message.make_query(host, dns.rdatatype.A, want_dnssec=True)
                    resp = dns.query.udp(q, resolver_ip or "8.8.8.8", timeout=timeout)
                    enrichment["dnssec"] = bool(resp.flags & dns.flags.AD)
                except Exception:
                    pass
                break  # got a real answer -- stop retrying this resolver
            if attempt >= retries:
                continue  # exhausted retries on this resolver -- move to the next one
        if ips:
            break

    return ips, enrichment


def dns_validate_batch(hosts, threads=50, cache=None, ttl=None, timeout=5, retries=1,
                        resolvers=None, enrich=False, progress_desc=None, quiet=False):
    """Returns {host: [ip, ...]} by default. With enrich=True, returns
    {host: {"ips": [...], "ttl":..., "resolver_used":..., "response_time_ms":..., "dnssec":...}}."""
    results = {}
    hosts = list(hosts)

    def _work(host):
        cache_key = f"resolve:{host}:{resolvers}:{enrich}"
        if cache is not None:
            cached = cache.get("dns", cache_key)
            if cached is not None:
                return host, cached
        ips, enrichment = _validate_one(host, resolvers, timeout, retries)
        if not ips:
            return host, None
        payload = {"ips": sorted(ips), **enrichment} if enrich else sorted(ips)
        if cache is not None:
            cache.set("dns", cache_key, payload, ttl=ttl)
        return host, payload

    reporter = ProgressReporter(len(hosts), progress_desc or "DNS validation", quiet=quiet)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_work, h) for h in hosts]
        for fut in concurrent.futures.as_completed(futures):
            host, payload = fut.result()
            if payload is not None:
                results[host] = payload
            reporter.update(1)
    reporter.close()
    return results


def filter_wildcards(resolved: dict, wildcard_ips: set) -> dict:
    if not wildcard_ips:
        return resolved
    filtered = {}
    for host, payload in resolved.items():
        ips = payload["ips"] if isinstance(payload, dict) else payload
        remaining = [ip for ip in ips if ip not in wildcard_ips]
        if not remaining:
            continue
        if isinstance(payload, dict):
            new_payload = dict(payload)
            new_payload["ips"] = remaining
            filtered[host] = new_payload
        else:
            filtered[host] = remaining
    return filtered


# --------------------------------------------------------------------- #
# Reverse DNS + ASN
# --------------------------------------------------------------------- #
def reverse_dns_batch(ips, threads=50, cache=None, ttl=None, timeout=5, quiet=False):
    results = {}
    ips = list(ips)

    def _work(ip):
        cache_key = f"ptr:{ip}"
        if cache is not None:
            cached = cache.get("dns", cache_key)
            if cached is not None:
                return ip, cached
        ptr = None
        try:
            if _HAS_DNSPYTHON:
                rev = dns.reversename.from_address(ip)
                r = dns.resolver.Resolver()
                r.lifetime = timeout
                r.timeout = timeout
                ans = r.resolve(rev, "PTR")
                ptr = str(ans[0]).rstrip(".")
            else:
                ptr = socket.gethostbyaddr(ip)[0]
        except Exception:
            ptr = None
        if ptr and cache is not None:
            cache.set("dns", cache_key, ptr, ttl=ttl)
        return ip, ptr

    reporter = ProgressReporter(len(ips), "Reverse DNS", quiet=quiet)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_work, ip) for ip in ips]
        for fut in concurrent.futures.as_completed(futures):
            ip, ptr = fut.result()
            reporter.update(1)
            if ptr:
                results[ip] = ptr
    reporter.close()
    return results
