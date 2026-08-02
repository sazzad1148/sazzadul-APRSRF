import sys
import time
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subdomain_recon import dns_utils


class _FakeResolver:
    """Stands in for dns.resolver.Resolver -- raises whatever exception the
    test configures for every .resolve() call, regardless of record type,
    to simulate a real resolver's answer for a given host."""
    def __init__(self, raise_exc):
        self.nameservers = []
        self.lifetime = None
        self.timeout = None
        self._raise_exc = raise_exc

    def resolve(self, host, rtype):
        raise self._raise_exc


def test_nxdomain_stops_immediately_no_retries_no_other_resolver():
    """The actual bug: NXDOMAIN used to be retried (retries+1) x
    len(resolvers) x 2-record-types times before giving up, which is where
    multi-hour permutation-validation runtimes came from (most generated
    candidates are NXDOMAIN). It must now return immediately on the first
    NXDOMAIN, making zero further resolve() calls."""
    if not dns_utils._HAS_DNSPYTHON:
        return  # nothing to test without dnspython installed

    call_count = {"n": 0}

    class _NXResolver(_FakeResolver):
        def __init__(self):
            super().__init__(None)

        def resolve(self, host, rtype):
            call_count["n"] += 1
            raise dns_utils.dns.resolver.NXDOMAIN()

    with mock.patch.object(dns_utils.dns.resolver, "Resolver", _NXResolver):
        t0 = time.time()
        ips, enrichment = dns_utils._validate_one(
            "definitely-does-not-exist.example.com",
            resolvers=["8.8.8.8", "1.1.1.1", "9.9.9.9"],  # 3 resolvers configured
            timeout=5, retries=3,                            # 4 attempts each
        )
        elapsed = time.time() - t0

    assert ips == set()
    # Old behavior: up to 3 resolvers x 4 attempts x 2 record types = 24 calls.
    # Fixed behavior: exactly 1 call (A lookup), then immediate return.
    assert call_count["n"] == 1, f"expected exactly 1 resolve() call, got {call_count['n']}"
    assert elapsed < 0.5


def test_noanswer_tries_the_other_record_type_and_other_resolvers():
    """NoAnswer (name exists, no record of this type) is NOT treated like
    NXDOMAIN -- it's still worth trying AAAA and other resolvers."""
    if not dns_utils._HAS_DNSPYTHON:
        return

    call_log = []

    class _NoAnswerThenSuccess:
        def __init__(self):
            self.nameservers = []
            self.lifetime = None
            self.timeout = None

        def resolve(self, host, rtype):
            call_log.append(rtype)
            if rtype == "A":
                raise dns_utils.dns.resolver.NoAnswer()
            # AAAA succeeds
            class _Ans:
                rrset = mock.Mock(ttl=300)
                def __iter__(self):
                    return iter(["2001:db8::1"])
            return _Ans()

    with mock.patch.object(dns_utils.dns.resolver, "Resolver", _NoAnswerThenSuccess):
        ips, enrichment = dns_utils._validate_one(
            "aaaa-only.example.com", resolvers=None, timeout=5, retries=1,
        )

    assert "A" in call_log and "AAAA" in call_log
    assert "2001:db8::1" in ips


def test_successful_resolution_still_works_and_stops_retrying():
    if not dns_utils._HAS_DNSPYTHON:
        return

    call_count = {"n": 0}

    class _SuccessResolver:
        def __init__(self):
            self.nameservers = []
            self.lifetime = None
            self.timeout = None

        def resolve(self, host, rtype):
            call_count["n"] += 1
            if rtype == "AAAA":
                raise dns_utils.dns.resolver.NoAnswer()
            class _Ans:
                rrset = mock.Mock(ttl=300)
                def __iter__(self):
                    return iter(["1.2.3.4"])
            return _Ans()

    with mock.patch.object(dns_utils.dns.resolver, "Resolver", _SuccessResolver):
        with mock.patch.object(dns_utils.dns.query, "udp", side_effect=Exception("no dnssec")):
            ips, enrichment = dns_utils._validate_one(
                "real-host.example.com", resolvers=["8.8.8.8", "1.1.1.1"], timeout=5, retries=2,
            )

    assert ips == {"1.2.3.4"}
    # A + AAAA on the first resolver, first attempt -- must not retry further
    # once a real answer was found.
    assert call_count["n"] == 2


def test_permutation_scale_simulation_nxdomain_dominant():
    """Realistic shape of the reported bug: mostly-NXDOMAIN candidates
    (typical for permutation guesses) must resolve fast in aggregate, not
    at multiple seconds each."""
    if not dns_utils._HAS_DNSPYTHON:
        return

    class _AllNXResolver:
        def __init__(self):
            self.nameservers = []
            self.lifetime = None
            self.timeout = None

        def resolve(self, host, rtype):
            raise dns_utils.dns.resolver.NXDOMAIN()

    with mock.patch.object(dns_utils.dns.resolver, "Resolver", _AllNXResolver):
        hosts = {f"guess{i}.example.com" for i in range(200)}
        t0 = time.time()
        result = dns_utils.dns_validate_batch(
            hosts, threads=20, cache=None, timeout=5, retries=3,
            resolvers=["8.8.8.8", "1.1.1.1", "9.9.9.9"], quiet=True,
        )
        elapsed = time.time() - t0

    assert result == {}
    # With the fix, 200 NXDOMAIN hosts across 20 threads should take a
    # fraction of a second (no real I/O, no retries). Generous ceiling.
    assert elapsed < 3.0, f"200 NXDOMAIN hosts took {elapsed:.2f}s -- retries/other-resolvers still being tried"
