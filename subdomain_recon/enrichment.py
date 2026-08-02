"""
Post-validation enrichment: ASN/organization lookup, cloud/CDN provider
fingerprinting, and full DNS record-set collection. Split out of
dns_utils.py (which stays focused on wildcard detection + core
validation/PTR) so each module has one clear job -- both are still "DNS
facing" but these three are enrichment layered on top of already-validated
hosts, not part of the validate/filter path itself.
"""
from __future__ import annotations

import concurrent.futures

from .progress import ProgressReporter

try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False

RECORD_TYPES_DEFAULT = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

# (fingerprint substring found in a CNAME chain, provider, service label)
CLOUD_SIGNATURES = [
    ("cloudfront.net", "AWS", "CloudFront"),
    ("s3.amazonaws.com", "AWS", "S3"),
    ("elb.amazonaws.com", "AWS", "ELB"),
    ("amazonaws.com", "AWS", "EC2/Other"),
    ("azurefd.net", "Azure", "Front Door"),
    ("azurewebsites.net", "Azure", "App Service"),
    ("cloudapp.azure.com", "Azure", "Cloud Service"),
    ("trafficmanager.net", "Azure", "Traffic Manager"),
    ("blob.core.windows.net", "Azure", "Blob Storage"),
    ("appspot.com", "GCP", "App Engine"),
    ("cloudfunctions.net", "GCP", "Cloud Functions"),
    ("run.app", "GCP", "Cloud Run"),
    ("googleusercontent.com", "GCP", "Google Hosting"),
    ("cdn.cloudflare.net", "Cloudflare", "CDN"),
    ("cloudflare.net", "Cloudflare", "CDN/Proxy"),
    ("fastly.net", "Fastly", "CDN"),
    ("edgekey.net", "Akamai", "CDN"),
    ("akamaiedge.net", "Akamai", "CDN"),
    ("akamai.net", "Akamai", "CDN"),
    ("vercel.app", "Vercel", "Hosting"),
    ("netlify.app", "Netlify", "Hosting"),
    ("herokudns.com", "Heroku", "DNS"),
    ("herokuapp.com", "Heroku", "Hosting"),
    ("github.io", "GitHub Pages", "Hosting"),
    ("wixdns.net", "Wix", "Hosting"),
]


def asn_lookup(ip, cache=None, ttl=None, timeout=5) -> dict:
    """Free, keyless ASN + org lookup via Team Cymru's DNS whois service.
    Two lookups: origin.asn.cymru.com (asn/prefix/country/registry) then
    asn.cymru.com (organization name for that ASN)."""
    cache_key = f"asn:{ip}"
    if cache is not None:
        cached = cache.get("dns", cache_key)
        if cached is not None:
            return cached

    result: dict = {}
    if _HAS_DNSPYTHON and ":" not in ip:  # IPv4 only for this lookup scheme
        try:
            r = dns.resolver.Resolver()
            r.lifetime = timeout
            r.timeout = timeout
            reversed_ip = ".".join(reversed(ip.split(".")))
            ans = r.resolve(f"{reversed_ip}.origin.asn.cymru.com", "TXT")
            parts = [p.strip() for p in str(ans[0]).strip('"').split("|")]
            if len(parts) >= 5:
                asn, prefix, country, registry, _allocated = parts[:5]
                asn_num = asn.split()[0]
                org_name = None
                try:
                    org_ans = r.resolve(f"AS{asn_num}.asn.cymru.com", "TXT")
                    org_parts = [p.strip() for p in str(org_ans[0]).strip('"').split("|")]
                    if len(org_parts) >= 5:
                        org_name = org_parts[4]
                except Exception:
                    pass
                result = {"asn": asn_num, "prefix": prefix, "country": country,
                          "registry": registry, "org": org_name}
        except Exception:
            pass

    if cache is not None:
        cache.set("dns", cache_key, result, ttl=ttl)
    return result


def cloud_asset_discovery(hosts, threads=50, cache=None, ttl=None, timeout=5, quiet=False):
    """Follows each host's CNAME chain (up to 8 hops) and matches links
    against known provider fingerprints."""
    results = {}
    hosts = list(hosts)

    def _work(host):
        cache_key = f"cloud:{host}"
        if cache is not None:
            cached = cache.get("dns", cache_key)
            if cached is not None:
                return host, cached or None
        info = None
        if _HAS_DNSPYTHON:
            try:
                r = dns.resolver.Resolver()
                r.lifetime = timeout
                r.timeout = timeout
                chain = []
                target = host
                for _ in range(8):
                    try:
                        ans = r.resolve(target, "CNAME")
                        cname = str(ans[0].target).rstrip(".")
                        chain.append(cname)
                        target = cname
                    except Exception:
                        break
                for link in chain:
                    for sig, provider, service in CLOUD_SIGNATURES:
                        if sig in link:
                            info = {"provider": provider, "service": service,
                                    "evidence": link, "cname_chain": chain}
                            break
                    if info:
                        break
            except Exception:
                info = None
        if cache is not None:
            cache.set("dns", cache_key, info, ttl=ttl)
        return host, info

    reporter = ProgressReporter(len(hosts), "Cloud discovery", quiet=quiet)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_work, h) for h in hosts]
        for fut in concurrent.futures.as_completed(futures):
            host, info = fut.result()
            reporter.update(1)
            if info:
                results[host] = info
    reporter.close()
    return results


def collect_dns_records(hosts, record_types=None, threads=30, cache=None, ttl=None, timeout=5,
                         quiet=False):
    record_types = record_types or RECORD_TYPES_DEFAULT
    hosts = list(hosts)

    def _work(host):
        cache_key = f"records:{host}:{','.join(record_types)}"
        if cache is not None:
            cached = cache.get("dns", cache_key)
            if cached is not None:
                return host, cached
        recs = {}
        if _HAS_DNSPYTHON:
            r = dns.resolver.Resolver()
            r.lifetime = timeout
            r.timeout = timeout
            for rtype in record_types:
                try:
                    ans = r.resolve(host, rtype)
                    recs[rtype] = {
                        "values": [str(rr) for rr in ans],
                        "ttl": ans.rrset.ttl if ans.rrset is not None else None,
                    }
                except Exception:
                    continue
        if cache is not None:
            cache.set("dns", cache_key, recs, ttl=ttl)
        return host, recs

    results = {}
    reporter = ProgressReporter(len(hosts), "DNS records", quiet=quiet)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_work, h) for h in hosts]
        for fut in concurrent.futures.as_completed(futures):
            host, recs = fut.result()
            reporter.update(1)
            if recs:
                results[host] = recs
    reporter.close()
    return results
