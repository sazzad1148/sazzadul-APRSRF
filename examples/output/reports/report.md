# Subdomain recon report -- example.com

**Profile:** balanced  |  **Max depth:** 5  |  **Generated:** Wed Jul 29 08:37:30 2026  |  **Runtime:** 68.6s

## Counts

| Metric | Value |
|---|---|
| passive candidates | 214 |
| validated after recursion | 9 |
| validated from permutations | 1 |
| final validated hosts | 8 |
| cloud assets | 2 |
| per level wildcard hosts | 1 |

**Wildcard IPs:** `[]`

## Provider health

```
Provider Summary
  censys         ✓ 18 hosts
  certspotter    ✓ 31 hosts
  chaos          ✗ Missing key (chaos)
  crt.sh         ✓ 114 hosts
  findomain      ✗ Missing binary (findomain)
  fullhunt       ✓ 9 hosts
  github         ✗ Missing key (github)
  hackertarget   ✗ Error: hackertarget: API count exceeded (free-tier rate limit hit)
  rapiddns       ✓ 0 hosts
  virustotal     ✓ 42 hosts

Unique Hosts : 214
Duplicates   : 35
Errors       : 1
```

## Confidence engine (active weights)

| Condition | Points |
|---|---|
| multi provider | +20 |
| dns valid | +20 |
| recursive | +15 |
| cloud | +10 |
| github | +15 |
| crt | +10 |
| permutation penalty | -15 |

_Score = sum of matching conditions, clamped to [0, 100]. High >= 70, Medium >= 40, else Low. Override any weight via `--config-file` (key `confidence_weights`)._

## Reverse DNS -- grouped by ASN

| ASN | Hosts |
|---|---|
| AS13335 | 1 |

## Reverse DNS -- grouped by cloud provider

| Provider | Hosts |
|---|---|
| Cloudflare | 1 |
| AWS | 1 |

## Final validated hosts

| Host | IP(s) | Confidence | Cloud | Wildcard | Depth | Tags |
|---|---|---|---|---|---|---|
| www.example.com | 93.184.216.34 | 95 (High) | Cloudflare | no | 1 | cloud |
| api.example.com | 93.184.216.35 | 65 (Medium) |  | no | 1 |  |
| developer.example.com | 203.0.113.10 | 40 (Medium) |  | no | 1 |  |
| api2.developer.example.com | 203.0.113.11 | 55 (Medium) |  | no | 2 | recursive |
| cdn-assets.example.com | 203.0.113.99 | 20 (Low) | AWS | no | 1 | cloud |
| vpn.example.com | 203.0.113.50 | 85 (High) |  | no | 1 | recursive |
| staging.example.com | 203.0.113.75 | 5 (Low) |  | yes | 1 | permutation, wildcard-suspect |
| mail.example.com | 203.0.113.25 | 90 (High) |  | no | 1 |  |

## Per-stage metrics

| Stage | Runtime (s) | OK | Fail | Errors |
|---|---|---|---|---|
| 01_passive_sources | 24.1 | 15 | 1 | 0 |
| 02_wildcard_detection | 3.2 | 1 | 0 | 0 |
| 03_initial_dns_validation | 8.6 | 214 | 6 | 0 |
| 04_recursive_enumeration | 11.4 | 27 | 0 | 0 |
| 05_word_extraction | 0.1 | 42 | 0 | 0 |
| 06_permutation_validation | 6.8 | 1 | 2999 | 0 |
| 07_reverse_dns | 2.1 | 6 | 0 | 0 |
| 08_cloud_discovery | 3.4 | 2 | 0 | 0 |
| 09_dns_records | 4.2 | 8 | 0 | 0 |
| 10_enrichment | 2.9 | 8 | 0 | 0 |
| 11_final_filter_validation | 1.8 | 8 | 0 | 0 |
