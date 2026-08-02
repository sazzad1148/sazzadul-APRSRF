# sazzad007 -- passive + active subdomain recon

Passive subdomain discovery from **19 production-ready sources**, smart multi-resolver
wildcard filtering, **multi-source recursive enumeration** (crt.sh SAN chaining +
Wayback + GitHub + optional active JS/CSP scraping), deep permutation (level
2-8), DNS validation enriched with **TTL / resolver used / response time /
DNSSEC**, reverse DNS grouped by **ASN / organization / cloud provider**, cloud
asset fingerprinting (AWS, Azure, GCP, Cloudflare, Fastly, Akamai, Vercel,
Netlify, Heroku, GitHub Pages, ...), a **configurable, explainable confidence
engine**, a **Provider Health Summary**, a queryable **SQLite intelligence
DB**, **diff mode** against a previous run, and a clean `txt/ + json/ +
reports/` output layout -- with resume support, caching, per-stage metrics,
and an auto-discovering plugin architecture.

See `ARCHITECTURE.md` for the pipeline diagram, full JSON schema, plugin SDK
contract, and confidence-engine formula. See `CONTRIBUTING.md` for dev
setup and how to add a new source. See `CHANGELOG.md` for version history.
See `examples/` for sample output (all formats), sample config files
(JSON/YAML/TOML), and a sample batch domain list.

### Quick start (installation)

> **Uploading this to GitHub?** Push it with `git`, don't drag-and-drop the
> folder into the GitHub web UI -- some file managers/browsers hide or skip
> dotfiles (`.env.example`, `.gitignore`, `.pre-commit-config.yaml`) and
> dot-folders (`.github/workflows/`) during a manual upload, which silently
> breaks CI and leaves secrets unprotected. `git add . && git commit && git
> push` picks up dotfiles correctly every time.

```bash
git clone <your-repo-url>
cd <repo-folder>          # the folder containing run.py

pip install -r requirements.txt --break-system-packages
# (or, pip-installable form: pip install -e .   -- gives you the
#  `passive-enum` command too, see section 2/17 below)

cp .env.example .env       # optional -- fill in any free API keys you have

python3 run.py -d example.com --profile balanced
```

Full detail (profiles, keys, CLI-tool sources, troubleshooting) is in
section 1 below.

### What's new in v3.1 (this round)

| Feature | Status |
|---|---|
| Modular plugin system | done |
| Auto plugin discovery (drop a `.py` file, it's live) | done -- was already true, verified with a dedicated test |
| Provider Health Summary (per-source ok/skipped/error + host counts + duplicates) | done |
| Confidence engine (additive, explainable, configurable via `--config-file`) | done |
| Source attribution | done |
| Rich JSON schema (`confidence_breakdown`, discovery path, ASN, cloud, enrichment) | done |
| TXT / CSV / HTML / Markdown reports | done |
| SQLite intelligence DB (`intel.sqlite3`: run history, host history, search, cross-run duplicates) | done |
| Diff mode (`--diff <report.json>` or `--diff auto`) | done |
| Resume (per-stage checkpointing + graceful Ctrl+C message) | done, mid-stage resume out of scope (see ARCHITECTURE.md) |
| Type hints on new/modified modules | done; full-codebase strict `mypy` is a work in progress, not a hard CI gate yet |
| `black` / `ruff` / `mypy` / pre-commit | configured (`pyproject.toml`, `.pre-commit-config.yaml`) |
| Tests | 25 tests across 5 files covering normalize, config, confidence engine, provider health, plugin discovery, intel DB, diff mode, exporters; no coverage-percentage claim made since `coverage.py` wasn't run in this sandbox (no network to install it) |
| CI/CD (lint -> test matrix 3.11/3.12 -> build) | done |
| pip packaging (`pyproject.toml`, `passive-enum` console script) | done |
| Async engine | not done -- current concurrency is thread-pool based (`ThreadPoolExecutor`), which is adequate for I/O-bound HTTP/DNS work; a true async rewrite is a larger architectural change left for a future round |
| HTML dashboard with charts/timeline | partial -- `report.html` is an interactive, sortable/filterable table with summary stat cards, not a charting dashboard |
| Dedicated "Mr. Cool" startup banner (box-art logo + Author: Sazzadul / Version / Engine / Mode / Status panel) | done |
| `--minimal` output mode (keep only `txt/final_hosts.txt` + `reports/report.json`, delete everything else) | done |
| Auto-fresh output per run (2nd run never mixes with 1st run's leftovers; `--resume` is the only opt-out) | done |
| Batch mode: `-dL/--domain-list example.txt` scans 2+ domains in one command, each into its own output subfolder | done |

### Per-source raw/normalized/rejected/duplicate breakdown

Previously a source's log line only showed the final count (e.g.
`assetfinder: 58 normalized hosts`) -- if a source returned real data that
all got rejected somewhere in normalization/scope-checking, that was
indistinguishable from the source legitimately finding nothing. Verified
first that `normalize_hostname()` itself has no bug (tested against 18
realistic hostname patterns matching actual subfinder output for a real
domain -- all normalized correctly), so this wasn't hiding a parsing bug --
but the *visibility* gap was real, so it's fixed:

```
[+] subfinder: 428 normalized hosts (raw=558, rejected=6, dup=124)
```

And if a source ever does return data that all gets rejected, that's now a
`WARNING`, not a quiet `INFO` line, so it can't blend into a normal "found
nothing" result:
```
[!] some-source: got 558 raw line(s) but 0 normalized -- likely a real
    parsing/scope issue, not "found nothing". Run with --debug for detail.
```
`raw`, `rejected`, and `duplicate_in_source` are also in each host's
`provider_health` entry in `reports/report.json` and shown in the console
Provider Health Summary. 2 new regression tests cover both the normal
breakdown and the anomaly-flagging behavior.

### Second performance fix: passive source collection was also sequential

The recursion-stage fix (below) wasn't the only sequential bottleneck.
**Stage 1** -- querying all passive sources (21 at the time this fix was made,
  19 now that C99/CertDB were removed) -- ran the exact same way:
one source at a time, in a plain `for` loop, each blocking call (including
slow/rate-limited free APIs like crt.sh, and subprocess-spawning CLI tools
like `findomain`/`sublist3r`) fully serial before the next started. Against
a realistic per-source latency profile, that alone costs minutes before DNS
validation, recursion, or permutation even begin -- almost certainly the
single biggest contributor to multi-hour total runtimes.

Fixed the same way as recursion: a bounded parallel worker pool
(`source_threads` -- 8/12/19 on fast/balanced/thorough, override with
`--source-threads`). A simulation with a realistic latency profile (most
sources 3-8s, a couple of slow ones up to 20s) went from **148s sequential
to 22s parallel -- a 6.7x speedup** for this one stage alone; combined with
the recursion fix, this is what actually closes the "1-3 hours" gap rather
than adding more sources or features. Added 3 regression tests.

### Third performance fix: the actual root cause of "still stuck for hours"

Parallelizing both stages above was necessary but **not sufficient** --
some real-world runs still stalled for hours afterward. The actual bug:
both stages used `with concurrent.futures.ThreadPoolExecutor(...) as ex:`.
Exiting that block calls `ex.shutdown(wait=True)`, which blocks until
**every** submitted task finishes, no matter how many already completed.
One abnormally slow response -- e.g. a crt.sh query for a host that shares
a wildcard certificate with thousands of unrelated names, a genuinely
common real-world case -- could hold an entire round hostage even though
the other 100+ calls in that round finished in parallel within seconds.
The work was genuinely parallel; the *exit path* silently re-serialized on
whichever straggler was slowest.

Fixed with a hard wall-clock ceiling per stage:

```bash
python3 run.py -d example.com --recursion-round-timeout 120   # default: 60/180/400s by profile
python3 run.py -d example.com --source-stage-timeout 120      # default: 60/180/400s by profile
```

Both stages now wait via `as_completed(futures, timeout=<ceiling>)`
instead of blocking indefinitely; on timeout, whatever completed is kept,
the stragglers are logged by name, and `ex.shutdown(wait=False,
cancel_futures=True)` returns immediately rather than waiting for
already-running threads (Python can't forcibly kill a thread -- they
finish in the background and their results are simply discarded). A
single round can now never take longer than its configured ceiling,
regardless of how slow the single worst response is. Covered by a
dedicated regression test that fails if this ever regresses to blocking
again.

### Fourth performance fix: permutation validation was 4+ seconds per host

Reported: 5,005 permutations at `--max-depth 8`, ~4.3s/host, a ~6-hour ETA.
Root cause was different from the three above -- not sequential execution,
but **DNS resolution treating every failure identically**. A single
nonexistent hostname (the large majority of speculative permutation
guesses) could trigger up to `(retries+1) x len(resolvers) x 2` lookups --
24 on the `thorough` profile -- before giving up, because NXDOMAIN
(dnspython's "this name does not exist" exception) was caught by the same
`except Exception: continue` as genuinely transient errors (timeouts,
SERVFAIL) and retried the same way.

**NXDOMAIN is authoritative at the name level** -- per the DNS spec, if a
name doesn't exist, it doesn't exist for *any* record type, so retrying it,
trying AAAA after A already came back NXDOMAIN, or asking a different
resolver cannot produce a different answer. Fixed: the first NXDOMAIN now
returns immediately -- 1 query instead of up to 24 for the common case.
`NoAnswer` (name exists, just no record of *that* type) is left alone and
still tries the other record type / other resolvers, since that case is
genuinely worth a second opinion. No new flag needed -- this is always-on
correct DNS handling, not a tunable. Covered by 4 tests, including one
asserting the exact call count and one simulating 200 NXDOMAIN hosts to
catch any regression.

### Additions from the maintainability/DX pass

- **Module split**: `dns_utils.py` (445 lines) split into `dns_utils.py`
  (wildcard + core validation/PTR) and `enrichment.py` (ASN lookup, cloud
  fingerprinting, full DNS record collection). `pipeline.py`'s recursion
  expander methods moved out into `recursion_expanders.py` as plain,
  independently-testable functions. See `ARCHITECTURE.md`'s new "Module
  layout" table. (`pipeline.py` is still the largest file at ~630 lines --
  that's the 11-stage orchestrator itself; further splitting it
  per-stage is possible but wasn't done this round.)
- **`summary.json`**: a lean summary (counts, provider health,
  duplicates, ASN/cloud groupings, confidence weights) alongside the full
  `report.json`, for scripts/dashboards that only need the numbers.
- **YAML/TOML config files**: `--config-file` now accepts `.yaml`/`.yml`
  (needs `pip install pyyaml`) and `.toml` (stdlib, no extra install) in
  addition to `.json`.
- **Real file logging**: `output/<domain>/logs/run_<timestamp>.log` is
  now actually created (it was documented but never wired up before) --
  always captures full DEBUG-level detail regardless of console
  verbosity. New `--debug` (full tracebacks for source failures, both on
  console and in the log) and `--quiet` (WARNING-level console only,
  full detail still goes to the log file) flags.
- **Progress display**: DNS validation, reverse DNS, cloud discovery, and
  DNS record collection now show live progress (a `tqdm` bar if
  installed, periodic log lines otherwise -- rate + ETA either way).
  Every pipeline stage also logs a `[stage N/11] <name>` marker.

### Fixes from the latest full-code revise pass

- **Silent failures made visible (the "subfinder: 0 hosts but works fine by
  hand" bug):** every source -- CLI-tool-based (`subfinder`, `findomain`,
  `assetfinder`, `sublist3r`) and HTTP-based (`crt.sh` and all 13 others)
  -- used to swallow real failures (timeout, non-zero exit code, connection
  refused, non-2xx HTTP response, a crashed parse) into a bare `except
  Exception: return []`. That made "the tool actually failed" completely
  indistinguishable from "it ran fine and legitimately found zero
  subdomains" -- exactly what happened when `subfinder` reported 0 through
  the pipeline while running the identical `subfinder -d ...` command by
  hand found 558. Fixed: a clean run with zero real results (exit 0 /
  HTTP 2xx, empty output) still correctly returns an empty list -- that's a
  real answer. Everything else now raises (`CLISourceError` /
  `HTTPSourceError`), which `stage_passive_sources`'s existing per-source
  try/except already catches and reports as a proper `error` entry (with
  the real reason -- exit code, stderr snippet, HTTP status, connection
  failure) in the Provider Health Summary, instead of a misleading `✓ 0
  hosts`. Added 15 tests covering both helpers and real source integration.
- **Critical performance bug:** recursive enumeration ran fully sequential
  -- 425 hosts x 3 sources (a real-world case, `crypto.com`) meant 1275+
  blocking HTTP calls one at a time against rate-limited APIs like crt.sh,
  which could stall for an hour or more on a single round. Fixed with a
  bounded parallel worker pool (`recursion_threads`, new per-profile
  tunable) plus an optional per-round frontier cap
  (`max_recursion_frontier_per_round`) for very large domains. See section
  7 for the before/after and how to tune or disable either one. Added 3
  regression tests, including one that fails if this ever goes sequential
  again.


Went through the entire codebase end-to-end and fixed everything found:

- **Bug:** `--diff <file> --minimal` used together silently deleted
  `reports/diff.json` / `reports/diff.md` -- `--minimal`'s cleanup only
  kept `report.json`, so the one thing `--diff` was asked to produce got
  thrown away. Fixed: `cleanup_to_minimal()` now also preserves
  `diff.json`/`diff.md` when present. Added a regression test
  (`test_cleanup_to_minimal_keeps_final_report_and_diff_output`) and an
  end-to-end reproduction so this can't silently regress.
- **Bug:** dead ternary in the Provider Health formatter
  (`"✓" if hosts > 0 else "✓"` -- both branches identical, clearly a
  leftover mistake). Simplified to just the checkmark.
- **Cleanup:** removed an unused `import sys` in `cli.py`.
- **Hardening:** the recursion-depth guard used when mapping permutation
  hosts back to their parent (for `discovery_path`) now matches
  `wordgen.generate_deep_permutations`'s bounds check exactly (`depth < 0
  or depth >= max_depth`, not just the upper bound) -- defensive, since in
  practice every base host reaching that code is already in-scope.
- Full pass also checked for: API keys ever being logged/printed anywhere
  (they aren't -- only ever passed as opaque dict values), unused imports
  across every module (heuristic + manual check -- clean), bare
  `except:` clauses (none -- every catch is `except Exception:`, so
  `KeyboardInterrupt`/`SystemExit` still propagate correctly).

### Installing (pip, optional)

```bash
pip install -e .          # editable install from this repo, or `pip install .`
passive-enum -d example.com --profile balanced
```

`python3 run.py -d example.com` keeps working exactly as before -- the pip
console script is an additional entry point, not a replacement.



**Scope:** only run this against domains you own or are explicitly
authorized to test. It only queries public/passive data sources and performs
standard DNS resolution -- no exploitation, no credential attacks. The
optional `--active-recursion` flag fetches public pages on discovered hosts
(to mine JS/CSP for more hostnames) -- still no exploitation, but it is a
direct HTTP request to the target's own servers, so it's opt-in and off by
default.

**Project scope (deliberate):** this is a *subdomain reconnaissance* tool --
find the maximum number of valid subdomains and enrich them (sources, DNS
records, ASN, cloud, confidence). It intentionally does NOT do port
scanning, vulnerability scanning (nuclei), screenshots, JS secret scanning,
directory brute-forcing, or exploitation -- those are different tools'
jobs, and bolting them on would turn a fast, focused recon tool into a slow,
sprawling one. If you need those, pipe this tool's `txt/final_hosts.txt`
into `httpx`, `nuclei`, `gowitness`, etc.

## 1. Installation

```bash
# from the project root (folder containing run.py)
pip install -r requirements.txt --break-system-packages

# optional external CLI tools (auto-detected, skipped if missing):
#   subfinder   https://github.com/projectdiscovery/subfinder
#   assetfinder https://github.com/tomnomnom/assetfinder
#   findomain   https://github.com/findomain/findomain
#   sublist3r   https://github.com/aboul3la/Sublist3r
```

Check what's available on your system:

```
python3 run.py --list-plugins
name               confidence available
-----------------------------------------------
alienvault_otx     Medium     yes
anubisdb           Medium     yes
assetfinder        Medium     no (missing key/binary)
bufferover         Medium     yes
censys             High       no (missing key/binary)
certspotter        High       yes
chaos              High       no (missing key/binary)
crt.sh             High       yes
findomain          Medium     no (missing key/binary)
fullhunt           Medium     no (missing key/binary)
github             Medium     no (missing key/binary)
hackertarget       Medium     yes
rapiddns           Medium     yes
subfinder          Medium     no (missing key/binary)
sublist3r          Medium     no (missing key/binary)
threatminer        Medium     yes
urlscan            Medium     yes
virustotal         Medium     no (missing key/binary)
wayback            Medium     yes
```

Keyless out of the box (9): `crt.sh`, `bufferover`, `alienvault_otx`,
`rapiddns`, `wayback`, `urlscan` (low volume), `certspotter` (low rate
limit), `hackertarget` (tightly rate-limited free tier), `anubisdb`,
`threatminer`.

CLI-tool sources (installed separately, auto-detected on `PATH`): `subfinder`,
`assetfinder`, `findomain`, `sublist3r`.

Optional-API-key sources (5) -- all free signup, no payment required. The
behavior is the same for every one of these: **key present -> the source
runs; key absent -> it's auto-skipped with a clear reason in the Provider
Health Summary, and the rest of the pipeline continues normally.** No
exception, no crash, nothing else affected -- confirmed by
`test_passive_sources_skipped_when_unavailable` and the "skipped" status
path in `stage_passive_sources` (`Pipeline.provider_health`).

| Source | Free signup at | CLI flag |
|---|---|---|
| GitHub | github.com (personal access token) | `--github-token` |
| Censys | search.censys.io (Community tier) | `--censys-id` + `--censys-secret` (both needed) |
| VirusTotal | virustotal.com | `--virustotal-key` |
| FullHunt | fullhunt.io | `--fullhunt-key` |
| Chaos | chaos.projectdiscovery.io (free, eligibility-based) | `--chaos-key` |

`urlscan.io` and `CertSpotter` also accept an optional key
(`--urlscan-key` / `--certspotter-key`) to raise their rate limit, but
they're keyless-capable (listed above), not optional-only.

**Removed from this project:** C99 (was a **paid** API -- didn't belong
next to free/freemium sources) and CertDB (was a stub with no real
endpoint -- there's no single standardized public "CertDB" service, so it
never actually worked). Counting either of them made the source count
inaccurate; 19 is the number of sources that actually run against real
data. If you have a real paid-API key you want wired in (C99 or anything
else), the plugin pattern in section 11 makes that a drop-in file, no core
changes needed.

Deliberately not included (paid-only, no usable free tier): Shodan,
BinaryEdge. Sources deliberately not included and why (discontinued,
ToS-violating scraping, or standalone tools already covered another way) are
unchanged from the previous README section and still apply.

### Storing API keys

```bash
cp .env.example .env
# then edit .env and fill in whichever keys you have
```

`.env` is already in `.gitignore`. Priority if a key is set in more than one
place: `--flag-on-cli` > shell environment variable > `.env` file.

## 2. Basic usage

```bash
python3 run.py -d example.com --profile balanced
```

### Auto-fresh output (default behavior)

Every run starts from a clean slate for that domain -- unless you pass
`--resume`, the domain's output directory is wiped automatically before the
pipeline starts. A second run against the same domain never mixes with a
first run's leftover files; you don't need to remember `--fresh` (it's kept
as a no-op flag for backward compatibility, but wiping is now the default
whenever you're not resuming).

```bash
python3 run.py -d example.com --profile fast     # run 1 -> output/...
python3 run.py -d example.com --profile fast     # run 2 -> output/ auto-wiped first, clean result
python3 run.py -d example.com --profile fast --resume   # only this one preserves the prior output
```

### Scanning multiple domains at once (`-dL` / `--domain-list`)

```bash
# example.txt -- one domain per line, blank lines and #comments are skipped
example.com
another-domain.com
# this-one-is-commented-out.com
third-domain.com
```

```bash
python3 run.py -dL example.txt --profile balanced
```

Runs the full pipeline against every domain in the file (duplicates
case-insensitively deduped). You can also combine `-d` with `-dL` -- both
get scanned. Each domain gets its **own isolated output subfolder**:

```
output/
  example.com/
    txt/  json/  reports/  ...
  another-domain.com/
    txt/  json/  reports/  ...
  third-domain.com/
    txt/  json/  reports/  ...
```

(With a single `-d` and no `-dL`, output stays flat at `output/...` exactly
as before -- the per-domain subfolder only kicks in for batch mode, so
existing single-domain scripts/workflows aren't affected.) Auto-fresh
applies per domain, and a Ctrl+C stops the whole batch (already-completed
domains keep their results; the interrupted domain can be resumed
individually with `--resume -d <that-domain>`). A batch summary
(OK/INTERRUPTED/FAILED per domain) prints at the end.

**Only want the final result, nothing else?** Use `--minimal` -- after the
run, everything except the two final-report files is deleted automatically:

```bash
python3 run.py -d example.com --profile fast --minimal
```

Leaves exactly:
```
output/
  txt/final_hosts.txt        # hostnames only, one per line
  reports/report.json        # full structured report (IPs, sources, confidence, cloud, ...)
```

Everything else -- per-stage `json/`, the other `txt/*.txt` files,
`report.csv`/`.html`/`.md`, `cache.sqlite3`, `intel.sqlite3`,
`metadata.json`, `checkpoints/`, `logs/` -- is removed. (Without
`--minimal`, the default behavior is unchanged: only `checkpoints/` is
auto-deleted, everything else stays -- see section 3 and section 18.)

## 3. Output structure

```
output/
  txt/
    passive_hosts.txt        # stage 01 -- raw candidates, pre-DNS-validation
    validated_hosts.txt      # stage 03 -- initial DNS-validated hosts
    recursive_hosts.txt      # stage 04 -- hosts after recursive expansion
    permutation_hosts.txt    # stage 06 -- hosts found via permutation
    final_hosts.txt          # FINAL validated hostnames -- ONLY hostnames, one per line
  json/
    01_passive_sources.json
    02_wildcard_detection.json
    03_initial_dns_validation.json
    04_recursive_enumeration.json
    05_word_extraction.json
    06_permutation_validation.json
    07_reverse_dns.json           # PTR + ASN, per IP
    08_cloud_discovery.json
    09_dns_records.json
    10_final_filter_validation.json  # final hosts + TTL/resolver/RTT/DNSSEC
  reports/
    report.json    # full structured report: hostname -> IPs + everything else
    summary.json   # lean summary only: counts, provider health, duplicates,
                    # ASN/cloud groupings, confidence weights -- no per-host array
    report.csv
    report.html     # dark-themed, sortable, filterable
    report.md
  metadata.json     # first_seen/last_seen/sources/discovery_path per host
  intel.sqlite3      # run history (see section 15) -- separate from cache.sqlite3
  cache.sqlite3      # API + DNS cache (persists across runs)
  logs/
    run_<timestamp>.log   # full DEBUG-level log for this run, regardless of
                           # console verbosity (--quiet still gets a complete file)
  checkpoints/       # per-stage checkpoint files, auto-deleted after a
                      # successful run (see "Auto-cleanup" below)
```

**`txt/final_hosts.txt` contains ONLY validated hostnames** -- no IPs, no
metadata -- exactly the "just hostname" list. Every other field you asked
to track (sources, provider_count, confidence, records, cloud, wildcard,
recursive_depth, discovery_path, tags, metadata) lives in `reports/report.json`,
per host, e.g.:

```json
{
  "host": "login.example.com",
  "validated": true,
  "sources": ["crt.sh", "recursive-wayback"],
  "provider_count": 2,
  "confidence": 0.98,
  "confidence_label": "High",
  "records": {
    "ips": ["1.2.3.4"],
    "ttl": 300,
    "resolver_used": "8.8.8.8",
    "response_time_ms": 14.2,
    "dnssec": false,
    "dns_records": {"A": {"values": ["1.2.3.4"], "ttl": 300}, "MX": {...}}
  },
  "cloud": {"provider": "AWS", "service": "CloudFront", "evidence": "d123.cloudfront.net"},
  "wildcard": false,
  "recursive_depth": 1,
  "discovery_path": ["example.com"],
  "tags": ["recursive"],
  "metadata": {
    "first_seen": 1753350000.0,
    "last_seen": 1753350100.0,
    "validation_time": 1753350100.0,
    "ptr": {"1.2.3.4": "ec2-1-2-3-4.compute-1.amazonaws.com"},
    "asn": {"1.2.3.4": {"asn": "16509", "prefix": "1.2.3.0/24", "country": "US",
                          "registry": "arin", "org": "AMAZON-02"}}
  }
}
```

### Auto-cleanup

After a run finishes successfully, `output/checkpoints/` is deleted
automatically (there's nothing left to resume once every stage completed) --
`txt/`, `json/`, `reports/`, `metadata.json`, `cache.sqlite3` and `logs/` are
left in place; those are the actual deliverables. Pass `--keep-checkpoints`
if you want to inspect them or resume-analyze a run later.

## 4. Configuration profiles

Profile | threads | max_depth | perm/level | cache TTL | DNS resolvers checked
---|---|---|---|---|---
fast | 30 | 2 | 500 | 1h | system default
balanced | 60 | 5 | 3,000 | 6h | 8.8.8.8, 1.1.1.1
thorough | 100 | 8 | 20,000 | 24h | 8.8.8.8, 1.1.1.1, 9.9.9.9

```bash
python3 run.py -d example.com --profile thorough --max-depth 8
python3 run.py -d example.com --profile balanced --threads 120 --perm-limit 8000
python3 run.py -d example.com --profile balanced --config-file myconfig.json
```

`--config-file` accepts three formats, picked by extension:

```bash
python3 run.py -d example.com --config-file myconfig.json   # stdlib, always available
python3 run.py -d example.com --config-file myconfig.toml   # stdlib (tomllib, Python 3.11+), no extra install
python3 run.py -d example.com --config-file myconfig.yaml   # needs: pip install pyyaml --break-system-packages
```

Same keys, any format -- e.g. `myconfig.yaml`:
```yaml
threads: 80
max_depth: 6
cache_ttl_seconds: 3600
confidence_weights:
  cloud: 20
  permutation_penalty: -25
```


`--config-file` picks its parser from the extension -- `.json` (always
available), `.toml` (stdlib `tomllib`, Python 3.11+, no extra install), or
`.yaml`/`.yml` (needs `pip install pyyaml`, and raises a clear error
telling you that if it's missing rather than a confusing traceback):

```json
// myconfig.json
{ "threads": 80, "max_depth": 6, "cache_ttl_seconds": 3600 }
```

```yaml
# myconfig.yaml
threads: 80
max_depth: 6
cache_ttl_seconds: 3600
confidence_weights:
  cloud: 20
  permutation_penalty: -25
```

```toml
# myconfig.toml
threads = 80
max_depth = 6
cache_ttl_seconds = 3600
```

All three are equivalent -- pick whichever format you're already using
elsewhere in your tooling.

## 5. Smarter wildcard detection

Two problems with a naive single-probe wildcard check: (a) one resolver's
stale cache or a transient answer can produce a false positive, and (b) a
subdomain can have its **own** wildcard entry independent of the root
(`*.dev.example.com` catching everything even though `*.example.com` does
not).

This version fixes both:

- **Multi-probe, multi-resolver majority vote.** 4 random, essentially
  guaranteed-unregistered labels are probed across every resolver in the
  active profile (Google/Cloudflare/Quad9 on `balanced`/`thorough`). An IP
  only counts as part of the wildcard signature if it shows up for a
  **majority** of probe/resolver combinations -- a single fluke answer can't
  produce (or hide) a wildcard signal on its own. This is what fixes the
  "wildcard detection always returns 0" problem: the old version used a
  single static check that was too easy to miss transient wildcard
  responses, or too eager to call one stray IP a wildcard.
- **Per-level detection**, unchanged in spirit from before: before the
  permutation stage expands deeper under an already-validated host, it
  separately probes `*.<that host>` for its own wildcard signature. Hosts
  found to be wildcarded are kept in the results (`"wildcard": true` in the
  report) but not used as a base for further permutation.

## 6. DNS validation enrichment

Every final host's record in `reports/report.json` / `json/10_final_filter_validation.json`
now carries, in addition to the resolved IPs:

- **TTL** of the resolved record
- **Resolver used** (which of the configured resolvers actually answered)
- **Response time** in milliseconds
- **DNSSEC** -- best-effort check for the Authenticated Data (AD) flag on a
  DNSSEC-aware re-query

## 7. Recursive enumeration -- multi-source expansion

The old version only re-queried crt.sh per newly-discovered host. This
version expands each round through **multiple independent sources per
host**:

```
developer.example.com
   |
   +--> crt.sh (certificate SAN chaining)
   +--> Wayback Machine (archived URLs under the host)
   +--> GitHub code search (only if --github-token is set)
   +--> [opt-in, --active-recursion] JS file links + CSP header hostnames
```

Every newly-validated host records **which parent host it was discovered
under**, in `discovery_path` -- so you can trace exactly how
`vpn.internal.developer.example.com` was reached (e.g.
`["example.com", "developer.example.com", "internal.developer.example.com"]`).

### Performance: parallelized, with a frontier cap (fixes hour-long stalls)

An earlier version of this stage expanded `(host, source)` pairs **fully
sequentially** -- one blocking HTTP call at a time, each carrying its own
retry/backoff wait. Against a domain with hundreds of initially-validated
hosts (e.g. `crypto.com` with 425), that's 1000+ sequential calls hitting a
rate-limited free API like crt.sh, which could genuinely stall for an hour
or more on a single round.

Fixed two ways:

1. **Parallel expansion.** `(host, source)` pairs now run through a bounded
   thread pool (`recursion_threads` -- 10/20/30 on fast/balanced/thorough)
   instead of one at a time. Deliberately lower than the general
   `--threads` count so a big domain doesn't hammer a free-tier API hard
   enough to get IP-banned, while still overlapping every call's
   retry/backoff wait instead of paying it host-by-host.
2. **Frontier cap.** `max_recursion_frontier_per_round` (100/250/600 on
   fast/balanced/thorough) caps how many hosts get expanded in a single
   round on very large domains -- the rest stay validated and in your
   results, they just aren't recursed into during that run. Override or
   disable per run:

```bash
python3 run.py -d crypto.com --profile balanced --recursion-threads 30
python3 run.py -d crypto.com --profile balanced --max-recursion-frontier 0   # disable the cap
```

Or via `--config-file`:
```json
{ "recursion_threads": 25, "max_recursion_frontier_per_round": null }
```

## 8. Reverse DNS -- grouped by ASN / provider / cloud

`reports/report.json["reverse_dns_groups"]` (and the "Reverse DNS" sections
of `report.md` / `summary` output) group every final host by:

- **ASN** -- free, keyless lookup via Team Cymru's DNS-based whois service
  (`origin.asn.cymru.com` / `asn.cymru.com`; no API key, no rate-limited
  paid dependency)
- **Cloud provider** -- see below

Per-host PTR + ASN detail also lives under each host's `metadata.ptr` /
`metadata.asn` in the full report.

## 9. Cloud/CDN discovery

Each validated host's CNAME chain (up to 8 hops) is followed and matched
against known provider fingerprints:

CloudFront/S3/ELB -> **AWS** &nbsp;|&nbsp; azurefd/azurewebsites/blob.core.windows.net -> **Azure**
&nbsp;|&nbsp; appspot/run.app/cloudfunctions -> **GCP** &nbsp;|&nbsp; cloudflare.net -> **Cloudflare**
&nbsp;|&nbsp; fastly.net -> **Fastly** &nbsp;|&nbsp; akamai*/edgekey -> **Akamai** &nbsp;|&nbsp;
vercel.app -> **Vercel** &nbsp;|&nbsp; netlify.app -> **Netlify** &nbsp;|&nbsp; heroku* -> **Heroku**
&nbsp;|&nbsp; github.io -> **GitHub Pages**

Matches show up per host as `"cloud": {"provider": "AWS", "service": "CloudFront", "evidence": "...", "cname_chain": [...]}`
and are rolled up in `reverse_dns_groups.by_cloud_provider`. (It can only
report what a CNAME chain actually reveals -- a host pointed straight at a
bare IP with no CNAME won't be attributable this way; that's an inherent
limit of passive CNAME fingerprinting, not a bug.)

## 10. Resume & checkpoints

```bash
python3 run.py -d example.com --profile thorough --resume
python3 run.py -d example.com --profile thorough --fresh   # force a clean re-run
```

Pipeline stages, in order: `01_passive_sources`, `02_wildcard_detection`,
`03_initial_dns_validation`, `04_recursive_enumeration`, `05_word_extraction`,
`06_permutation_validation`, `07_reverse_dns` (+ ASN), `08_cloud_discovery`,
`09_dns_records`, `10_enrichment`, `11_final_filter_validation`.

## 11. Adding a new source (plugin architecture)

No core pipeline code needs to change. Create a new file in
`subdomain_recon/sources/`:

```python
# subdomain_recon/sources/my_source.py
from .base import Source, SourceContext

class MySource(Source):
    name = "my_source"
    confidence = "Medium"

    def fetch(self, domain, ctx: SourceContext):
        return [f"host1.{domain}", f"host2.{domain}"]
```

It's picked up automatically -- verify with `python3 run.py --list-plugins`.

## 12. Running the test suite

```bash
pip install pytest dnspython --break-system-packages
pytest tests/ -v
```

Covers: hostname normalization, scope/depth checks, config-profile loading
and overrides, confidence scoring, and the full `txt/ + json/ + reports/`
export layout (including the "auto-cleanup only removes checkpoints"
behavior).

## 13. Provider Health Summary

Every run ends with a per-source breakdown -- printed to the console and
embedded in `reports/report.md`:

```
Provider Summary
  alienvault_otx     ✓ 114 hosts
  certspotter        ✓ 98 hosts
  github             ✗ Missing key (github)
  chaos              ✗ Missing key (chaos)
  subfinder          ✓ 31 hosts

Unique Hosts : 421
Duplicates   : 198
Errors       : 2
```

`✗` distinguishes **skipped** (unavailable -- missing key or CLI binary,
named explicitly) from **error** (a real failure -- non-2xx HTTP status,
connection failure, non-zero CLI exit code, or timeout -- with the actual
reason in the message; see the "Silent failures made visible" changelog
entry above). A clean run that genuinely found zero hosts still correctly
shows `ok, 0 hosts` -- that distinction is the whole point of the fix.

### Logging flags

```bash
python3 run.py -d example.com --quiet     # console: warnings/errors + final summary only
python3 run.py -d example.com --verbose   # console: DEBUG level
python3 run.py -d example.com --debug     # console: DEBUG + full tracebacks for source failures
```

Regardless of console verbosity, a complete DEBUG-level log is always
written to `output/<domain>/logs/run_<timestamp>.log` -- `--quiet` only
affects what scrolls past on screen, not what's kept for later debugging.

## 14. Confidence engine

Full formula and JSON `confidence_breakdown` shape are in
`ARCHITECTURE.md`. Quick version -- additive points, configurable via
`--config-file`:

```json
{ "confidence_weights": { "cloud": 20, "permutation_penalty": -25 } }
```

Defaults: 2+ providers +20, DNS valid +20, recursive +15, cloud +10, GitHub
+15, crt.sh +10, permutation-only -15. Score clamped to `[0, 100]`; High
>= 70, Medium >= 40, else Low.

## 15. SQLite intelligence DB + diff mode

Every run is stored in `output/intel.sqlite3` (separate from the API/DNS
`cache.sqlite3`) -- run history, per-host history across runs, cross-run
duplicate detection, and hostname search are all plain SQL queries against
it (see `subdomain_recon/intel_db.py`). Skip this with `--no-intel-db` if
you don't want it.

```bash
# diff against a specific saved report
python3 run.py -d example.com --diff /path/to/old/reports/report.json

# diff against the most recent prior run for this domain in intel.sqlite3
python3 run.py -d example.com --diff auto
```

Writes `reports/diff.json` + `reports/diff.md` and logs a NEW/REMOVED
summary.

## 16. Resume + Ctrl+C

```bash
python3 run.py -d example.com --profile thorough --resume   # the ONLY way to skip the auto-wipe
python3 run.py -d example.com --profile thorough            # every other invocation auto-wipes first (see section 2)
```

`--fresh` still parses (so old scripts don't break) but is now a no-op --
wiping is the default whenever `--resume` isn't passed.

Pressing Ctrl+C mid-run no longer just dies silently -- it logs exactly
which stages were completed/checkpointed and prints the precise `--resume`
command to continue. Resume granularity is per-stage (see `ARCHITECTURE.md`
for why mid-stage resume isn't implemented). In batch mode (`-dL`), Ctrl+C
stops the whole batch after the current domain; already-finished domains
keep their results and the interrupted one can be resumed individually.

## 17. Developer tooling

```bash
pip install -r requirements-dev.txt   # pytest, black, ruff, mypy, pre-commit
pre-commit install                     # run lint+format+tests before every commit
black .
ruff check .
mypy .
pytest tests/ -v
```

CI (`.github/workflows/tests.yml`): lint (`ruff` + `black --check`) -> test
matrix (Python 3.11, 3.12) -> package build, each gating the next.

## 18. Troubleshooting

- **`pip install ... --break-system-packages` says "no such option"** --
  you're on an older pip; either upgrade pip or drop the flag and use a
  virtualenv instead.
- **dnspython not installed** -- basic A-record resolution falls back to
  Python's built-in `socket` module, but AAAA/CNAME/MX/TXT/NS/PTR, TTL,
  DNSSEC, and ASN lookups all require it: `pip install dnspython --break-system-packages`.
- **`subfinder` / `assetfinder` / `findomain` / `sublist3r` show "no (missing
  key/binary)"** -- these are optional external CLI tools; install them and
  make sure they're on `PATH`, or ignore them.
- **A source shows fewer hosts (or 0) here than running it standalone by
  hand** -- check the Provider Health Summary and `reports/report.json`'s
  `provider_health` section first: it now shows `error` with the real
  reason (timeout, exit code + stderr, HTTP status) whenever that's what
  actually happened, instead of a misleading `ok, 0 hosts` (see the fixes
  changelog above). If it genuinely says `ok, 0 hosts` with no error, the
  two runs likely just hit different upstream conditions (rate limits,
  transient network issues, or the standalone tool's own separate provider
  config/cache) -- re-run and compare, or run that one source standalone
  alongside this tool to compare directly.
- **Running multiple domains at once is slower/flakier than expected** --
  if you're launching several separate `python3 run.py -d ...` processes
  at the same time (one per domain) from the same machine, they all
  compete for the same free/rate-limited APIs and the same outbound
  connection pool simultaneously, which can trigger rate-limiting or
  timeouts across the board. Use `-dL/--domain-list` (section 2) instead
  -- it scans domains one at a time within a single process, so you get
  the same result without the self-inflicted concurrent load.
- **Empty `txt/final_hosts.txt`** -- check `output/logs/run_*.log` and the
  `errors` list inside `reports/report.json["metrics"]` -- most commonly no
  sources were reachable (no network / no keys / no CLI tools), or the
  domain has aggressive wildcard DNS filtering out every candidate (check
  `report.json["wildcard_ips"]`).
- **Cache seems stale** -- lower `cache_ttl_seconds` via `--config-file`, or
  delete `output/cache.sqlite3`.

## LICENSE

MIT -- see `LICENSE`. This tool is intended for authorized security testing
and research only. Only use it against domains and systems you own or have
explicit written permission to test. The authors accept no liability for
misuse.
