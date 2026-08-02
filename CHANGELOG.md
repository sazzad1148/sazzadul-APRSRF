# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.2.2] -- The permutation-validation bottleneck (4+ seconds per host)

### Fixed
- **DNS resolution retried NXDOMAIN answers as if they were transient
  failures.** `_validate_one()` treated every exception from a DNS lookup
  identically -- timeout, SERVFAIL, and NXDOMAIN all fell into the same
  `except Exception: continue`, so a single nonexistent hostname could
  trigger up to `(retries+1) x len(resolvers) x 2` lookups (thorough
  profile: 4 x 3 x 2 = 24) before giving up. Permutation validation
  generates hundreds to tens of thousands of speculative hostnames, the
  large majority of which don't exist -- so this was the dominant cost
  there specifically (reported: 5,005 permutations at ~4.3s/host, a
  ~6-hour ETA at `max_depth=8`).

  **NXDOMAIN is a name-level, authoritative DNS answer** -- per the DNS
  spec, "this name does not exist" is true for every record type, so
  retrying it, querying a different record type, or asking a different
  resolver cannot change the answer. `_validate_one()` now returns
  immediately on the first NXDOMAIN: 1 query instead of up to 24 for the
  common (nonexistent) case. `NoAnswer` (name exists, no record of *this*
  type) is left alone -- still tries the other record type and other
  resolvers, since that one is genuinely worth a second opinion. Covered
  by 4 new tests, including one asserting the exact call count (1, not up
  to 24) and one simulating 200 NXDOMAIN hosts to catch any regression
  back toward per-host multi-second behavior.

## [3.2.1] -- The actual "stuck for hours despite parallelization" fix

### Fixed
- **The real root cause of multi-hour stalls, found after 3.2.0's
  parallelization wasn't enough on its own.** Both stage 1 (passive
  sources) and recursive enumeration used
  `with concurrent.futures.ThreadPoolExecutor(...) as ex:`. Exiting that
  `with` block calls `ex.shutdown(wait=True)`, which blocks until **every**
  submitted task finishes -- no matter how many already completed. So one
  abnormally slow response (a host sharing a wildcard certificate with
  thousands of unrelated names on crt.sh is a common real-world trigger)
  could hold an **entire round hostage** even though the other 175+ calls
  in that round finished in parallel correctly within seconds. Work was
  genuinely parallel; the *exit path* silently re-serialized on whichever
  straggler was slowest -- which is exactly what a 6.7x-faster-on-paper
  fix followed by "still stuck for hours" in practice looks like.

  Fixed with a hard per-stage wall-clock ceiling: `recursion_round_timeout`
  (fast=60s/balanced=180s/thorough=400s, `--recursion-round-timeout`) and
  `source_stage_timeout` (same defaults, `--source-stage-timeout`). Both
  stages now use an explicit (non-`with`) `ThreadPoolExecutor`, wait via
  `as_completed(futures, timeout=<ceiling>)`, and on timeout log which
  straggler(s) didn't finish, keep whatever completed, and call
  `ex.shutdown(wait=False, cancel_futures=True)` -- returns immediately,
  drops queued-but-not-started work, and does not block on already-running
  threads (Python can't forcibly kill a thread; they finish in the
  background and their results are simply discarded). A round can now
  never take longer than its configured ceiling, regardless of how slow
  the single worst response is. Covered by a dedicated regression test
  that fails if this ever regresses to blocking again.

## [3.2.0] -- Performance, observability, and cleanup

### Fixed
- **Passive source collection (stage 1) was fully sequential.** All 19
  sources were queried one at a time in a plain `for` loop -- with several
  slow/rate-limited free APIs and subprocess-spawning CLI tools in the mix,
  this alone could take 10+ minutes before DNS validation, recursion, or
  permutation even started. Now runs through a bounded parallel worker pool
  (`source_threads`, override with `--source-threads`). A simulation with a
  realistic latency spread went from 148s sequential to 22s parallel (6.7x).
- **Recursive enumeration was also fully sequential** -- `(host, source)`
  pairs one at a time. A 425-host case went from a ~170s estimate to ~5s
  after adding `recursion_threads` + an optional per-round frontier cap
  (`max_recursion_frontier_per_round`). Combined, these two fixes are what
  actually closes multi-hour runtimes, not new sources or algorithm changes.
- **Silent source failures** (subfinder/findomain/crt.sh reporting "0
  hosts" while working fine when run by hand) -- every source now raises a
  real error (`CLISourceError` / `HTTPSourceError`) on an actual failure
  (non-zero exit, timeout, non-2xx HTTP, connection failure) instead of
  swallowing it into an empty list. Shows up as `✗ Error: <real reason>` in
  the Provider Health Summary instead of a misleading `✓ 0 hosts`.
- `output/<domain>/logs/run_<timestamp>.log` was documented but never
  actually created -- now genuinely written, always at full DEBUG detail
  regardless of console verbosity.
- `--minimal` + `--diff` together used to silently delete
  `reports/diff.json`/`diff.md` (the one thing `--diff` was asked to
  produce) -- now preserved alongside `report.json`.
- A dead ternary in the Provider Health formatter (`"✓" if hosts > 0 else
  "✓"`) simplified to just the checkmark.

### Added
- **Detailed per-source metrics**: `raw_count`, `invalid_count`,
  `out_of_scope_count`, `duplicate_count` alongside the final `hosts`
  count for every source in `provider_health` -- answers "raw=558,
  invalid=6, final=428" instead of just a single opaque number, so a
  parsing/normalization problem is visible immediately instead of looking
  identical to "found nothing."
- `--source-threads` / `--recursion-threads` / `--max-recursion-frontier`
  CLI flags and matching per-profile defaults.
- `summary.json` (lean summary alongside the full `report.json`).
- YAML/TOML support for `--config-file` (in addition to JSON).
- `--debug` (full tracebacks for source failures) and `--quiet`
  (WARNING-level console only, full detail still goes to the log file).
- Progress display (`tqdm` bar if installed, periodic log lines
  otherwise) for DNS validation, reverse DNS, cloud discovery, and DNS
  record collection; a `[stage N/11] <name>` marker per pipeline stage.
- `-dL/--domain-list` batch mode (scan 2+ domains from a file, one at a
  time, each into its own output subfolder).
- Auto-fresh output: every run wipes that domain's output dir first
  unless `--resume` is passed (no more manually managing `--fresh`).
- `--minimal` mode: keep only `txt/final_hosts.txt` +
  `reports/report.json`, delete everything else.
- Output-dir PID lock (prevents two instances corrupting the same
  `output/` directory if accidentally run concurrently).
- SQLite intelligence DB (`intel.sqlite3`): run history, per-host
  history across runs, cross-run duplicate detection, hostname search.
- `--diff <report.json>` / `--diff auto`: NEW/REMOVED comparison against
  a prior run.
- Configurable, explainable confidence engine (additive point scoring,
  full breakdown per host, override any weight via `--config-file`).
- "Mr. Cool" startup banner (box-art logo + Author/Version/Engine/
  Mode/Status panel).
- `CONTRIBUTING.md`, this `CHANGELOG.md`, and an `examples/` folder with
  sample output.

### Changed
- **C99 and CertDB sources removed.** C99 was a paid API that didn't
  belong next to a free/freemium source set; CertDB was a stub with no
  real endpoint (no single standardized public "CertDB" service exists).
  Source count: 21 -> 19. If you have a real paid-API key you want wired
  in, the plugin pattern (drop a file in `subdomain_recon/sources/`) makes
  that a few-line addition -- see `ARCHITECTURE.md`.
- Module split for maintainability: `dns_utils.py` (445 lines) split into
  `dns_utils.py` (wildcard + core validation/PTR) and `enrichment.py` (ASN
  lookup, cloud fingerprinting, DNS record collection). `pipeline.py`'s
  recursion expanders moved to `recursion_expanders.py`; `build_report()`
  moved to `report_builder.py`. `pipeline.py`: 695 -> 601 lines.
- Test suite made fully network-independent (one test previously made
  real HTTP calls in a way that was resilient to failure but slow/noisy;
  now mocked like the rest of the suite). 59 tests total.

## [3.1.0] -- Confidence engine, provider health, intel DB (initial round)

### Added
- Auto-discovering plugin architecture confirmed/documented (was already
  in place: drop a `.py` file in `sources/`, no core changes needed).
- Reworked source-reliability scoring into an additive, explainable
  points-based confidence engine.
- Provider Health Summary (per-source ok/skipped/error + host counts).
- `txt/` + `json/` + `reports/` (json/csv/html/md) output structure.
- Resume/checkpoint support, graceful Ctrl+C handling.

## [3.0.0] -- Major feature expansion

### Added
- Grew from a handful of sources to 21: added Findomain, Sublist3r,
  Subfinder (CLI-wrapped), Chaos, AnubisDB, ThreatMiner, C99, CertDB
  (the last two later removed in 3.2.0 -- see above).
- Smart multi-resolver, majority-vote wildcard detection (root + per-level).
- Multi-source recursive enumeration (crt.sh SAN chaining + Wayback +
  GitHub + optional active JS/CSP scraping), with discovery-path tracking.
- Cloud/CDN fingerprinting (AWS, Azure, GCP, Cloudflare, Fastly, Akamai,
  Vercel, Netlify, Heroku, GitHub Pages) and ASN lookup (Team Cymru).
- DNS validation enrichment (TTL, resolver used, response time, DNSSEC).

## [2.0.0] and earlier

Baseline passive subdomain enumeration pipeline (predates this project's
involvement in maintaining/extending it): passive source collection, DNS
validation, deep permutation, resume/checkpointing, SQLite API/DNS cache,
rate-limit-aware retry with exponential backoff, JSON/CSV/HTML export.
