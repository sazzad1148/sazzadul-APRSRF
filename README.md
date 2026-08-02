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
git clone https://github.com/sazzad1148/sazzadul-APRSRF.git
cd sazzadul-APRSRF          # the folder containing run.py

pip install -r requirements.txt --break-system-packages
# (or, pip-installable form: pip install -e .   -- gives you the
#  `passive-enum` command too, see section 2/17 below)

cp .env.example
nano.env     # optional -- fill in any free API keys you have
GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
CENSYS_API_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
CENSYS_API_SECRET="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
VIRUSTOTAL_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
URLSCAN_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
FULLHUNT_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
CHAOS_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
## SAVE
Ctrl + O → Save (Write Out)
Enter 
Ctrl + X → Nano

python3 run.py -d example.com --profile fast     # run 2 -> output/ auto-wiped first, clean result
python3 run.py -d example.com --profile fast --resume   # only this one preserves the prior output
python3 run.py -d example.com --profile balanced
python3 run.py -d example.com --profile thorough --max-depth 8

### Scanning multiple domains at once (`-dL` / `--domain-list`)

python3 run.py -dL example.txt --profile fast
python3 run.py -dL example.txt --profile balanced
python3 run.py -dL example.txt --profile thorough
<img width="366" height="151" alt="image" src="https://github.com/user-attachments/assets/e3271702-44c5-4e1b-8fa6-153ba4e73219" />


python3 run.py -d example.com --recursion-round-timeout 120   # default: 60/180/400s by profile
python3 run.py -d example.com --source-stage-timeout 120      # default: 60/180/400s by profile


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


`--config-file` accepts three formats, picked by extension:

```bash
python3 run.py -d example.com --config-file myconfig.json   # stdlib, always available
python3 run.py -d example.com --config-file myconfig.toml   # stdlib (tomllib, Python 3.11+), no extra install
python3 run.py -d example.com --config-file myconfig.yaml   # needs: pip install pyyaml --break-system-packages
```





```bash
python3 run.py -d crypto.com --profile balanced --recursion-threads 30
python3 run.py -d crypto.com --profile balanced --max-recursion-frontier 0   # disable the cap
```

##  Resume & checkpoints

```bash
python3 run.py -d example.com --profile thorough --resume
python3 run.py -d example.com --profile thorough --fresh   # force a clean re-run
```

Pipeline stages, in order: `01_passive_sources`, `02_wildcard_detection`,
`03_initial_dns_validation`, `04_recursive_enumeration`, `05_word_extraction`,
`06_permutation_validation`, `07_reverse_dns` (+ ASN), `08_cloud_discovery`,
`09_dns_records`, `10_enrichment`, `11_final_filter_validation`.

##  Running the test suite

```bash
pip install pytest dnspython --break-system-packages
pytest tests/ -v
```

Covers: hostname normalization, scope/depth checks, config-profile loading
and overrides, confidence scoring, and the full `txt/ + json/ + reports/`
export layout (including the "auto-cleanup only removes checkpoints"
behavior).
### Logging flags

```bash
python3 run.py -d example.com --quiet     # console: warnings/errors + final summary only
python3 run.py -d example.com --verbose   # console: DEBUG level
python3 run.py -d example.com --debug     # console: DEBUG + full tracebacks for source failures
```

```bash
# diff against a specific saved report
python3 run.py -d example.com --diff /path/to/old/reports/report.json

# diff against the most recent prior run for this domain in intel.sqlite3
python3 run.py -d example.com --diff auto
##  Resume + Ctrl+C

## LICENSE

MIT -- see `LICENSE`. This tool is intended for authorized security testing
and research only. Only use it against domains and systems you own or have
explicit written permission to test. The authors accept no liability for
misuse.
