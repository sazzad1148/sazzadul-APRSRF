# Examples

`output/` in this folder is **sample output** -- generated from synthetic
data using the tool's real export code (`subdomain_recon/exporters.py`), so
it's guaranteed to match the actual current schema exactly (not hand-typed
and liable to drift). It is NOT the result of scanning the real
`example.com` -- every hostname, IP, and count here is fabricated to
illustrate the shape of the output, including a few intentionally
interesting cases:

- `www.example.com` -- high confidence, multiple sources, Cloudflare CNAME chain
- `api2.developer.example.com` -- discovered two hops deep via recursion
  (`discovery_path: ["example.com", "developer.example.com"]`)
- `staging.example.com` -- permutation-only (low confidence, penalty
  applied) and flagged `wildcard-suspect`
- `mail.example.com` -- has MX/TXT records in `records.dns_records`
- `provider_health` shows all three states: `ok` (with the raw/invalid/
  duplicate breakdown), `skipped` (missing key/binary), and `error`
  (a real failure reason, not a silent zero)

Files:

```
output/
  txt/
    final_hosts.txt      # just hostnames -- what --minimal keeps
    passive_hosts.txt
  reports/
    report.json           # full schema -- see ARCHITECTURE.md for the field-by-field breakdown
    summary.json           # lean version of the same run
    report.csv
    report.html            # open this one in a browser -- sortable/filterable table
    report.md
```

`config/` holds a sample override file in each supported format (same
keys, pick whichever syntax you prefer):

```bash
python3 run.py -d example.com --config-file examples/config/sample.json
python3 run.py -d example.com --config-file examples/config/sample.yaml
python3 run.py -d example.com --config-file examples/config/sample.toml
```

`domains.txt` is a sample input for batch mode:
```bash
python3 run.py -dL examples/domains.txt --profile balanced
```
