"""
Writes every output artifact from a completed Pipeline run, laid out as:

output/
  txt/
    passive_hosts.txt        # stage 01 candidates, pre-DNS-validation
    validated_hosts.txt      # stage 03 initial DNS-validated hosts
    recursive_hosts.txt      # stage 04 hosts after recursive expansion
    permutation_hosts.txt    # stage 06 hosts found via permutation
    final_hosts.txt          # stage 11 final validated hosts -- ONLY hostnames
  json/
    01_passive_sources.json
    02_wildcard_detection.json
    03_initial_dns_validation.json
    04_recursive_enumeration.json
    05_word_extraction.json
    06_permutation_validation.json
    07_reverse_dns.json          # PTR + ASN
    08_cloud_discovery.json
    09_dns_records.json
    10_final_filter_validation.json  # final hosts + TTL/resolver/RTT/DNSSEC enrichment
  reports/
    report.json   # full structured report (hostname -> IP + everything else)
    report.csv
    report.html
    report.md

Post-run, output/checkpoints/ (needed only for --resume) is deleted
automatically -- everything under txt/, json/, reports/, plus
metadata.json, cache.sqlite3 and logs/, is left in place.
"""
from __future__ import annotations

import csv
import html
import json
import shutil
import time
from pathlib import Path


def format_provider_summary(report: dict) -> str:
    """Plain-text Provider Health Summary, used both for the end-of-run
    console printout and embedded in reports/report.md."""
    health = report.get("provider_health", {})
    dup = report.get("duplicates", {})
    lines = ["Provider Summary"]
    name_width = max([len(n) for n in health] + [10]) + 2
    for name, info in sorted(health.items()):
        if info["status"] == "ok":
            raw = info.get("raw")
            detail = ""
            if raw is not None:
                rejected = info.get("rejected", 0)
                dup_in_source = info.get("duplicate_in_source", 0)
                detail = f"  (raw={raw}, rejected={rejected}, dup={dup_in_source})"
                if raw > 0 and info["hosts"] == 0:
                    detail += "  <-- got data but 0 survived normalization, check --debug"
            lines.append(f"  {name:<{name_width}} \u2713 {info['hosts']} hosts{detail}")
        elif info["status"] == "skipped":
            lines.append(f"  {name:<{name_width}} \u2717 {info['reason']}")
        else:
            lines.append(f"  {name:<{name_width}} \u2717 Error: {info['reason']}")
    lines.append("")
    lines.append(f"Unique Hosts : {dup.get('unique_hosts', 0)}")
    lines.append(f"Duplicates   : {dup.get('duplicate_mentions', 0)}")
    error_count = sum(1 for i in health.values() if i["status"] == "error")
    lines.append(f"Errors       : {error_count}")
    return "\n".join(lines)


# --------------------------------------------------------------------- #
# reports/report.json, report.csv, report.html, report.md
# --------------------------------------------------------------------- #
def write_json(report: dict, reports_dir: Path) -> None:
    (reports_dir / "report.json").write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )


def write_csv(report: dict, reports_dir: Path) -> None:
    with open(reports_dir / "report.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "hostname", "ips", "sources", "provider_count", "confidence",
            "confidence_label", "wildcard", "cloud_provider", "cloud_service",
            "recursive_depth", "discovery_path", "ttl", "resolver_used",
            "response_time_ms", "dnssec", "asn", "first_seen", "last_seen",
        ])
        for h in report["hosts"]:
            recs = h["records"]
            asn_orgs = sorted({info.get("org") or info.get("asn")
                                for info in h["metadata"]["asn"].values() if info})
            writer.writerow([
                h["host"], ";".join(recs["ips"]), ";".join(h["sources"]),
                h["provider_count"], h["confidence"], h["confidence_label"],
                h["wildcard"], h["cloud"].get("provider", ""), h["cloud"].get("service", ""),
                h["recursive_depth"], ";".join(h["discovery_path"]),
                recs.get("ttl", ""), recs.get("resolver_used", ""),
                recs.get("response_time_ms", ""), recs.get("dnssec", ""),
                ";".join(asn_orgs), h["metadata"].get("first_seen", ""),
                h["metadata"].get("last_seen", ""),
            ])


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>sazzad007 -- {domain}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d1117; color:#c9d1d9; font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin:0; padding:2rem; }}
  h1 {{ color:#ff2d55; }}
  .stats {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
  .stat {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:0.75rem 1.25rem; }}
  .stat b {{ display:block; font-size:1.4rem; color:#ff8c00; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.85rem; }}
  th, td {{ border-bottom:1px solid #30363d; padding:6px 8px; text-align:left; vertical-align:top; }}
  th {{ background:#161b22; position:sticky; top:0; cursor:pointer; }}
  tr:hover {{ background:#161b22; }}
  .tag {{ display:inline-block; background:#21262d; border:1px solid #30363d; border-radius:10px;
          padding:1px 8px; margin:1px; font-size:0.72rem; }}
  .high {{ color:#3fb950; }} .medium {{ color:#d29922; }} .low {{ color:#f85149; }}
  input#filter {{ padding:6px 10px; width:280px; margin-bottom:1rem; background:#161b22; color:#c9d1d9; border:1px solid #30363d; border-radius:6px; }}
</style></head>
<body>
<h1>sazzad007 -- passive + active subdomain recon</h1>
<p>Target: <b>{domain}</b> &middot; Generated: {generated} &middot; Runtime: {runtime}s</p>
<div class="stats">{stats_html}</div>
<input id="filter" placeholder="Filter hostnames..." onkeyup="filterTable()">
<table id="hosts">
<thead><tr>
<th>Host</th><th>IP(s)</th><th>Sources</th><th>Confidence</th><th>Cloud</th>
<th>Wildcard</th><th>Depth</th><th>Discovery Path</th><th>Tags</th>
</tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
<script>
function filterTable() {{
  const q = document.getElementById('filter').value.toLowerCase();
  document.querySelectorAll('#hosts tbody tr').forEach(row => {{
    row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
document.querySelectorAll('#hosts th').forEach((th, idx) => {{
  th.addEventListener('click', () => {{
    const tbody = document.querySelector('#hosts tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const asc = th.dataset.asc = th.dataset.asc === '1' ? '0' : '1';
    rows.sort((a, b) => {{
      const av = a.children[idx].innerText, bv = b.children[idx].innerText;
      return asc === '1' ? av.localeCompare(bv) : bv.localeCompare(av);
    }});
    rows.forEach(r => tbody.appendChild(r));
  }});
}});
</script>
</body></html>
"""


def write_html(report: dict, reports_dir: Path) -> None:
    counts = report["counts"]
    stats_html = "".join(
        f'<div class="stat"><b>{v}</b>{k.replace("_", " ")}</div>' for k, v in counts.items()
    )
    rows = []
    for h in report["hosts"]:
        conf_class = h["confidence_label"].lower()
        cloud = h["cloud"].get("provider", "")
        tags = " ".join(f'<span class="tag">{html.escape(t)}</span>' for t in h["tags"])
        rows.append(
            "<tr>"
            f"<td>{html.escape(h['host'])}</td>"
            f"<td>{html.escape(', '.join(h['records']['ips']))}</td>"
            f"<td>{html.escape(', '.join(h['sources']))}</td>"
            f"<td class='{conf_class}'>{h['confidence']} ({h['confidence_label']})</td>"
            f"<td>{html.escape(cloud)}</td>"
            f"<td>{'yes' if h['wildcard'] else 'no'}</td>"
            f"<td>{h['recursive_depth']}</td>"
            f"<td>{html.escape(' -> '.join(h['discovery_path']))}</td>"
            f"<td>{tags}</td>"
            "</tr>"
        )
    out = _HTML_TEMPLATE.format(
        domain=html.escape(report["domain"]),
        generated=time.strftime("%a %b %d %H:%M:%S %Y", time.localtime(report["generated_at"])),
        runtime=report.get("total_runtime_seconds", "?"),
        stats_html=stats_html,
        rows_html="\n".join(rows),
    )
    (reports_dir / "report.html").write_text(out, encoding="utf-8")


def write_markdown(report: dict, reports_dir: Path, profile: str, max_depth) -> None:
    counts = report["counts"]
    lines = [
        f"# Subdomain recon report -- {report['domain']}",
        "",
        f"**Profile:** {profile}  |  **Max depth:** {max_depth}  |  "
        f"**Generated:** {time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(report['generated_at']))}  |  "
        f"**Runtime:** {report.get('total_runtime_seconds', '?')}s",
        "",
        "## Counts",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for k, v in counts.items():
        lines.append(f"| {k.replace('_', ' ')} | {v} |")

    lines += ["", f"**Wildcard IPs:** `{report['wildcard_ips']}`", ""]

    lines += ["## Provider health", "", "```", format_provider_summary(report), "```", ""]

    weights = report.get("confidence_weights", {})
    lines += ["## Confidence engine (active weights)", "", "| Condition | Points |", "|---|---|"]
    for k, v in weights.items():
        lines.append(f"| {k.replace('_', ' ')} | {v:+d} |" if isinstance(v, int) else f"| {k} | {v} |")
    lines.append("")
    lines.append(f"_Score = sum of matching conditions, clamped to [0, 100]. "
                 f"High >= 70, Medium >= 40, else Low. Override any weight via "
                 f"`--config-file` (key `confidence_weights`)._")
    lines.append("")

    lines += ["## Reverse DNS -- grouped by ASN", "", "| ASN | Hosts |", "|---|---|"]
    for asn, hosts in report["reverse_dns_groups"]["by_asn"].items():
        lines.append(f"| AS{asn} | {len(hosts)} |")

    lines += ["", "## Reverse DNS -- grouped by cloud provider", "", "| Provider | Hosts |", "|---|---|"]
    for provider, hosts in report["reverse_dns_groups"]["by_cloud_provider"].items():
        lines.append(f"| {provider} | {len(hosts)} |")

    lines += ["", "## Final validated hosts", "",
              "| Host | IP(s) | Confidence | Cloud | Wildcard | Depth | Tags |",
              "|---|---|---|---|---|---|---|"]
    for h in report["hosts"]:
        lines.append(
            f"| {h['host']} | {', '.join(h['records']['ips'])} | "
            f"{h['confidence']} ({h['confidence_label']}) | "
            f"{h['cloud'].get('provider', '')} | {'yes' if h['wildcard'] else 'no'} | "
            f"{h['recursive_depth']} | {', '.join(h['tags'])} |"
        )

    lines += ["", "## Per-stage metrics", "", "| Stage | Runtime (s) | OK | Fail | Errors |",
              "|---|---|---|---|---|"]
    for stage, m in report["metrics"].items():
        lines.append(f"| {stage} | {m['runtime_seconds']} | {m['success']} | "
                      f"{m['failure']} | {len(m['errors'])} |")

    (reports_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_summary_json(report: dict, reports_dir: Path) -> None:
    """A lean, fast-to-parse summary -- total/live/wildcard/cloud/ASN
    counts plus provider health and confidence weights -- without the
    full per-host array. Useful for scripting/dashboards that only need
    the numbers, not every host's full record."""
    hosts = report["hosts"]
    cloud_counts: dict[str, int] = {}
    for h in hosts:
        provider = h["cloud"].get("provider")
        if provider:
            cloud_counts[provider] = cloud_counts.get(provider, 0) + 1

    summary = {
        "domain": report["domain"],
        "generated_at": report["generated_at"],
        "total_runtime_seconds": report.get("total_runtime_seconds"),
        "counts": report["counts"],
        "live_hosts": len(hosts),
        "wildcard_hosts": sum(1 for h in hosts if h["wildcard"]),
        "cloud_hosts": sum(1 for h in hosts if h["cloud"]),
        "cloud_by_provider": cloud_counts,
        "asn_groups": {asn: len(hs) for asn, hs in report["reverse_dns_groups"]["by_asn"].items()},
        "provider_health": report.get("provider_health", {}),
        "duplicates": report.get("duplicates", {}),
        "confidence_weights": report.get("confidence_weights", {}),
        "wildcard_ips": report.get("wildcard_ips", []),
    }
    (reports_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")


def write_reports(report: dict, out_dir: Path, profile: str, max_depth) -> None:
    reports_dir = out_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    write_json(report, reports_dir)
    write_summary_json(report, reports_dir)
    write_csv(report, reports_dir)
    write_html(report, reports_dir)
    write_markdown(report, reports_dir, profile, max_depth)


# --------------------------------------------------------------------- #
# txt/ -- one hostname-only file per key stage
# --------------------------------------------------------------------- #
def write_stage_txt(pipeline, report: dict, out_dir: Path) -> None:
    txt_dir = out_dir / "txt"
    txt_dir.mkdir(parents=True, exist_ok=True)
    snap = pipeline.stage_snapshots

    def _dump(filename: str, hosts_iterable) -> None:
        lines = sorted(set(hosts_iterable))
        (txt_dir / filename).write_text(
            "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
        )

    _dump("passive_hosts.txt", snap.get("01_passive_sources", {}).keys())
    _dump("validated_hosts.txt", snap.get("03_initial_dns_validation", {}).keys())
    _dump("recursive_hosts.txt", snap.get("04_recursive_enumeration", {}).keys())
    _dump("permutation_hosts.txt", snap.get("06_permutation_validation", {}).keys())
    _dump("final_hosts.txt", (h["host"] for h in report["hosts"]))  # only hostnames


# --------------------------------------------------------------------- #
# json/ -- one raw snapshot per pipeline stage
# --------------------------------------------------------------------- #
def write_stage_json(pipeline, out_dir: Path) -> None:
    json_dir = out_dir / "json"
    json_dir.mkdir(parents=True, exist_ok=True)
    snap = pipeline.stage_snapshots

    def _dump(filename: str, data) -> None:
        (json_dir / filename).write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8"
        )

    _dump("01_passive_sources.json", snap.get("01_passive_sources", {}))
    _dump("02_wildcard_detection.json", snap.get("02_wildcard_detection", []))
    _dump("03_initial_dns_validation.json", snap.get("03_initial_dns_validation", {}))
    _dump("04_recursive_enumeration.json", snap.get("04_recursive_enumeration", {}))
    _dump("05_word_extraction.json", snap.get("05_word_extraction", []))
    _dump("06_permutation_validation.json", snap.get("06_permutation_validation", {}))
    _dump("07_reverse_dns.json", {
        "ptr": snap.get("07_reverse_dns", {}),
        "asn": snap.get("07b_asn_lookup", {}),
    })
    _dump("08_cloud_discovery.json", snap.get("08_cloud_discovery", {}))
    _dump("09_dns_records.json", snap.get("09_dns_records", {}))
    _dump("10_final_filter_validation.json", {
        "validated": snap.get("11_final_filter_validation", {}),
        "enrichment": snap.get("10_enrichment", {}),
    })


# --------------------------------------------------------------------- #
def write_all(report: dict, out_dir: str, profile: str = "balanced", max_depth=None,
              pipeline=None) -> None:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    write_reports(report, out_path, profile, max_depth)
    if pipeline is not None:
        write_stage_txt(pipeline, report, out_path)
        write_stage_json(pipeline, out_path)


def cleanup_intermediate(out_dir: str) -> None:
    """Post-run cleanup: once a run completes successfully, the per-stage
    checkpoint files are no longer needed (there's nothing left to resume),
    so they're removed automatically. txt/, json/, reports/, metadata.json,
    cache.sqlite3 and logs/ are all left in place -- those ARE the
    deliverables."""
    checkpoints_dir = Path(out_dir) / "checkpoints"
    if checkpoints_dir.exists():
        shutil.rmtree(checkpoints_dir, ignore_errors=True)


def cleanup_to_minimal(out_dir: str) -> None:
    """Stricter cleanup (opt-in, via --minimal): deletes EVERYTHING except
    the final-report files -- txt/final_hosts.txt (hostnames only),
    reports/report.json (the full structured report), and, if a --diff was
    run in the same invocation, reports/diff.json + reports/diff.md (those
    are also final output, not intermediate scratch -- deleting them would
    silently throw away the one thing --diff was asked to produce).
    Removes the other per-stage txt/json snapshots, report.csv/.html/.md,
    the API/DNS cache, the intel DB, checkpoints, and logs. Use this when
    you only care about the final validated-subdomain result and don't
    need any of the intermediate/debugging artifacts."""
    out_path = Path(out_dir)
    KEEP_REPORTS_FILES = {"report.json", "diff.json", "diff.md"}

    for name in ("checkpoints", "json", "logs"):
        d = out_path / name
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)

    txt_dir = out_path / "txt"
    if txt_dir.exists():
        for f in txt_dir.iterdir():
            if f.name != "final_hosts.txt":
                f.unlink(missing_ok=True)

    reports_dir = out_path / "reports"
    if reports_dir.exists():
        for f in reports_dir.iterdir():
            if f.name not in KEEP_REPORTS_FILES:
                f.unlink(missing_ok=True)

    for name in ("cache.sqlite3", "intel.sqlite3", "metadata.json"):
        f = out_path / name
        if f.exists():
            f.unlink(missing_ok=True)
