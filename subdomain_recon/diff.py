"""Diff mode: compare the current run's final hosts against a previous
run and report NEW / REMOVED (and unchanged count).

The "previous" side can come from either:
  * a saved report.json file (--diff /path/to/old/report.json), or
  * the intelligence DB's most recent prior run for the same domain
    (--diff auto)
"""
from __future__ import annotations

import json
from pathlib import Path


def load_hosts_from_report_json(path: str) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {h["host"] for h in data.get("hosts", [])}


def load_hosts_from_intel_db(intel_db, domain: str, before: float | None = None) -> set[str] | None:
    run_id = intel_db.latest_run_id(domain, before=before)
    if run_id is None:
        return None
    return intel_db.hosts_for_run(run_id)


def compute_diff(old_hosts: set[str], new_hosts: set[str]) -> dict:
    new = sorted(new_hosts - old_hosts)
    removed = sorted(old_hosts - new_hosts)
    unchanged = sorted(old_hosts & new_hosts)
    return {
        "new": new,
        "removed": removed,
        "unchanged_count": len(unchanged),
        "old_count": len(old_hosts),
        "new_count": len(new_hosts),
    }


def render_diff_text(diff: dict) -> str:
    lines = []
    lines.append("NEW")
    if diff["new"]:
        lines.extend(f"  {h}" for h in diff["new"])
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("REMOVED")
    if diff["removed"]:
        lines.extend(f"  {h}" for h in diff["removed"])
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append(f"Unchanged: {diff['unchanged_count']}  |  "
                  f"Previous total: {diff['old_count']}  |  Current total: {diff['new_count']}")
    return "\n".join(lines)


def write_diff_files(diff: dict, out_dir: Path) -> None:
    reports_dir = out_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "diff.json").write_text(json.dumps(diff, indent=2), encoding="utf-8")

    md = ["# Diff report", "", "## NEW", ""]
    md += [f"- {h}" for h in diff["new"]] or ["_(none)_"]
    md += ["", "## REMOVED", ""]
    md += [f"- {h}" for h in diff["removed"]] or ["_(none)_"]
    md += ["", f"Unchanged: {diff['unchanged_count']}  |  "
               f"Previous total: {diff['old_count']}  |  Current total: {diff['new_count']}"]
    (reports_dir / "diff.md").write_text("\n".join(md) + "\n", encoding="utf-8")
