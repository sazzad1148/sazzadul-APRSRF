"""
SQLite "intelligence" database -- separate from cache.sqlite3 (which only
holds transient API/DNS cache entries). This one is an append-only history
of every completed run: what hosts existed, with what confidence/sources/
cloud info, per run. It's what makes diff mode, cross-run search, and
duplicate/host-history queries possible without re-parsing old JSON files.

Schema
------
runs(run_id TEXT PRIMARY KEY, domain TEXT, started_at REAL, profile TEXT,
     final_host_count INTEGER)
hosts(run_id TEXT, host TEXT, ips TEXT, sources TEXT, confidence INTEGER,
      confidence_label TEXT, cloud_provider TEXT, wildcard INTEGER,
      recursive_depth INTEGER, discovery_path TEXT, tags TEXT,
      first_seen REAL, last_seen REAL, PRIMARY KEY (run_id, host))

`ips`, `sources`, `discovery_path`, `tags` are stored as JSON text blobs;
decoded back into Python objects on read.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


def _run_id_for(domain: str, timestamp: float) -> str:
    return f"{domain}:{int(timestamp)}"


class IntelDB:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY, domain TEXT, started_at REAL,
                profile TEXT, final_host_count INTEGER
            )"""
        )
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS hosts (
                run_id TEXT, host TEXT, ips TEXT, sources TEXT,
                confidence INTEGER, confidence_label TEXT, cloud_provider TEXT,
                wildcard INTEGER, recursive_depth INTEGER, discovery_path TEXT,
                tags TEXT, first_seen REAL, last_seen REAL,
                PRIMARY KEY (run_id, host)
            )"""
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_host ON hosts(host)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_domain ON runs(domain)")
        self._conn.commit()

    # ------------------------------------------------------------------ #
    def store_run(self, report: dict, profile: str = "") -> str:
        domain = report["domain"]
        started_at = report.get("generated_at", time.time())
        run_id = _run_id_for(domain, started_at)

        self._conn.execute(
            "INSERT OR REPLACE INTO runs (run_id, domain, started_at, profile, final_host_count) "
            "VALUES (?, ?, ?, ?, ?)",
            (run_id, domain, started_at, profile, len(report["hosts"])),
        )
        for h in report["hosts"]:
            self._conn.execute(
                "INSERT OR REPLACE INTO hosts (run_id, host, ips, sources, confidence, "
                "confidence_label, cloud_provider, wildcard, recursive_depth, discovery_path, "
                "tags, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id, h["host"], json.dumps(h["records"]["ips"]), json.dumps(h["sources"]),
                    h["confidence"], h["confidence_label"], h["cloud"].get("provider"),
                    int(h["wildcard"]), h["recursive_depth"], json.dumps(h["discovery_path"]),
                    json.dumps(h["tags"]), h["metadata"].get("first_seen"),
                    h["metadata"].get("last_seen"),
                ),
            )
        self._conn.commit()
        return run_id

    # ------------------------------------------------------------------ #
    def list_runs(self, domain: str) -> list[dict]:
        cur = self._conn.execute(
            "SELECT run_id, started_at, profile, final_host_count FROM runs "
            "WHERE domain=? ORDER BY started_at DESC", (domain,),
        )
        return [
            {"run_id": r[0], "started_at": r[1], "profile": r[2], "final_host_count": r[3]}
            for r in cur.fetchall()
        ]

    def latest_run_id(self, domain: str, before: float | None = None) -> str | None:
        if before is None:
            cur = self._conn.execute(
                "SELECT run_id FROM runs WHERE domain=? ORDER BY started_at DESC LIMIT 1",
                (domain,),
            )
        else:
            cur = self._conn.execute(
                "SELECT run_id FROM runs WHERE domain=? AND started_at < ? "
                "ORDER BY started_at DESC LIMIT 1", (domain, before),
            )
        row = cur.fetchone()
        return row[0] if row else None

    def hosts_for_run(self, run_id: str) -> set[str]:
        cur = self._conn.execute("SELECT host FROM hosts WHERE run_id=?", (run_id,))
        return {r[0] for r in cur.fetchall()}

    def host_history(self, domain: str, host: str) -> list[dict]:
        """Every run (for this domain) in which `host` was seen -- the
        "history" query the tool review asked for."""
        cur = self._conn.execute(
            "SELECT hosts.run_id, runs.started_at, hosts.confidence, hosts.confidence_label "
            "FROM hosts JOIN runs ON hosts.run_id = runs.run_id "
            "WHERE runs.domain=? AND hosts.host=? ORDER BY runs.started_at",
            (domain, host),
        )
        return [
            {"run_id": r[0], "started_at": r[1], "confidence": r[2], "confidence_label": r[3]}
            for r in cur.fetchall()
        ]

    def search(self, domain: str, substring: str) -> list[str]:
        """Hosts (ever seen, any run) for this domain containing `substring`."""
        cur = self._conn.execute(
            "SELECT DISTINCT hosts.host FROM hosts JOIN runs ON hosts.run_id = runs.run_id "
            "WHERE runs.domain=? AND hosts.host LIKE ? ORDER BY hosts.host",
            (domain, f"%{substring}%"),
        )
        return [r[0] for r in cur.fetchall()]

    def duplicate_hosts_across_runs(self, domain: str) -> dict[str, int]:
        """Hosts that showed up in more than one run for this domain, with
        how many runs each appeared in."""
        cur = self._conn.execute(
            "SELECT hosts.host, COUNT(DISTINCT hosts.run_id) as n "
            "FROM hosts JOIN runs ON hosts.run_id = runs.run_id "
            "WHERE runs.domain=? GROUP BY hosts.host HAVING n > 1 ORDER BY n DESC",
            (domain,),
        )
        return {r[0]: r[1] for r in cur.fetchall()}

    def close(self) -> None:
        self._conn.close()
