"""
Persistent cache (SQLite) shared by API-source plugins and DNS lookups.

Two logical namespaces are used: 'api' and 'dns', so an API cache and a DNS
cache can be inspected/cleared independently even though they share one file.
Every entry has its own TTL (seconds); expired entries are treated as misses
and overwritten on next write.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from threading import Lock


class Cache:
    def __init__(self, path: str, default_ttl: int = 21600):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl
        self._lock = Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                expires_at REAL NOT NULL,
                PRIMARY KEY (namespace, key)
            )
            """
        )
        self._conn.commit()

    def get(self, namespace: str, key: str):
        with self._lock:
            cur = self._conn.execute(
                "SELECT value, expires_at FROM cache WHERE namespace=? AND key=?",
                (namespace, key),
            )
            row = cur.fetchone()
        if not row:
            return None
        value, expires_at = row
        if expires_at < time.time():
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None

    def set(self, namespace: str, key: str, value, ttl: int | None = None):
        ttl = self.default_ttl if ttl is None else ttl
        expires_at = time.time() + ttl
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO cache (namespace, key, value, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (namespace, key, json.dumps(value), expires_at),
            )
            self._conn.commit()

    def purge_expired(self):
        with self._lock:
            self._conn.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),))
            self._conn.commit()

    def clear(self, namespace: str | None = None):
        with self._lock:
            if namespace:
                self._conn.execute("DELETE FROM cache WHERE namespace=?", (namespace,))
            else:
                self._conn.execute("DELETE FROM cache")
            self._conn.commit()

    def stats(self) -> dict:
        with self._lock:
            cur = self._conn.execute(
                "SELECT namespace, COUNT(*) FROM cache GROUP BY namespace"
            )
            rows = cur.fetchall()
        return {ns: count for ns, count in rows}

    def close(self):
        self._conn.close()
