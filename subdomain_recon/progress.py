"""
Progress display for long-running batch operations (DNS validation,
reverse DNS, cloud discovery, record collection, per-round recursion).

Uses `tqdm` if it's installed (nice bar + rate + ETA, `pip install tqdm`),
and falls back to periodic plain-text "N/Total (rate/s, ETA Xs)" log lines
if it isn't -- so the tool works identically either way, just prettier
with tqdm.
"""
from __future__ import annotations

import logging
import sys
import time

try:
    from tqdm import tqdm as _tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False


class ProgressReporter:
    """Context-manager-style progress reporter for a batch of `total` items
    processed one at a time (typically inside a ThreadPoolExecutor
    as_completed loop). Call .update(1) as each item finishes.

    quiet=True suppresses all progress output (still tracks internally,
    just doesn't print) -- used for --quiet mode.
    """

    def __init__(self, total: int, desc: str, quiet: bool = False, log_every: int = 100):
        self.total = total
        self.desc = desc
        self.quiet = quiet or total == 0
        self.log_every = log_every
        self._done = 0
        self._t0 = time.time()
        self._bar = None
        if _HAS_TQDM and not self.quiet and sys.stderr.isatty():
            self._bar = _tqdm(total=total, desc=desc, unit="host", leave=False)

    def update(self, n: int = 1) -> None:
        self._done += n
        if self._bar is not None:
            self._bar.update(n)
            return
        if self.quiet:
            return
        if self._done % self.log_every == 0 or self._done == self.total:
            elapsed = max(time.time() - self._t0, 1e-6)
            rate = self._done / elapsed
            remaining = self.total - self._done
            eta = remaining / rate if rate > 0 else float("inf")
            eta_str = f"{eta:.0f}s" if eta != float("inf") else "?"
            logging.info(f"[{self.desc}] {self._done}/{self.total} "
                         f"({rate:.1f}/s, ETA {eta_str})")

    def close(self) -> None:
        if self._bar is not None:
            self._bar.close()


def log_stage_progress(stage_num: int, total_stages: int, name: str) -> None:
    """One-line 'Stage N/Total: <name>' marker, logged at the start of
    every pipeline stage so a long run shows overall progress even before
    any per-item progress bar for that stage starts."""
    logging.info(f"[stage {stage_num}/{total_stages}] {name}")
