from __future__ import annotations

import json
from pathlib import Path

STAGE_ORDER = [
    "01_passive_sources",
    "02_wildcard_detection",
    "03_initial_dns_validation",
    "04_recursive_enumeration",
    "05_word_extraction",
    "06_permutation_validation",
    "07_reverse_dns",
    "08_cloud_discovery",
    "09_dns_records",
    "10_enrichment",
    "11_final_filter_validation",
]


class CheckpointManager:
    def __init__(self, out_dir: str, resume: bool = False):
        self.dir = Path(out_dir) / "checkpoints"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.resume = resume

    def _path(self, stage_name: str) -> Path:
        return self.dir / f"{stage_name}.json"

    def has(self, stage_name: str) -> bool:
        return self.resume and self._path(stage_name).exists()

    def load(self, stage_name: str):
        return json.loads(self._path(stage_name).read_text(encoding="utf-8"))

    def save(self, stage_name: str, data):
        self._path(stage_name).write_text(
            json.dumps(data, default=list), encoding="utf-8"
        )

    def clear_all(self):
        for f in self.dir.glob("*.json"):
            try:
                f.unlink()
            except OSError:
                pass
        try:
            self.dir.rmdir()
        except OSError:
            pass
