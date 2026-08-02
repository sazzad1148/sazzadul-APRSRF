from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class StageMetric:
    success: int = 0
    failure: int = 0
    errors: list = field(default_factory=list)
    runtime_seconds: float = 0.0


class MetricsCollector:
    def __init__(self):
        self.stages: dict[str, StageMetric] = {}

    @contextmanager
    def track(self, stage_name: str):
        sm = StageMetric()
        t0 = time.time()
        try:
            yield sm
        finally:
            sm.runtime_seconds = round(time.time() - t0, 2)
            if len(sm.errors) > 20:
                sm.errors = sm.errors[:20]
            self.stages[stage_name] = sm

    def to_dict(self) -> dict:
        return {
            name: {
                "runtime_seconds": sm.runtime_seconds,
                "success": sm.success,
                "failure": sm.failure,
                "errors": sm.errors,
            }
            for name, sm in self.stages.items()
        }
