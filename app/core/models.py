from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class ScanRequest:
    target: str
    scan_type: str = "quick"
    extra_args: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    tool: str
    target: str
    command: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    status: str = "success"
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()
