"""Injectable time source. Nothing else in the package may read the wall clock."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC).replace(microsecond=0)


class FixedClock:
    def __init__(self, at: datetime) -> None:
        self._at = at.astimezone(UTC).replace(microsecond=0)

    def now(self) -> datetime:
        return self._at


def clock_from_env(env: dict[str, str] | None = None) -> Clock:
    """Honour SOURCE_DATE_EPOCH for reproducible runs; otherwise use the system clock."""
    raw = (os.environ if env is None else env).get("SOURCE_DATE_EPOCH")
    if raw is not None and raw.strip().isdigit():
        return FixedClock(datetime.fromtimestamp(int(raw), UTC))
    return SystemClock()


def isoformat(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
