"""Evidence records and canonical serialisation helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Evidence(BaseModel):
    """Where a fact came from. Paths are repo-relative POSIX paths."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(min_length=1)
    source: str = Field(min_length=1)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    content_hash: str | None = None
    note: str | None = None

    @model_validator(mode="after")
    def _check_span(self) -> Evidence:
        if self.end_line is not None and (
            self.start_line is None or self.end_line < self.start_line
        ):
            raise ValueError("end_line requires start_line and must not precede it")
        return self

    def sort_key(self) -> tuple[str, int, int, str, str, str]:
        return (
            self.path,
            self.start_line or 0,
            self.end_line or 0,
            self.source,
            self.note or "",
            self.content_hash or "",
        )

    def as_json(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


def normalise_evidence(items: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
    """Deduplicate and sort so that row content never depends on discovery order."""
    return tuple(sorted(set(items), key=Evidence.sort_key))


def canonical_json(value: Any) -> str:
    """Stable JSON: sorted keys, no insignificant whitespace, UTF-8 kept as-is."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:24]}"
