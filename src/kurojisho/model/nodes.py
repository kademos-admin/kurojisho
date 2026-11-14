"""Graph node model."""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from kurojisho.model.enums import NodeType, Provenance
from kurojisho.model.provenance import Evidence, canonical_json, normalise_evidence, stable_id


def node_key(node_type: NodeType, *parts: str) -> str:
    """Human-readable unique key, e.g. ``Function:app/views.py::Cart.total``."""
    return f"{node_type.value}:{'::'.join(parts)}"


def node_id(key: str) -> str:
    return stable_id("n", key)


class Node(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    type: NodeType
    key: str = Field(min_length=1)
    name: str
    owner_file: str | None = None
    props: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: tuple[Evidence, ...] = Field(min_length=1)

    @field_validator("evidence")
    @classmethod
    def _sorted_evidence(cls, value: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
        return normalise_evidence(value)

    @property
    def id(self) -> str:
        return node_id(self.key)

    def content(self) -> dict[str, Any]:
        """Everything that defines the row, excluding first/last seen bookkeeping."""
        return {
            "id": self.id,
            "type": self.type.value,
            "key": self.key,
            "name": self.name,
            "owner_file": self.owner_file,
            "props": self.props,
            "provenance": self.provenance.value,
            "confidence": self.confidence,
            "evidence": [e.as_json() for e in self.evidence],
        }

    def row_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.content()).encode("utf-8")).hexdigest()
