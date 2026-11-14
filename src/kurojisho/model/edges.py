"""Graph edge model."""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from kurojisho.model.enums import EdgeType, Provenance
from kurojisho.model.provenance import Evidence, canonical_json, normalise_evidence, stable_id


class Edge(BaseModel):
    """A typed edge. ``discriminator`` separates parallel edges of the same type."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: EdgeType
    src: str = Field(min_length=1)
    dst: str = Field(min_length=1)
    discriminator: str = ""
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
        return stable_id("e", self.type.value, self.src, self.dst, self.discriminator)

    def content(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "src": self.src,
            "dst": self.dst,
            "owner_file": self.owner_file,
            "props": self.props,
            "provenance": self.provenance.value,
            "confidence": self.confidence,
            "evidence": [e.as_json() for e in self.evidence],
        }

    def row_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.content()).encode("utf-8")).hexdigest()
