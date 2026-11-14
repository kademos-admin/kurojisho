"""Enumerations shared by the graph model."""

from __future__ import annotations

from enum import StrEnum


class Provenance(StrEnum):
    EXTRACTED = "EXTRACTED"
    INFERRED = "INFERRED"
    TOOL = "TOOL"
    INTEL = "INTEL"
    ASSERTED = "ASSERTED"
    LLM_SUGGESTED = "LLM_SUGGESTED"


class NodeType(StrEnum):
    # TODO(M2+): security, deployment, AI, standards and finding node types.
    REPO = "Repo"
    MODULE = "Module"
    FILE = "File"
    CLASS = "Class"
    FUNCTION = "Function"
    ROUTE = "Route"
    PACKAGE = "Package"
    ASSET = "Asset"


class EdgeType(StrEnum):
    # TODO(M2+): remaining edge types from the schema.
    CONTAINS = "CONTAINS"
    DEFINES = "DEFINES"
    IMPORTS = "IMPORTS"
    INHERITS = "INHERITS"
    CALLS = "CALLS"
    DEPENDS_ON = "DEPENDS_ON"
    BELONGS_TO = "BELONGS_TO"


class Resolution(StrEnum):
    EXACT = "exact"
    NAME_MATCH = "name_match"
    DYNAMIC_UNKNOWN = "dynamic_unknown"


class Scope(StrEnum):
    RUNTIME = "runtime"
    DEV = "dev"
    TEST = "test"
    # Not in the schema table: used when a lockfile gives no way to tell. Unknown is never
    # treated as "not shipped"; consumers must rank it with runtime.
    UNKNOWN = "unknown"


#: Confidence assigned to each call-resolution outcome (all INFERRED).
RESOLUTION_CONFIDENCE: dict[Resolution, float] = {
    Resolution.EXACT: 0.9,
    Resolution.NAME_MATCH: 0.5,
    Resolution.DYNAMIC_UNKNOWN: 0.1,
}
