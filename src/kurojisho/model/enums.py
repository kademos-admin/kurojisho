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
    # TODO(M3+): security, deployment, AI, standards and remediation node types.
    REPO = "Repo"
    MODULE = "Module"
    FILE = "File"
    CLASS = "Class"
    FUNCTION = "Function"
    ROUTE = "Route"
    PACKAGE = "Package"
    ASSET = "Asset"
    FINDING = "Finding"
    SECRET = "Secret"  # noqa: S105 - a node type name, not a credential
    ADVISORY = "Advisory"
    # Not in the schema table: required by "tool failures become CoverageGap records".
    COVERAGE_GAP = "CoverageGap"


class EdgeType(StrEnum):
    # TODO(M3+): remaining edge types from the schema.
    CONTAINS = "CONTAINS"
    DEFINES = "DEFINES"
    IMPORTS = "IMPORTS"
    INHERITS = "INHERITS"
    CALLS = "CALLS"
    DEPENDS_ON = "DEPENDS_ON"
    BELONGS_TO = "BELONGS_TO"
    LOCATED_IN = "LOCATED_IN"
    DUPLICATE_OF = "DUPLICATE_OF"
    AFFECTED_BY = "AFFECTED_BY"


class Severity(StrEnum):
    """Severity as reported by a tool, normalised. ``UNKNOWN`` is not a low value: it ranks
    with HIGH wherever an order is needed, so a missing rating can never hide a finding."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
    UNKNOWN = "Unknown"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


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

_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.UNKNOWN: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
