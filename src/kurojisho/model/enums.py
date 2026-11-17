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
    # TODO(M4+): AI, standards, threat and maturity node types.
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
    ENTRY_POINT = "EntryPoint"
    SOURCE = "Source"
    SINK = "Sink"
    SANITIZER = "Sanitizer"
    CONTROL = "Control"
    VULNERABLE_SYMBOL = "VulnerableSymbol"
    CONTAINER = "Container"
    WORKLOAD = "Workload"
    SERVICE = "Service"
    INGRESS = "Ingress"
    NETWORK_POLICY = "NetworkPolicy"
    PIPELINE = "Pipeline"
    REMEDIATION = "Remediation"
    # Not in the schema table: section 3.4 says a disagreement between the context file
    # and the IaC "raises a ContextConflict".
    CONTEXT_CONFLICT = "ContextConflict"


class EdgeType(StrEnum):
    # TODO(M4+): READS/WRITES, SENDS_TO, CROSSES, AI and standards edges.
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
    HANDLES = "HANDLES"
    GUARDED_BY = "GUARDED_BY"
    FLOWS_TO = "FLOWS_TO"
    USES_SYMBOL = "USES_SYMBOL"
    DEPLOYED_AS = "DEPLOYED_AS"
    EXPOSED_VIA = "EXPOSED_VIA"
    FIXED_BY = "FIXED_BY"


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


class Reach(StrEnum):
    """Reachability state (spec 7.1). ``R0`` is "unknown", not "lowest"."""

    R0 = "R0_UNKNOWN"
    R1 = "R1_NOT_LOADED"
    R2 = "R2_IMPORTED_NOT_CALLED"
    R3 = "R3_INTERNAL_REACHABLE"
    R4 = "R4_ENTRY_REACHABLE"

    @property
    def short(self) -> str:
        return self.value[:2]


class Exposure(StrEnum):
    INTERNET = "internet"
    PARTNER = "partner"
    INTERNAL = "internal"
    NONE = "none"

    @property
    def rank(self) -> int:
        return {"internet": 3, "partner": 2, "internal": 1, "none": 0}[self.value]


#: Severity one level down, for the single step that authentication may take off.
SEVERITY_ORDER = ("Info", "Low", "Medium", "High", "Critical")


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
