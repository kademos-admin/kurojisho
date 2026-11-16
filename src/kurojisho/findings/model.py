"""Tool-neutral finding record produced by every parser."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import unquote

from kurojisho.ingest.deps.base import purl as make_purl
from kurojisho.model import Severity

MAX_MESSAGE = 300
#: Confidence that a tool-reported finding is real, from the tool's own rating.
TOOL_CONFIDENCE = {"high": 0.9, "medium": 0.7, "low": 0.5}
DEFAULT_CONFIDENCE = TOOL_CONFIDENCE["medium"]
_CWE = re.compile(r"CWE[-_ ]?0*(\d+)", re.IGNORECASE)
_PURL = re.compile(r"^pkg:([a-z0-9.+-]+)/([^@?#]+)(?:@([^?#]+))?")


class ToolOutputError(ValueError):
    """A tool produced output that cannot be trusted. Becomes a CoverageGap."""


@dataclass
class RawFinding:
    tool: str
    tool_version: str
    category: str  # sast | sca | secret | iac
    rule_id: str
    message: str
    severity: Severity
    severity_native: str = ""
    cwe: tuple[str, ...] = ()
    confidence: float = DEFAULT_CONFIDENCE
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    # dependency findings
    purl: str | None = None
    advisory_ids: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()
    cvss: float | None = None
    #: How far the scanner itself traced the vulnerable code: symbol | package | module.
    tool_reachability: str = ""
    # secret findings. ``secret`` is the raw value: memory only, never serialised.
    secret: str | None = field(default=None, repr=False)
    secret_type: str = ""
    entropy: float | None = None
    commit: str | None = None
    #: "true" / "false" only when a verifier actually tested the credential; else "unknown".
    verified_live: str = "unknown"
    #: Other raw forms of the secret (e.g. before decoding) to scrub. Memory only.
    scrub_also: tuple[str, ...] = field(default=(), repr=False)
    imported: bool = False

    def __post_init__(self) -> None:
        self.message = " ".join(self.message.split())[:MAX_MESSAGE]
        self.cwe = tuple(dict.fromkeys(self.cwe))
        self.advisory_ids = tuple(sorted(set(self.advisory_ids)))
        self.fixed_versions = tuple(sorted(set(self.fixed_versions)))
        if self.start_line is not None and (
            self.end_line is None or self.end_line < self.start_line
        ):
            self.end_line = self.start_line

    def to_json(self) -> dict[str, Any]:
        if self.secret is not None:
            raise ValueError("secret findings are never serialised")
        data = asdict(self)
        data.pop("secret")
        data.pop("scrub_also")
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> RawFinding:
        fields = dict(data)
        fields["severity"] = Severity(fields["severity"])
        for key in ("cwe", "advisory_ids", "fixed_versions"):
            fields[key] = tuple(fields[key])
        return cls(**fields)


def dumps(findings: list[RawFinding]) -> str:
    return json.dumps([f.to_json() for f in findings], sort_keys=True, separators=(",", ":"))


def loads(text: str) -> list[RawFinding]:
    return [RawFinding.from_json(item) for item in json.loads(text)]


def extract_cwes(*texts: str) -> tuple[str, ...]:
    """``CWE-89`` identifiers found in free text or tags, in order of appearance."""
    found = [f"CWE-{m}" for text in texts for m in _CWE.findall(text)]
    return tuple(dict.fromkeys(found))


def severity_from_cvss(score: float | None) -> Severity:
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW if score > 0 else Severity.INFO


_WORDS = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "note": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "negligible": Severity.INFO,
    "none": Severity.INFO,
}


def severity_from_word(word: str | None) -> Severity:
    """Map a tool's severity word. Anything unrecognised is UNKNOWN, never a low value."""
    return _WORDS.get((word or "").strip().lower(), Severity.UNKNOWN)


def normalise_purl(raw: str | None) -> str | None:
    """Reduce a purl to the form the dependency graph uses: no qualifiers, canonical name."""
    match = _PURL.match(raw or "")
    if match is None:
        return None
    ecosystem, name, version = match.group(1), unquote(match.group(2)), match.group(3)
    if ecosystem == "maven":
        name = name.replace("/", ":")
    return make_purl(ecosystem, name, unquote(version) if version else None)
