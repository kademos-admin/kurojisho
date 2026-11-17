"""What a report says, read from the stored graph. Reports are a pure function of the
database: the timestamp is the scan's, not the moment the report is printed."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from kurojisho.model import Severity
from kurojisho.store import Store

_ORDER = {"sast": 0, "sca": 1, "secret": 2, "iac": 3}


@dataclass
class Item:
    key: str
    props: dict[str, Any]
    evidence: list[dict[str, Any]]
    fix: dict[str, Any] | None = None
    duplicates: int = 0

    @property
    def severity(self) -> Severity:
        return Severity(self.props["final_severity"])

    @property
    def line(self) -> int | None:
        span = self.props.get("span")
        return int(span[0]) if span else None

    @property
    def location(self) -> str:
        path = self.props.get("path") or self.props.get("purl") or "-"
        return f"{path}:{self.line}" if self.line and self.props.get("path") else str(path)


@dataclass
class Report:
    repo: str
    generated_at: str
    commit: str | None
    version: str
    findings: list[Item] = field(default_factory=list)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)

    def at_least(self, minimum: Severity | None) -> list[Item]:
        """Findings at or above a severity. Unknown ranks with High: it is never hidden."""
        if minimum is None:
            return self.findings
        return [f for f in self.findings if f.severity.rank >= minimum.rank]

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for item in self.findings:
            out[item.severity.value] += 1
        return out


def _props(store: Store, kind: str) -> list[tuple[str, str, dict[str, Any], list[dict[str, Any]]]]:
    rows = store.conn.execute(
        "SELECT id, key, props, evidence FROM nodes WHERE type = ? AND retired = 0 ORDER BY key",
        (kind,),
    )
    return [(r["id"], r["key"], json.loads(r["props"]), json.loads(r["evidence"])) for r in rows]


def load_report(store: Store) -> Report:
    scan = store.conn.execute(
        "SELECT commit_sha, started_at, tool_version FROM scans ORDER BY id DESC LIMIT 1"
    ).fetchone()
    repo = store.conn.execute(
        "SELECT name FROM nodes WHERE type = 'Repo' AND retired = 0"
    ).fetchone()
    report = Report(
        repo=repo["name"] if repo else "",
        generated_at=scan["started_at"] if scan else "",
        commit=scan["commit_sha"] if scan else None,
        version=scan["tool_version"] if scan else "",
    )
    fixes = {
        r["src"]: json.loads(r["props"])
        for r in store.conn.execute(
            "SELECT e.src, n.props FROM edges e JOIN nodes n ON n.id = e.dst "
            "WHERE e.type = 'FIXED_BY' AND e.retired = 0 AND n.retired = 0 ORDER BY e.id"
        )
    }
    duplicates = dict(
        store.conn.execute(
            "SELECT dst, COUNT(*) FROM edges "
            "WHERE type = 'DUPLICATE_OF' AND retired = 0 GROUP BY dst"
        ).fetchall()
    )
    for node_id, key, props, evidence in _props(store, "Finding"):
        if props.get("final_severity") is None or props.get("triage_state") == "duplicate":
            continue
        report.findings.append(
            Item(key, props, evidence, fixes.get(node_id), duplicates.get(node_id, 0))
        )
    report.findings.sort(
        key=lambda i: (
            -i.severity.rank,
            i.severity is Severity.UNKNOWN,
            _ORDER.get(i.props["category"], 9),
            i.props.get("path") or i.props.get("purl") or "",
            i.line or 0,
            i.key,
        )
    )
    report.gaps = [{"key": key, **props} for _, key, props, _ in _props(store, "CoverageGap")]
    report.conflicts = [props for _, _, props, _ in _props(store, "ContextConflict")]
    return report
