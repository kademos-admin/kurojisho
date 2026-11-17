"""Report formats: Markdown, JSON, SARIF 2.1.0, OpenVEX 0.2.0, CycloneDX 1.5 VEX."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from typing import Any

from kurojisho.model import Severity
from kurojisho.report.model import Item, Report

FORMATS = ("md", "json", "sarif", "openvex", "cyclonedx-vex")
SCHEMA = "kurojisho.report/1"
_SARIF_LEVEL = {"Critical": "error", "High": "error", "Unknown": "error", "Medium": "warning"}
_CDX_STATE = {
    "affected": "exploitable",
    "not_affected": "not_affected",
    "under_investigation": "in_triage",
}
_CDX_JUSTIFICATION = {
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "component_not_present": "code_not_present",
}
_NAMESPACE = uuid.UUID("6f1d7f0e-8a57-5d0b-9c3e-2f6c1b7a4e11")


def _dump(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _factor(factor: dict[str, Any] | None) -> str:
    if not factor:
        return "n/a"
    mark = " (assumed)" if factor.get("assumed") else ""
    return f"{factor['value']}{mark}: {factor['reason']}"


def _cell(text: object) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def _finding_json(item: Item) -> dict[str, Any]:
    p = item.props
    keep = (
        "tool", "rule_id", "category", "message", "cwe", "path", "span", "purl", "advisory_ids",
        "raw_severity", "group_severity", "final_severity", "triage_state", "triage_rule",
        "reasons", "guards", "flags", "reach", "exploit", "impact", "entry_points", "asset",
        "exposure", "vex", "fingerprint", "reported_by", "secret_type", "verified_live",
    )  # fmt: skip
    out = {name: p.get(name) for name in keep if name in p}
    out["key"] = item.key
    out["duplicates"] = item.duplicates
    out["remediation"] = item.fix
    out["evidence"] = item.evidence
    return out


def to_json(report: Report, minimum: Severity | None = None) -> str:
    return _dump(
        {
            "schema": SCHEMA,
            "repo": report.repo,
            "generated_at": report.generated_at,
            "commit": report.commit,
            "tool": {"name": "kurojisho", "version": report.version},
            "summary": report.counts(),
            "findings": [_finding_json(i) for i in report.at_least(minimum)],
            "coverage_gaps": report.gaps,
            "context_conflicts": report.conflicts,
        }
    )


def to_markdown(report: Report, minimum: Severity | None = Severity.MEDIUM) -> str:
    counts = report.counts()
    shown = report.at_least(minimum)
    lines = [
        f"# Security findings: {report.repo}",
        "",
        f"Scan of {report.generated_at}"
        + (f", commit `{report.commit[:12]}`" if report.commit else "")
        + f", kurojisho {report.version}.",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    for severity in ("Critical", "High", "Unknown", "Medium", "Low", "Info"):
        if counts[severity] or severity in ("Critical", "High", "Medium"):
            lines.append(f"| {severity} | {counts[severity]} |")
    hidden = len(report.findings) - len(shown)
    lines.append("")
    if hidden:
        lines += [f"{hidden} lower-severity finding(s) are not listed below.", ""]
    if counts["Unknown"]:
        lines += [
            "Findings with severity **Unknown** matched no triage rule and came with no tool "
            "rating. They are listed with High: unknown is not safe.",
            "",
        ]
    lines += ["## What was not checked", ""]
    if report.gaps:
        lines += ["| Area | Reason | Detail |", "|---|---|---|"]
        for gap in report.gaps:
            detail = gap.get("detail") or ""
            files = gap.get("files") or []
            if files:
                detail = f"{detail} ({', '.join(files[:5])}{'…' if len(files) > 5 else ''})"
            lines.append(
                f"| {_cell(gap.get('tool'))} | {_cell(gap.get('reason'))} | {_cell(detail)} |"
            )
    else:
        lines.append("No coverage gaps were recorded for this scan.")
    lines.append("")
    if report.conflicts:
        lines += ["## Context conflicts", ""]
        for conflict in report.conflicts:
            lines.append(
                f"- Asset `{conflict['asset']}`: the context file says {conflict['field']} is "
                f"**{conflict['asserted']}**, the deployment files show **{conflict['observed']}** "
                f"({conflict.get('observed_reason')}). Triage used **{conflict['effective']}**."
            )
        lines.append("")
    lines += ["## Findings", ""]
    if not shown:
        lines += ["None at or above the listed severity.", ""]
    for item in shown:
        p = item.props
        cwe = ", ".join(p.get("cwe") or []) or "-"
        tools = ", ".join(p.get("reported_by") or [p["tool"]])
        lines += [
            f"### [{p['final_severity']}] {p['rule_id']}",
            "",
            f"`{item.location}`: {_cell(p.get('message') or '')}",
            "",
            "| | |",
            "|---|---|",
            f"| Reported by | {_cell(tools)} (tool severity {p['group_severity']}) |",
            f"| Weakness | {_cell(cwe)} |",
            f"| Decided by | {p.get('triage_rule') or 'no rule matched'} |",
        ]
        if p.get("reach"):
            lines += [
                f"| Reachability | {_cell(_factor(p['reach']))} |",
                f"| Exploitability | {_cell(_factor(p['exploit']))} |",
                f"| Business impact | {_cell(_factor(p['impact']))} |",
            ]
        if p.get("entry_points"):
            lines.append(f"| Entry points | {_cell(', '.join(p['entry_points']))} |")
        if p.get("flags"):
            lines.append(f"| Flags | {_cell(', '.join(p['flags']))} |")
        lines += ["", "Why:"]
        lines += [f"- {reason}" for reason in p.get("reasons") or []]
        fix = item.fix
        if fix:
            lines += ["", f"Fix: **{fix['title']}**. {fix['guidance']}"]
            if fix.get("fixed_version"):
                lines.append(f"Breaking risk of the upgrade: {fix['breaking_risk']}.")
            lines += ["", "Verify:"]
            lines += [f"- {step}" for step in fix.get("verify_steps") or []]
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def to_sarif(report: Report, minimum: Severity | None = None) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for item in report.at_least(minimum):
        p = item.props
        rule_id = f"{p['tool']}/{p['rule_id']}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": str(p["rule_id"])},
                "properties": {"category": p["category"], "cwe": p.get("cwe") or []},
            },
        )
        why = "; ".join(p.get("reasons") or [])
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(p["final_severity"], "note"),
            "message": {
                "text": f"{p.get('message') or p['rule_id']} [{p['final_severity']}: {why}]"
            },
            "partialFingerprints": {"kurojisho/v1": p["fingerprint"]},
            "properties": {
                "final_severity": p["final_severity"],
                "tool_severity": p["group_severity"],
                "triage_rule": p.get("triage_rule"),
                "triage_state": p.get("triage_state"),
                "reach": (p.get("reach") or {}).get("value"),
                "exploit": (p.get("exploit") or {}).get("value"),
                "impact": (p.get("impact") or {}).get("value"),
                "flags": p.get("flags") or [],
                "entry_points": p.get("entry_points") or [],
            },
        }
        if p.get("path"):
            physical: dict[str, Any] = {"artifactLocation": {"uri": p["path"]}}
            if p.get("span"):
                physical["region"] = {"startLine": p["span"][0], "endLine": p["span"][1]}
            result["locations"] = [{"physicalLocation": physical}]
        if item.fix:
            result["fixes"] = [
                {"description": {"text": f"{item.fix['title']}. {item.fix['guidance']}"}}
            ]
        results.append(result)
    return _dump(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "KuroJisho",
                            "version": report.version,
                            "rules": [rules[k] for k in sorted(rules)],
                        }
                    },
                    "results": results,
                }
            ],
        }
    )


def _vulnerability(props: dict[str, Any]) -> str:
    ids = sorted(str(i) for i in props.get("advisory_ids") or [props["rule_id"]])
    return next((i for i in ids if i.startswith("CVE-")), ids[0])


def _dependencies(report: Report) -> list[Item]:
    return [i for i in report.findings if i.props["category"] == "sca" and i.props.get("vex")]


def to_openvex(report: Report, minimum: Severity | None = None) -> str:
    """Every dependency finding gets a statement, whatever its severity: leaving the
    "not affected" ones out would defeat the purpose of a VEX document."""
    del minimum
    statements = []
    for item in _dependencies(report):
        p = item.props
        vex = p["vex"]
        statement: dict[str, Any] = {
            "vulnerability": {"name": _vulnerability(p)},
            "products": [{"@id": p["purl"]}],
            "status": vex["status"],
        }
        if vex["status"] == "not_affected":
            statement["justification"] = vex["justification"]
            statement["impact_statement"] = p["reach"]["reason"]
        elif vex["status"] == "affected":
            fix = item.fix or {}
            statement["action_statement"] = fix.get("title") or "No fix is available yet"
        statements.append(statement)
    statements.sort(key=lambda s: (s["vulnerability"]["name"], s["products"][0]["@id"]))
    digest = hashlib.sha256(json.dumps(statements, sort_keys=True).encode()).hexdigest()
    return _dump(
        {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": f"urn:kurojisho:vex:{digest[:32]}",
            "author": "KuroJisho",
            "tooling": f"kurojisho {report.version}",
            "timestamp": report.generated_at,
            "version": 1,
            "statements": statements,
        }
    )


def to_cyclonedx_vex(report: Report, minimum: Severity | None = None) -> str:
    del minimum
    vulnerabilities: list[dict[str, Any]] = []
    for item in _dependencies(report):
        p = item.props
        vex = p["vex"]
        analysis: dict[str, Any] = {
            "state": _CDX_STATE[vex["status"]],
            "detail": "; ".join(p.get("reasons") or []),
        }
        if vex["status"] == "not_affected":
            analysis["justification"] = _CDX_JUSTIFICATION[vex["justification"]]
        vulnerabilities.append(
            {
                "id": _vulnerability(p),
                "ratings": [{"severity": p["final_severity"].lower(), "method": "other"}],
                "affects": [{"ref": p["purl"]}],
                "analysis": analysis,
            }
        )
    vulnerabilities.sort(key=lambda v: (v["id"], v["affects"][0]["ref"]))
    digest = hashlib.sha256(json.dumps(vulnerabilities, sort_keys=True).encode()).hexdigest()
    return _dump(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid5(_NAMESPACE, digest)}",
            "version": 1,
            "metadata": {
                "timestamp": report.generated_at,
                "tools": [{"vendor": "KuroJisho", "name": "kurojisho", "version": report.version}],
            },
            "vulnerabilities": vulnerabilities,
        }
    )


RENDERERS: dict[str, Callable[[Report, Severity | None], str]] = {
    "json": to_json,
    "sarif": to_sarif,
    "openvex": to_openvex,
    "cyclonedx-vex": to_cyclonedx_vex,
}


def render(report: Report, fmt: str, minimum: Severity | None = None) -> str:
    if fmt == "md":
        return to_markdown(report, minimum or Severity.MEDIUM)
    return RENDERERS[fmt](report, minimum)
