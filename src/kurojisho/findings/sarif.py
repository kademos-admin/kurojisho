"""SARIF 2.1.0 reader shared by every SARIF-emitting scanner and by ``import-sarif``."""

from __future__ import annotations

import json
import posixpath
from typing import Any
from urllib.parse import unquote, urlparse

from kurojisho.findings.model import (
    DEFAULT_CONFIDENCE,
    TOOL_CONFIDENCE,
    RawFinding,
    ToolOutputError,
    extract_cwes,
    severity_from_cvss,
    severity_from_word,
)
from kurojisho.model import Severity

_LEVELS = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW}


def load(text: str | bytes) -> dict[str, Any]:
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ToolOutputError("output is not valid JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise ToolOutputError("output is not a SARIF log (no runs array)")
    return doc


def relative_path(uri: str, prefixes: tuple[str, ...] = ("/src/",)) -> str | None:
    """Repo-relative POSIX path for an artifact URI, or None if it points outside the repo."""
    parsed = urlparse(uri)
    path = unquote(parsed.path if parsed.scheme in ("file", "") else uri)
    for prefix in prefixes:
        if path.startswith(prefix):
            path = path[len(prefix) :]
            break
    path = posixpath.normpath(path.lstrip("/")) if path else ""
    if not path or path == "." or path.startswith(".."):
        return None
    return path


def _severity(result: dict[str, Any], rule: dict[str, Any]) -> tuple[Severity, str]:
    props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
    score = props.get("security-severity")
    try:
        if score is not None:
            return severity_from_cvss(float(score)), f"security-severity:{score}"
    except (TypeError, ValueError):
        pass
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    if isinstance(level, str) and level in _LEVELS:
        return _LEVELS[level], level
    word = props.get("severity") or props.get("problem.severity")
    return severity_from_word(word if isinstance(word, str) else None), str(level or word or "")


def parse(
    text: str | bytes,
    *,
    tool: str,
    version: str,
    category: str = "sast",
    prefixes: tuple[str, ...] = ("/src/",),
    imported: bool = False,
) -> list[RawFinding]:
    findings = []
    for run in load(text)["runs"]:
        driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run, dict) else {}
        rules = {r.get("id"): r for r in driver.get("rules") or [] if isinstance(r, dict)}
        for result in run.get("results") or []:
            if not isinstance(result, dict) or result.get("kind") in ("pass", "notApplicable"):
                continue
            rule_id = str(result.get("ruleId") or (result.get("rule") or {}).get("id") or "")
            if not rule_id:
                raise ToolOutputError("SARIF result without a ruleId")
            rule = rules.get(rule_id) or {}
            props = rule.get("properties") or {}
            tags = [t for t in props.get("tags") or [] if isinstance(t, str)]
            cwe_field = props.get("cwe")
            cwe_texts = cwe_field if isinstance(cwe_field, list) else [cwe_field or ""]
            for relation in rule.get("relationships") or []:  # gosec links rules to CWE this way
                target = (relation or {}).get("target") or {}
                if (target.get("toolComponent") or {}).get("name") == "CWE" and target.get("id"):
                    cwe_texts = [*cwe_texts, f"CWE-{target['id']}"]
            severity, native = _severity(result, rule)
            rating = str(props.get("confidence") or "").lower()
            for tag in tags:  # Semgrep writes "HIGH CONFIDENCE" as a tag
                if tag.upper().endswith(" CONFIDENCE"):
                    rating = tag.split()[0].lower()
            confidence = TOOL_CONFIDENCE.get(rating, DEFAULT_CONFIDENCE)
            path, start, end = None, None, None
            for location in result.get("locations") or []:
                physical = (location or {}).get("physicalLocation") or {}
                uri = (physical.get("artifactLocation") or {}).get("uri")
                if isinstance(uri, str):
                    path = relative_path(uri, prefixes)
                    region = physical.get("region") or {}
                    start = (
                        region.get("startLine")
                        if isinstance(region.get("startLine"), int)
                        else None
                    )
                    end = region.get("endLine") if isinstance(region.get("endLine"), int) else None
                    break
            message = (result.get("message") or {}).get("text")
            if not isinstance(message, str) or not message:
                message = (rule.get("shortDescription") or {}).get("text") or rule_id
            findings.append(
                RawFinding(
                    tool=tool,
                    tool_version=version,
                    category=category,
                    rule_id=rule_id,
                    message=str(message),
                    severity=severity,
                    severity_native=native,
                    cwe=extract_cwes(*tags, *(str(c) for c in cwe_texts)),
                    confidence=confidence,
                    path=path,
                    start_line=start if start and start > 0 else None,
                    end_line=end,
                    imported=imported,
                )
            )
    return findings
