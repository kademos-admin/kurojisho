"""Bandit: Python SAST."""

from __future__ import annotations

import json

from kurojisho.findings.model import (
    DEFAULT_CONFIDENCE,
    TOOL_CONFIDENCE,
    RawFinding,
    ToolOutputError,
    severity_from_word,
)
from kurojisho.findings.sarif import relative_path
from kurojisho.tools.runners.base import RepoProfile, RunContext, Runner, Step


class BanditRunner(Runner):
    name = "bandit"
    category = "sast"
    target_config = (".bandit",)

    def applicable(self, profile: RepoProfile) -> bool:
        return "python" in profile.languages

    def steps(self, ctx: RunContext) -> list[Step]:
        spec = ctx.spec(
            "-r", "/src", "-f", "json", "-o", "/out/bandit.json", "-q",
            "--ignore-nosec",  # inline suppressions are the target's opinion, not evidence
            "--exit-zero",
        )  # fmt: skip
        return [Step("scan", spec, "bandit.json")]

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        try:
            doc = json.loads(outputs["scan"])
        except (ValueError, RecursionError) as exc:
            raise ToolOutputError("bandit output is not valid JSON") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
            raise ToolOutputError("bandit output has no results array")
        findings = []
        for item in doc["results"]:
            if not isinstance(item, dict) or not item.get("test_id"):
                raise ToolOutputError("bandit result lacks test_id")
            cwe = (item.get("issue_cwe") or {}).get("id")
            lines = [n for n in item.get("line_range") or [] if isinstance(n, int)]
            start = item.get("line_number") if isinstance(item.get("line_number"), int) else None
            findings.append(
                RawFinding(
                    tool=self.name,
                    tool_version=ctx.pin.version,
                    category="sast",
                    rule_id=str(item["test_id"]),
                    message=str(item.get("issue_text") or item["test_id"]),
                    severity=severity_from_word(item.get("issue_severity")),
                    severity_native=str(item.get("issue_severity") or ""),
                    cwe=(f"CWE-{cwe}",) if isinstance(cwe, int) else (),
                    confidence=TOOL_CONFIDENCE.get(
                        str(item.get("issue_confidence") or "").lower(), DEFAULT_CONFIDENCE
                    ),
                    path=relative_path(str(item.get("filename") or "")),
                    start_line=start,
                    end_line=max(lines) if lines else None,
                )
            )
        return findings
