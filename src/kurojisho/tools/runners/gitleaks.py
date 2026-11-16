"""Gitleaks: secrets in the working tree and, for git checkouts, in history."""

from __future__ import annotations

import json
from typing import Any

from kurojisho.findings.model import RawFinding, ToolOutputError
from kurojisho.findings.sarif import relative_path
from kurojisho.model import Severity
from kurojisho.tools.runners.base import RepoProfile, RunContext, Runner, Step

_COMMON = ("--report-format", "json", "--no-banner", "--no-color", "--exit-code", "0",
           "--log-level", "error", "--gitleaks-ignore-path", "/out/no-ignore-file")  # fmt: skip


class GitleaksRunner(Runner):
    name = "gitleaks"
    category = "secret"
    sensitive = True
    target_config = (".gitleaks.toml", ".gitleaksignore")

    def applicable(self, profile: RepoProfile) -> bool:
        return bool(profile.files)

    def steps(self, ctx: RunContext) -> list[Step]:
        steps = [
            Step(
                "dir",
                ctx.spec("dir", "/src", "--report-path", "/out/dir.json", *_COMMON),
                "dir.json",
            )
        ]
        if ctx.profile.has_git:
            steps.append(
                Step(
                    "git",
                    ctx.spec("git", "/src", "--report-path", "/out/git.json", *_COMMON),
                    "git.json",
                )
            )
        return steps

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        findings: list[RawFinding] = []
        in_tree: set[tuple[str, str | None, str]] = set()
        for step in ("dir", "git"):
            if step not in outputs:
                continue
            try:
                items = json.loads(outputs[step])
            except (ValueError, RecursionError) as exc:
                raise ToolOutputError("gitleaks output is not valid JSON") from exc
            if not isinstance(items, list):
                raise ToolOutputError("gitleaks output is not a JSON array")
            for item in items:
                finding = self._finding(ctx, item)
                identity = (finding.rule_id, finding.path, finding.secret or "")
                if step == "dir":
                    in_tree.add(identity)
                elif identity in in_tree:
                    continue  # the same secret at HEAD is already reported from the tree
                findings.append(finding)
        return findings

    def _finding(self, ctx: RunContext, item: Any) -> RawFinding:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("Secret"), str)
            or not item.get("RuleID")
        ):
            raise ToolOutputError("gitleaks finding lacks RuleID or Secret")
        entropy = item.get("Entropy")
        start = item.get("StartLine")
        return RawFinding(
            tool=self.name,
            tool_version=ctx.pin.version,
            category="secret",
            rule_id=str(item["RuleID"]),
            # The rule's description is generic text; Match/Line/Secret are never copied.
            message=str(item.get("Description") or item["RuleID"]),
            severity=Severity.UNKNOWN,  # gitleaks does not rate; triage decides (SEC-01/02)
            path=relative_path(str(item.get("File") or ""), ("/src/",)),
            start_line=start if isinstance(start, int) and start > 0 else None,
            end_line=item.get("EndLine") if isinstance(item.get("EndLine"), int) else None,
            secret=item["Secret"],
            secret_type=str(item["RuleID"]),
            entropy=float(entropy) if isinstance(entropy, int | float) else None,
            commit=str(item["Commit"]) if item.get("Commit") else None,
        )
