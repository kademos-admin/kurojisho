"""TruffleHog: secrets, with optional live verification.

Verification is the one place a scanner may touch the network, and only when the user
passes ``--verify-secrets``. Without it every result stays ``verified_live = unknown``.
"""

from __future__ import annotations

import json
from typing import Any

from kurojisho.findings.model import RawFinding, ToolOutputError
from kurojisho.findings.sarif import relative_path
from kurojisho.model import Severity
from kurojisho.tools.runners.base import RepoProfile, RunContext, Runner, Step


class TrufflehogRunner(Runner):
    name = "trufflehog"
    category = "secret"
    sensitive = True

    def applicable(self, profile: RepoProfile) -> bool:
        return bool(profile.files)

    def steps(self, ctx: RunContext) -> list[Step]:
        verify = ctx.options.verify_secrets
        flags = ["--json", "--no-update", *([] if verify else ["--no-verification"])]
        common = {"entrypoint": "trufflehog", "network": verify}
        steps = [Step("fs", ctx.spec("filesystem", "/src", *flags, **common), "")]
        if ctx.profile.has_git:
            steps.append(Step("git", ctx.spec("git", "file:///src", *flags, **common), ""))
        return steps

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        findings: list[RawFinding] = []
        in_tree: set[tuple[str, str | None, str]] = set()
        for step in ("fs", "git"):
            for line in outputs.get(step, b"").splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except (ValueError, RecursionError) as exc:
                    raise ToolOutputError("trufflehog emitted a line that is not JSON") from exc
                finding = self._finding(ctx, item, step)
                if finding is None:
                    continue
                identity = (finding.rule_id, finding.path, finding.secret or "")
                if step == "fs":
                    in_tree.add(identity)
                elif identity in in_tree:
                    continue
                findings.append(finding)
        return findings

    def _finding(self, ctx: RunContext, item: Any, step: str) -> RawFinding | None:
        if not isinstance(item, dict) or "DetectorName" not in item:
            return None  # a log line, not a result
        raw = item.get("Raw")
        if not isinstance(raw, str) or not raw:
            raise ToolOutputError("trufflehog result lacks Raw")
        data = ((item.get("SourceMetadata") or {}).get("Data") or {}).get(
            "Git" if step == "git" else "Filesystem"
        ) or {}
        path = relative_path(str(data.get("file") or ""))
        if step == "fs" and path is not None and (path == ".git" or path.startswith(".git/")):
            return None  # packed history: the git step reports it with its commit
        line = data.get("line")
        if not ctx.options.verify_secrets or item.get("VerificationError"):
            verified = "unknown"
        else:
            verified = "true" if item.get("Verified") is True else "false"
        extra = item.get("RawV2")
        return RawFinding(
            tool=self.name,
            tool_version=ctx.pin.version,
            category="secret",
            rule_id=str(item["DetectorName"]),
            message=str(item.get("DetectorDescription") or item["DetectorName"]),
            severity=Severity.UNKNOWN,
            path=path,
            start_line=line if isinstance(line, int) and line > 0 else None,
            secret=raw,
            secret_type=str(item["DetectorName"]),
            commit=str(data["commit"]) if data.get("commit") else None,
            verified_live=verified,
            scrub_also=(extra,) if isinstance(extra, str) and extra else (),
        )
