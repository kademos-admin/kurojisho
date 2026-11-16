"""gosec: Go SAST. Runs once per Go module, offline.

gosec type-checks the code, so third-party imports must already be resolvable (a
``vendor/`` directory). When they are not, the run fails and becomes a CoverageGap; module
downloads are never attempted.
"""

from __future__ import annotations

import re

from kurojisho.findings import sarif
from kurojisho.findings.model import TOOL_CONFIDENCE, RawFinding, severity_from_word
from kurojisho.tools.runners.base import RepoProfile, RunContext, Runner, Step

MAX_MODULES = 20
_ENV = {
    "GOFLAGS": "-mod=mod",
    "GOPROXY": "off",  # no downloads, even if the sandbox were given a network
    "GOTOOLCHAIN": "local",
    "GOCACHE": "/tmp/gocache",  # noqa: S108 - the container's private tmpfs
    "GOPATH": "/tmp/gopath",  # noqa: S108
}
_CONFIDENCE = re.compile(r"Confidence:\s*(HIGH|MEDIUM|LOW)")
_SEVERITY = re.compile(r"Severity:\s*(HIGH|MEDIUM|LOW)")


def go_modules(profile: RepoProfile) -> list[str]:
    return profile.dirs_with("go.mod")[:MAX_MODULES]


class GosecRunner(Runner):
    name = "gosec"
    category = "sast"

    def applicable(self, profile: RepoProfile) -> bool:
        return "go" in profile.languages and bool(go_modules(profile))

    def steps(self, ctx: RunContext) -> list[Step]:
        steps = []
        for index, module in enumerate(go_modules(ctx.profile)):
            report = f"gosec-{index}.sarif"
            spec = ctx.spec(
                "-fmt", "sarif", "-out", f"/out/{report}", "-no-fail",
                "-nosec",  # report issues even where the target says "#nosec"
                "./...",
                entrypoint="gosec",
                workdir=f"/src/{module}" if module else "/src",
                env=_ENV,
            )  # fmt: skip
            steps.append(Step(f"module:{module}", spec, report))
        return steps

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for step, raw in sorted(outputs.items()):
            module = step.split(":", 1)[1]
            doc = sarif.load(raw)
            help_text = {
                rule.get("id"): str((rule.get("help") or {}).get("text") or "")
                for run in doc["runs"]
                for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
            }
            for finding in sarif.parse(raw, tool=self.name, version=ctx.pin.version, prefixes=()):
                if finding.path is not None and module:
                    finding.path = f"{module}/{finding.path}"
                text = help_text.get(finding.rule_id, "")
                rated = _SEVERITY.search(text)
                if rated:  # gosec's own rating; its SARIF level is "error" for most rules
                    finding.severity = severity_from_word(rated.group(1))
                    finding.severity_native = rated.group(1)
                sure = _CONFIDENCE.search(text)
                if sure:
                    finding.confidence = TOOL_CONFIDENCE[sure.group(1).lower()]
                findings.append(finding)
        return findings
