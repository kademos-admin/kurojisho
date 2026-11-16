"""Semgrep CE with KuroJisho's own rule pack. Registry rules are never fetched here."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import kurojisho
from kurojisho.findings import sarif
from kurojisho.findings.model import RawFinding, ToolOutputError
from kurojisho.tools.runners.base import CODE_LANGUAGES, RepoProfile, RunContext, Runner, Step
from kurojisho.tools.sandbox import Mount

RULES_DIR = Path(kurojisho.__file__).parent / "rules" / "semgrep"
RULES_MOUNT = "/rules"


class SemgrepRunner(Runner):
    name = "semgrep"
    category = "sast"
    target_config = (".semgrepignore",)

    def applicable(self, profile: RepoProfile) -> bool:
        return bool(profile.languages & CODE_LANGUAGES)

    def steps(self, ctx: RunContext) -> list[Step]:
        ctx.extra_mounts = (Mount(RULES_DIR, RULES_MOUNT),)
        spec = ctx.spec(
            "semgrep",
            "scan",
            "--config",
            RULES_MOUNT,
            "--sarif",
            "--output",
            "/out/semgrep.sarif",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",  # ignored files are still shipped code
            "--disable-nosem",  # inline suppressions are the target's opinion, not evidence
            "--quiet",
            "/src",
            env={"SEMGREP_SEND_METRICS": "off"},
        )
        return [Step("scan", spec, "semgrep.sarif")]

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        doc = sarif.load(outputs["scan"])
        for run in doc["runs"]:
            for invocation in run.get("invocations") or []:
                if invocation.get("executionSuccessful") is False:
                    raise ToolOutputError("semgrep reported an unsuccessful execution")
        findings = sarif.parse(json.dumps(doc), tool=self.name, version=ctx.pin.version)
        prefix = RULES_MOUNT.strip("/") + "."
        for finding in findings:
            finding.rule_id = finding.rule_id.removeprefix(prefix)
        return findings

    def cache_inputs(self) -> str:
        digest = hashlib.sha256()
        for path in sorted(RULES_DIR.glob("*.yaml")):
            digest.update(path.name.encode() + b"\0" + path.read_bytes())
        return digest.hexdigest()
