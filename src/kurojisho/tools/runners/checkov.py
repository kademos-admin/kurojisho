"""Checkov: infrastructure-as-code misconfigurations. Policies are the ones bundled in the
image; nothing is downloaded."""

from __future__ import annotations

from kurojisho.findings import sarif
from kurojisho.findings.model import RawFinding
from kurojisho.tools.runners.base import RepoProfile, RunContext, Runner, Step

FRAMEWORKS = "terraform,cloudformation,kubernetes,dockerfile,github_actions"


def has_iac(profile: RepoProfile) -> bool:
    names = {f.rsplit("/", 1)[-1].lower() for f in profile.files}
    return profile.has_suffix(".tf", ".tf.json", ".yaml", ".yml", ".dockerfile") or any(
        n == "dockerfile" or n.startswith("dockerfile.") for n in names
    )


class CheckovRunner(Runner):
    name = "checkov"
    category = "iac"
    target_config = (".checkov.yaml", ".checkov.yml")

    def applicable(self, profile: RepoProfile) -> bool:
        return has_iac(profile)

    def steps(self, ctx: RunContext) -> list[Step]:
        spec = ctx.spec(
            "-d", "/src", "-o", "sarif", "--output-file-path", "/out", "--framework", FRAMEWORKS,
            "--skip-download", "--quiet", "--soft-fail",
        )  # fmt: skip
        return [Step("scan", spec, "results_sarif.sarif")]

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        return sarif.parse(outputs["scan"], tool=self.name, version=ctx.pin.version, category="iac")
