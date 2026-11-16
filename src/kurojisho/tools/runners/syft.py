"""Syft: CycloneDX SBOM of the target directory."""

from __future__ import annotations

from kurojisho.findings.model import RawFinding
from kurojisho.findings.sbom import SbomPackage, parse_cyclonedx
from kurojisho.tools.runners.base import RepoProfile, RunContext, Runner, Step


class SyftRunner(Runner):
    name = "syft"
    category = "sbom"
    target_config = (".syft.yaml", ".syft.yml")

    def applicable(self, profile: RepoProfile) -> bool:
        return bool(profile.files)

    def steps(self, ctx: RunContext) -> list[Step]:
        spec = ctx.spec(
            "scan", "dir:/src", "-o", "cyclonedx-json=/out/sbom.json", "-q",
            env={"SYFT_CHECK_FOR_APP_UPDATE": "false"},
        )  # fmt: skip
        return [Step("sbom", spec, "sbom.json")]

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        return []

    def packages(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[SbomPackage]:
        return parse_cyclonedx(outputs["sbom"])
