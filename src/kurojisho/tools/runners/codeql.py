"""CodeQL: off by default and behind a licence gate.

The CodeQL CLI is free only for open-source code and academic research; private commercial
code needs GitHub Advanced Security / Code Security. It runs only after the user passes
``--enable codeql`` and has recorded acceptance of those terms.

This build pins no CodeQL bundle, so even when enabled the run is reported as a coverage
gap. The command lines below follow the CodeQL CLI manual and are covered by tests, but
have not been exercised against a real CodeQL here.
"""

from __future__ import annotations

from kurojisho.findings import sarif
from kurojisho.findings.model import RawFinding
from kurojisho.tools.runners.base import RepoProfile, RunContext, Runner, Step
from kurojisho.tools.sandbox import Mount

#: Languages CodeQL can extract without building (``--build-mode=none``). Go is absent on
#: purpose: it would require a build, and target code is never built.
LANGUAGES = {"python": "python", "javascript": "javascript", "typescript": "javascript",
             "tsx": "javascript", "java": "java"}  # fmt: skip
TERMS = (
    "The CodeQL CLI may be used free of charge only on open-source codebases and for "
    "academic research. Analysing private or commercial code requires a GitHub Advanced "
    "Security / GitHub Code Security licence. See "
    "https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md"
)


class CodeqlRunner(Runner):
    name = "codeql"
    category = "sast"
    opt_in = True
    licence_terms = TERMS

    def applicable(self, profile: RepoProfile) -> bool:
        return bool(profile.languages & set(LANGUAGES))

    def steps(self, ctx: RunContext) -> list[Step]:
        if ctx.tools_dir is None:
            raise RuntimeError("CodeQL bundle directory not provided")
        ctx.extra_mounts = (*ctx.extra_mounts, Mount(ctx.tools_dir, "/tools"))
        steps = []
        for language in sorted({LANGUAGES[x] for x in ctx.profile.languages if x in LANGUAGES}):
            database = f"/out/db-{language}"
            common = {"entrypoint": "/tools/codeql/codeql", "tmp_exec": True, "memory_mb": 8192}
            steps.append(
                Step(
                    f"create:{language}",
                    ctx.spec(
                        "database",
                        "create",
                        database,
                        f"--language={language}",
                        "--source-root=/src",
                        "--build-mode=none",
                        "--overwrite",
                        **common,
                    ),
                    "",
                )
            )
            suite = f"codeql/{language}-queries:codeql-suites/{language}-security-extended.qls"
            steps.append(
                Step(
                    f"analyze:{language}",
                    ctx.spec(
                        "database",
                        "analyze",
                        database,
                        suite,
                        "--format=sarif-latest",
                        f"--output=/out/{language}.sarif",
                        **common,
                    ),
                    f"{language}.sarif",
                )
            )
        return steps

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for step, raw in sorted(outputs.items()):
            if step.startswith("analyze:"):
                findings += sarif.parse(raw, tool=self.name, version=ctx.pin.version)
        return findings
