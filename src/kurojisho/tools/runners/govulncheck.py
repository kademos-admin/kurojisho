"""govulncheck: Go vulnerabilities with the scanner's own call-graph reachability.

It type-checks the module, so dependencies must already be resolvable offline (a
``vendor/`` directory). When they are not it fails and becomes a CoverageGap; OSV-Scanner
still covers the module list.
"""

from __future__ import annotations

import json
from typing import Any

from kurojisho.findings.model import RawFinding, ToolOutputError
from kurojisho.ingest.deps.base import purl as make_purl
from kurojisho.model import Severity
from kurojisho.tools.runners.base import RepoProfile, RunContext, Runner, Step
from kurojisho.tools.runners.gosec import _ENV, go_modules
from kurojisho.tools.sandbox import Mount


def decode_stream(raw: bytes) -> list[dict[str, Any]]:
    """govulncheck prints concatenated JSON objects, not a JSON array."""
    text = raw.decode("utf-8", "replace")
    decoder = json.JSONDecoder()
    messages, index = [], 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        try:
            message, index = decoder.raw_decode(text, index)
        except ValueError as exc:
            raise ToolOutputError("govulncheck output is not a JSON stream") from exc
        if isinstance(message, dict):
            messages.append(message)
    return messages


class GovulncheckRunner(Runner):
    name = "govulncheck"
    category = "sca"

    def applicable(self, profile: RepoProfile) -> bool:
        return "go" in profile.languages and bool(go_modules(profile))

    def intel_sources(self, profile: RepoProfile) -> list[str]:
        return ["govulndb"]

    def steps(self, ctx: RunContext) -> list[Step]:
        if ctx.tools_dir is None:
            raise RuntimeError("govulncheck binary directory not provided")
        ctx.intel_mount("govulndb")
        ctx.extra_mounts = (*ctx.extra_mounts, Mount(ctx.tools_dir, "/tools"))
        steps = []
        for module in go_modules(ctx.profile):
            spec = ctx.spec(
                "-db", "file:///intel", "-format", "json", "./...",
                entrypoint="/tools/govulncheck",
                workdir=f"/src/{module}" if module else "/src",
                env=_ENV,
                tmp_exec=True,  # the Go toolchain runs helpers from its build cache
            )  # fmt: skip
            steps.append(Step(f"module:{module}", spec, ""))
        return steps

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        findings = []
        for step, raw in sorted(outputs.items()):
            module_dir = step.split(":", 1)[1]
            messages = decode_stream(raw)
            if not any("config" in m for m in messages):
                raise ToolOutputError("govulncheck output has no config message")
            aliases = {
                m["osv"]["id"]: [str(a) for a in m["osv"].get("aliases") or []]
                for m in messages
                if isinstance(m.get("osv"), dict) and m["osv"].get("id")
            }
            # One vulnerability is reported once per depth reached; keep the deepest.
            best: dict[tuple[str, str], tuple[int, dict[str, Any]]] = {}
            for message in messages:
                finding = message.get("finding")
                if not isinstance(finding, dict) or not finding.get("osv"):
                    continue
                trace = [t for t in finding.get("trace") or [] if isinstance(t, dict)]
                if not trace or not trace[0].get("module"):
                    continue
                depth = 2 if trace[0].get("function") else 1 if trace[0].get("package") else 0
                key = (str(finding["osv"]), str(trace[0]["module"]))
                if key not in best or depth > best[key][0]:
                    best[key] = (depth, finding)
            for (osv_id, module), (depth, finding) in sorted(best.items()):
                version = str(finding["trace"][0].get("version") or "")
                fixed = finding.get("fixed_version")
                path = f"{module_dir}/go.mod" if module_dir else "go.mod"
                findings.append(
                    RawFinding(
                        tool=self.name,
                        tool_version=ctx.pin.version,
                        category="sca",
                        rule_id=osv_id,
                        message=f"{module} {version} is affected by {osv_id}",
                        severity=Severity.UNKNOWN,  # the Go database carries no severity
                        confidence=0.9,
                        path=path,
                        purl=make_purl("golang", module, version or None),
                        advisory_ids=(osv_id, *aliases.get(osv_id, [])),
                        fixed_versions=(str(fixed),) if fixed else (),
                        tool_reachability=("module", "package", "symbol")[depth],
                        symbol=_symbol(finding["trace"][0]) if depth == 2 else "",
                        callers=_callers(finding["trace"], module_dir) if depth == 2 else (),
                    )
                )
        return findings


def _symbol(frame: dict[str, Any]) -> str:
    receiver = str(frame.get("receiver") or "").lstrip("*")
    name = f"{receiver}.{frame['function']}" if receiver else str(frame["function"])
    return f"{frame.get('package') or frame.get('module')}.{name}"


def _callers(trace: list[dict[str, Any]], module_dir: str) -> tuple[str, ...]:
    """``file:line`` of the frames in the scanned module (they carry no version)."""
    out = []
    for frame in trace[1:]:
        position = frame.get("position")
        if frame.get("version") or not isinstance(position, dict):
            continue
        filename, line = str(position.get("filename") or ""), position.get("line")
        if filename and isinstance(line, int) and not filename.startswith(("/", "..")):
            out.append(f"{module_dir}/{filename}:{line}" if module_dir else f"{filename}:{line}")
    return tuple(sorted(set(out)))
