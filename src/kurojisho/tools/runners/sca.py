"""Dependency scanners: OSV-Scanner, Trivy (fs) and Grype. All run offline against
databases the host process fetched beforehand."""

from __future__ import annotations

import json
from typing import Any

from kurojisho.findings.model import (
    RawFinding,
    ToolOutputError,
    normalise_purl,
    severity_from_cvss,
    severity_from_word,
)
from kurojisho.findings.normalise import canonical_advisory
from kurojisho.findings.sarif import relative_path
from kurojisho.ingest.deps import manifest_kind
from kurojisho.ingest.deps.base import purl as make_purl
from kurojisho.intel.refresh import OSV_ECOSYSTEMS, OSV_EXTRA, osv_source
from kurojisho.model import Severity
from kurojisho.tools.runners.base import RepoProfile, RunContext, Runner, Step

_OSV_ECOSYSTEM = {
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "Maven": "maven",
    "crates.io": "cargo",
    "RubyGems": "gem",
    "Packagist": "composer",
    "NuGet": "nuget",
}


def has_manifests(profile: RepoProfile) -> bool:
    return any(manifest_kind(f) is not None for f in profile.files)


def _json(raw: bytes, tool: str) -> dict[str, Any]:
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise ToolOutputError(f"{tool} output is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise ToolOutputError(f"{tool} output is not a JSON object")
    return doc


def _score(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


class OsvScannerRunner(Runner):
    name = "osv-scanner"
    category = "sca"
    target_config = ("osv-scanner.toml",)

    def applicable(self, profile: RepoProfile) -> bool:
        return has_manifests(profile)

    def intel_sources(self, profile: RepoProfile) -> list[str]:
        extra = [eco for name, eco in OSV_EXTRA.items() if profile.has_name(name)]
        return [osv_source(e) for e in (*OSV_ECOSYSTEMS, *extra)]

    def steps(self, ctx: RunContext) -> list[Step]:
        ctx.intel_mount("osv")
        spec = ctx.spec(
            "scan", "source", "--offline", "--offline-vulnerabilities", "--recursive",
            "--no-ignore", "--format", "json", "--output-file", "/out/osv.json",
            "--verbosity", "error", "/src",
            env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/intel"},
        )  # fmt: skip
        return [Step("scan", spec, "osv.json", frozenset({0, 1}))]  # 1 = vulnerabilities found

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        doc = _json(outputs["scan"], self.name)
        if not isinstance(doc.get("results"), list):
            raise ToolOutputError("osv-scanner output has no results array")
        findings = []
        for result in doc["results"]:
            path = relative_path(str((result.get("source") or {}).get("path") or ""))
            for entry in result.get("packages") or []:
                package = entry.get("package") or {}
                name, version = package.get("name"), package.get("version")
                ecosystem = _OSV_ECOSYSTEM.get(str(package.get("ecosystem")).split(":")[0])
                if not name or not version or ecosystem is None:
                    continue
                if ecosystem == "golang" and not str(version).startswith("v"):
                    version = f"v{version}"
                purl = make_purl(ecosystem, str(name), str(version))
                records = {v.get("id"): v for v in entry.get("vulnerabilities") or []}
                for group in entry.get("groups") or []:
                    ids = {str(i) for i in (*group.get("ids", []), *group.get("aliases", []))}
                    if not ids:
                        continue
                    fixed = set()
                    for member in group.get("ids", []):
                        for affected in (records.get(member) or {}).get("affected") or []:
                            if (affected.get("package") or {}).get("name") != name:
                                continue
                            for span in affected.get("ranges") or []:
                                fixed |= {
                                    e["fixed"] for e in span.get("events") or [] if "fixed" in e
                                }
                    score = _score(group.get("max_severity"))
                    findings.append(
                        RawFinding(
                            tool=self.name,
                            tool_version=ctx.pin.version,
                            category="sca",
                            rule_id=canonical_advisory(ids),
                            message=f"{name} {version} is affected by {canonical_advisory(ids)}",
                            severity=severity_from_cvss(score),
                            severity_native=str(group.get("max_severity") or ""),
                            confidence=0.9,
                            path=path,
                            purl=purl,
                            advisory_ids=tuple(ids),
                            fixed_versions=tuple(str(f) for f in fixed),
                            cvss=score,
                        )
                    )
        return findings


class TrivyRunner(Runner):
    name = "trivy"
    category = "sca"
    target_config = (".trivyignore", "trivy.yaml")

    def applicable(self, profile: RepoProfile) -> bool:
        return has_manifests(profile)

    def intel_sources(self, profile: RepoProfile) -> list[str]:
        return ["trivy-db"]

    def steps(self, ctx: RunContext) -> list[Step]:
        ctx.intel_mount("trivy")
        spec = ctx.spec(
            "fs", "--cache-dir", "/intel", "--cache-backend", "memory", "--skip-db-update",
            "--skip-java-db-update", "--offline-scan", "--skip-version-check", "--scanners", "vuln",
            "--format", "json", "--output", "/out/trivy.json", "--ignorefile", "", "--config", "",
            "--no-progress", "--quiet", "/src",
        )  # fmt: skip
        return [Step("fs", spec, "trivy.json")]

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        doc = _json(outputs["fs"], self.name)
        if "SchemaVersion" not in doc:
            raise ToolOutputError("trivy output has no SchemaVersion")
        findings = []
        for result in doc.get("Results") or []:
            path = relative_path(str(result.get("Target") or ""), ())
            for vuln in result.get("Vulnerabilities") or []:
                purl = normalise_purl((vuln.get("PkgIdentifier") or {}).get("PURL"))
                primary = vuln.get("VulnerabilityID")
                if purl is None or not primary:
                    continue
                scores = [
                    _score(source.get(key))
                    for source in (vuln.get("CVSS") or {}).values()
                    for key in ("V40Score", "V3Score")
                ]
                known = [s for s in scores if s is not None]
                fixed = [
                    v.strip() for v in str(vuln.get("FixedVersion") or "").split(",") if v.strip()
                ]
                findings.append(
                    RawFinding(
                        tool=self.name,
                        tool_version=ctx.pin.version,
                        category="sca",
                        rule_id=str(primary),
                        message=str(vuln.get("Title") or f"{vuln.get('PkgName')} {primary}"),
                        severity=severity_from_word(vuln.get("Severity")),
                        severity_native=str(vuln.get("Severity") or ""),
                        cwe=tuple(c for c in vuln.get("CweIDs") or [] if isinstance(c, str)),
                        confidence=0.9,
                        path=path,
                        purl=purl,
                        advisory_ids=(str(primary), *(str(i) for i in vuln.get("VendorIDs") or [])),
                        fixed_versions=tuple(fixed),
                        cvss=max(known) if known else None,
                    )
                )
        return findings


class TrivyConfigRunner(Runner):
    """Trivy's misconfiguration scanner. Needs no database: checks are built into the image."""

    name = "trivy-config"
    pin_name = "trivy"
    category = "iac"
    target_config = (".trivyignore", "trivy.yaml")

    def applicable(self, profile: RepoProfile) -> bool:
        from kurojisho.tools.runners.checkov import has_iac

        return has_iac(profile)

    def steps(self, ctx: RunContext) -> list[Step]:
        spec = ctx.spec(
            "config", "--cache-dir", "/tmp/trivy", "--skip-check-update", "--skip-version-check",  # noqa: S108
            "--format", "json", "--output", "/out/trivy-config.json", "--ignorefile", "",
            "--config", "", "--quiet", "/src",
        )  # fmt: skip
        return [Step("config", spec, "trivy-config.json")]

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        doc = _json(outputs["config"], self.name)
        if "SchemaVersion" not in doc:
            raise ToolOutputError("trivy output has no SchemaVersion")
        findings = []
        for result in doc.get("Results") or []:
            path = relative_path(str(result.get("Target") or ""), ())
            for item in result.get("Misconfigurations") or []:
                if item.get("Status") != "FAIL" or not item.get("ID"):
                    continue
                cause = item.get("CauseMetadata") or {}
                start = cause.get("StartLine")
                findings.append(
                    RawFinding(
                        tool=self.name,
                        tool_version=ctx.pin.version,
                        category="iac",
                        rule_id=str(item["ID"]),
                        message=str(item.get("Title") or item["ID"]),
                        severity=severity_from_word(item.get("Severity")),
                        severity_native=str(item.get("Severity") or ""),
                        path=path,
                        start_line=start if isinstance(start, int) and start > 0 else None,
                        end_line=cause.get("EndLine")
                        if isinstance(cause.get("EndLine"), int)
                        else None,
                    )
                )
        return findings


class GrypeRunner(Runner):
    name = "grype"
    category = "sca"
    target_config = (".grype.yaml",)

    def applicable(self, profile: RepoProfile) -> bool:
        return has_manifests(profile)

    def intel_sources(self, profile: RepoProfile) -> list[str]:
        return ["grype-db"]

    def steps(self, ctx: RunContext) -> list[Step]:
        ctx.intel_mount("grype/db")
        spec = ctx.spec(
            "dir:/src", "-o", "json", "--file", "/out/grype.json", "-q",
            env={
                "GRYPE_DB_CACHE_DIR": "/intel",
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_DB_VALIDATE_AGE": "false",  # staleness is reported by KuroJisho instead
                "GRYPE_CHECK_FOR_APP_UPDATE": "false",
            },
        )  # fmt: skip
        return [Step("scan", spec, "grype.json")]

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        doc = _json(outputs["scan"], self.name)
        if not isinstance(doc.get("matches"), list):
            raise ToolOutputError("grype output has no matches array")
        findings = []
        for match in doc["matches"]:
            vuln, artifact = match.get("vulnerability") or {}, match.get("artifact") or {}
            purl = normalise_purl(artifact.get("purl"))
            if purl is None or not vuln.get("id"):
                continue
            related = [
                str(r.get("id")) for r in match.get("relatedVulnerabilities") or [] if r.get("id")
            ]
            scores = [
                _score((metric.get("metrics") or {}).get("baseScore"))
                for record in (vuln, *(match.get("relatedVulnerabilities") or []))
                for metric in record.get("cvss") or []
            ]
            known = [s for s in scores if s is not None]
            locations = artifact.get("locations") or [{}]
            word = vuln.get("severity")
            findings.append(
                RawFinding(
                    tool=self.name,
                    tool_version=ctx.pin.version,
                    category="sca",
                    rule_id=str(vuln["id"]),
                    message=f"{artifact.get('name')} {artifact.get('version')}: {vuln['id']}",
                    severity=Severity.UNKNOWN if word == "Unknown" else severity_from_word(word),
                    severity_native=str(word or ""),
                    confidence=0.9,
                    path=relative_path(str(locations[0].get("path") or ""), ("/",)),
                    purl=purl,
                    advisory_ids=(str(vuln["id"]), *related),
                    fixed_versions=tuple(
                        str(v) for v in (vuln.get("fix") or {}).get("versions") or []
                    ),
                    cvss=max(known) if known else None,
                )
            )
        return findings
