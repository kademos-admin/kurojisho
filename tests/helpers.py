"""Shared builders and test doubles."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from kurojisho.clock import Clock
from kurojisho.intel.cache import IntelCache
from kurojisho.intel.fetch import FetchError
from kurojisho.model import Edge, EdgeType, Evidence, Node, NodeType, Provenance, node_key
from kurojisho.tools.lock import load_lock
from kurojisho.tools.runtime import RunResult, RuntimeUnavailable
from kurojisho.tools.sandbox import OUT, RunSpec, build_command

EV = Evidence(path="a.py", source="test", start_line=1, end_line=1)


def fn(name: str, owner: str = "a.py", **props: Any) -> Node:
    return Node(
        type=NodeType.FUNCTION,
        key=node_key(NodeType.FUNCTION, owner, name),
        name=name,
        owner_file=owner,
        props=props,
        provenance=Provenance.EXTRACTED,
        confidence=1.0,
        evidence=(EV,),
    )


def call(src: Node, dst: Node, resolution: str = "exact", confidence: float = 0.9) -> Edge:
    return Edge(
        type=EdgeType.CALLS,
        src=src.id,
        dst=dst.id,
        owner_file=src.owner_file,
        props={"resolution": resolution},
        provenance=Provenance.INFERRED,
        confidence=confidence,
        evidence=(EV,),
    )


# -- scanner test doubles ---------------------------------------------------------------


PINS = load_lock()
TOOL_BY_REF = {pin.ref: name for name, pin in PINS.items()}
TOOL_OUTPUTS = Path(__file__).parent / "fixtures" / "tool_outputs"

Handler = Callable[[RunSpec, Path], RunResult]


def writes(files: dict[str, bytes | str], *, exit_code: int = 0, stderr: bytes = b"") -> Handler:
    """Handler that behaves like a tool writing ``files`` into its /out mount."""

    def handler(spec: RunSpec, out: Path) -> RunResult:
        for name, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            (out / name).write_bytes(data)
        return RunResult(exit_code, b"", stderr, duration_ms=5)

    return handler


def gitleaks_report(*findings: tuple[str, str, int, str], commit: str = "") -> str:
    """Gitleaks JSON in the shape the real tool emits: (rule, file, line, secret)."""
    return json.dumps(
        [
            {
                "RuleID": rule,
                "Description": f"Detected a {rule}.",
                "StartLine": line,
                "EndLine": line,
                "Match": f'KEY = "{secret}"',
                "Secret": secret,
                "File": path if commit else f"/src/{path}",
                "Commit": commit,
                "Entropy": 4.5,
                "Fingerprint": f"{commit}:{path}:{rule}:{line}",
            }
            for rule, path, line, secret in findings
        ]
    )


class FakeRuntime:
    """Stands in for Docker: validates every spec through the real sandbox builder, then
    lets a per-tool handler play the scanner."""

    name = "fake"

    def __init__(self, handlers: dict[str, Handler], *, installed: bool = True) -> None:
        self.handlers = handlers
        self.present = set(TOOL_BY_REF) if installed else set()
        self.pulled: list[str] = []
        self.runs: list[tuple[str, RunSpec, bool]] = []
        self.commands: list[list[str]] = []
        self.out_dirs: list[Path] = []
        self.fail_pull = False

    def image_present(self, ref: str) -> bool:
        return ref in self.present

    def pull(self, ref: str) -> None:
        if self.fail_pull:
            raise RuntimeUnavailable("registry unreachable")
        self.pulled.append(ref)
        self.present.add(ref)

    def run(self, spec: RunSpec, *, allow_network: bool = False) -> RunResult:
        tool = TOOL_BY_REF[spec.image]
        self.commands.append(
            build_command("docker", spec, name="t", uid=1000, gid=1000, allow_network=allow_network)
        )
        out = next((m.source for m in spec.mounts if m.target == OUT), Path("/nonexistent"))
        self.runs.append((tool, spec, allow_network))
        if out.exists():
            self.out_dirs.append(out)
        handler = self.handlers.get(tool)
        return handler(spec, out) if handler else RunResult(1, b"", b"no such tool in this test")


def recorded(tool: str, name: str) -> bytes:
    return (TOOL_OUTPUTS / tool / name).read_bytes()


def all_handlers(**override: Handler) -> dict[str, Handler]:
    """Every adapter replaying what the real tool produced for the vuln_app fixture.
    Secret scanners report nothing unless a test overrides them."""
    base: dict[str, Handler] = {
        "semgrep": writes({"semgrep.sarif": recorded("semgrep", "vuln_app.sarif")}),
        "bandit": writes({"bandit.json": recorded("bandit", "vuln_app.json")}),
        "gosec": writes({"gosec-0.sarif": recorded("gosec", "vuln_app.sarif")}),
        "checkov": writes({"results_sarif.sarif": recorded("checkov", "vuln_app.sarif")}),
        "syft": writes({"sbom.json": recorded("syft", "vuln_app.cdx.json")}),
        "gitleaks": writes({"dir.json": "[]", "git.json": "[]"}),
        "trufflehog": lambda _spec, _out: RunResult(0, b"", b"", duration_ms=5),
        "osv-scanner": writes({"osv.json": recorded("osv-scanner", "vuln_app.json")}, exit_code=1),
        "trivy": writes(
            {
                "trivy.json": recorded("trivy", "vuln_app.fs.json"),
                "trivy-config.json": recorded("trivy", "vuln_app.config.json"),
            }
        ),
        "grype": writes({"grype.json": recorded("grype", "vuln_app.json")}),
    }
    return {**base, **override}


# -- intel test doubles -------------------------------------------------------------------


class FakeFetcher:
    """Serves canned bytes per URL prefix and records every request."""

    def __init__(self, responses: dict[str, bytes]) -> None:
        self.responses = responses
        self.requested: list[str] = []

    def _find(self, url: str) -> bytes:
        self.requested.append(url)
        for prefix in sorted(self.responses, key=len, reverse=True):
            if url.startswith(prefix):
                return self.responses[prefix]
        raise FetchError(f"no route to {url}")

    def get(self, url: str, headers: dict[str, str] | None = None) -> bytes:
        return self._find(url)

    def download(self, url: str, dest: Path, headers: dict[str, str] | None = None) -> str:
        data = self._find(url)
        dest.write_bytes(data)
        return hashlib.sha256(data).hexdigest()


def zip_bytes(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name, content in files.items():
            # a fixed timestamp keeps the archive, and so the intel snapshot id, reproducible
            bundle.writestr(zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0)), content)
    return buffer.getvalue()


LOG4SHELL = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "aliases": ["CVE-2021-44228"],
    "summary": "Remote code injection in Log4j",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
}


def make_intel(
    root: Path, clock: Clock, *, feeds: bool = True, sources: tuple[str, ...] = ()
) -> IntelCache:
    """A small but structurally real intel cache: scanner databases as placeholders (the
    fake runtime never opens them) plus genuine-format OSV, KEV and EPSS data."""
    cache = IntelCache(root)
    for ecosystem in ("PyPI", "npm", "Go", "Maven"):
        archive = cache.dir(f"osv/osv-scalibr/{ecosystem}") / "all.zip"
        records = (
            {"GHSA-jfh8-c2jp-5v3q.json": json.dumps(LOG4SHELL)} if ecosystem == "Maven" else {}
        )
        archive.write_bytes(zip_bytes(records))
        cache.record(f"osv:{ecosystem}", hashlib.sha256(archive.read_bytes()).hexdigest(), clock)
    for source, directory in (
        ("trivy-db", "trivy/db"),
        ("grype-db", "grype/db"),
        ("govulndb", "govulndb"),
    ):
        cache.dir(directory)
        cache.record(source, hashlib.sha256(source.encode()).hexdigest(), clock)
    if feeds:
        kev = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}
        (cache.dir("feeds") / "kev.json").write_text(json.dumps(kev))
        cache.record("kev", "k" * 64, clock)
        rows = (
            "#model_version:v1\ncve,epss,percentile\n"
            "CVE-2021-44228,0.97500,0.99990\nCVE-2018-1000656,0.00300,0.52000\n"
        )
        (cache.dir("feeds") / "epss.csv.gz").write_bytes(gzip.compress(rows.encode(), mtime=0))
        cache.record("epss", "e" * 64, clock)
    for source in sources:
        cache.record(source, "x" * 64, clock)
    return cache


def tool_gaps(store: Any) -> list[dict[str, Any]]:
    """Coverage gaps left by scanners and intel (not the ones the deploy reader records)."""
    from kurojisho.store import queries

    found = queries.find_nodes(store, node_type="CoverageGap")
    return [g for g in found if g["props"]["tool"] != "deploy"]


class Graph:
    """A scanned in-memory tree, with lookups by readable key."""

    def __init__(
        self,
        root: Path,
        files: dict[str, str],
        *,
        findings: list[Any] | None = None,
        intel: IntelCache | None = None,
        **scan_options: Any,
    ) -> None:
        """``findings``: RawFinding objects, brought in the way ``import-sarif`` does."""
        from datetime import UTC, datetime

        from kurojisho.clock import FixedClock
        from kurojisho.ingest.pipeline import scan
        from kurojisho.scanner import import_findings, scan_with_tools
        from kurojisho.store import Store
        from kurojisho.tools.runners.base import ScanOptions

        for name, content in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        self.root = root
        self.store = Store(":memory:")
        clock = FixedClock(datetime(2024, 1, 1, tzinfo=UTC))
        if findings is None:
            scan(root, self.store, clock, **scan_options)
        else:
            import_findings(self.store, "probe", findings)
            scan_with_tools(
                root, self.store, clock, runtime=None, options=ScanOptions(tools=False), intel=intel
            )
        rows = self.store.conn.execute("SELECT id, key FROM nodes WHERE retired = 0")
        self.names = {r["id"]: r["key"] for r in rows}

    def nodes(self, kind: str) -> dict[str, dict[str, Any]]:
        rows = self.store.conn.execute(
            "SELECT key, props, provenance, confidence FROM nodes "
            "WHERE type = ? AND retired = 0 ORDER BY key",
            (kind,),
        )
        return {
            r["key"].split(":", 1)[1]: {
                **json.loads(r["props"]),
                "_provenance": r["provenance"],
                "_confidence": r["confidence"],
            }
            for r in rows
        }

    def edges(self, kind: str) -> list[tuple[str, str, dict[str, Any]]]:
        rows = self.store.conn.execute(
            "SELECT src, dst, props, provenance, confidence FROM edges "
            "WHERE type = ? AND retired = 0 ORDER BY id",
            (kind,),
        )
        return sorted(
            (
                (
                    self.names[r["src"]].split(":", 1)[1],
                    self.names[r["dst"]].split(":", 1)[1],
                    {
                        **json.loads(r["props"]),
                        "_provenance": r["provenance"],
                        "_confidence": r["confidence"],
                    },
                )
                for r in rows
            ),
            key=lambda e: (e[0], e[1]),
        )
