"""Scan orchestration: ingest the code, run the selected scanners in the sandbox, and commit
graph, findings and coverage gaps together.

A scanner that is missing, fails, times out or returns something unreadable never ends the
scan and never passes silently: it becomes a CoverageGap node.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from kurojisho import __version__
from kurojisho.clock import Clock, SystemClock
from kurojisho.config.settings import licence_accepted
from kurojisho.findings.locate import FunctionIndex
from kurojisho.findings.model import RawFinding, ToolOutputError, dumps, loads
from kurojisho.findings.normalise import build_findings
from kurojisho.findings.sbom import SbomPackage, merge_sbom
from kurojisho.findings.secrets import Scrubber, SecretHasher, load_salt
from kurojisho.ingest.pipeline import Extension, IngestState, ScanResult, scan
from kurojisho.intel.advisories import IntelData, build_advisories
from kurojisho.intel.cache import IntelCache
from kurojisho.intel.fetch import Fetcher
from kurojisho.intel.refresh import refresh
from kurojisho.model import Evidence, Node, NodeType, Provenance, node_key
from kurojisho.store import Store
from kurojisho.tools.manager import ToolManager
from kurojisho.tools.runners import RUNNERS, RepoProfile, RunContext, Runner, ScanOptions
from kurojisho.tools.runtime import Runtime, RuntimeUnavailable
from kurojisho.tools.sandbox import SandboxError

MAX_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024
#: Outcomes that leave part of the codebase unexamined.
GAP_DETAIL = {
    "sandbox_unavailable": "no container runtime; the tool was not run",
    "not_installed": "pinned image is not installed and installing was not allowed (offline)",
    "install_failed": "the pinned image could not be pulled",
    "failed": "the tool exited with an error",
    "timeout": "the tool exceeded its time limit and was stopped",
    "output_missing": "the tool finished without writing its report",
    "invalid_output": "the tool's report could not be parsed",
    "skipped_by_user": "the tool was excluded on the command line",
    "offline_db_missing": "the vulnerability database this tool needs is not in the intel cache",
}


class SelectionError(ValueError):
    """An unknown tool name was requested."""


class LicenceError(SelectionError):
    """A licence-gated tool was enabled without the terms being accepted."""


IMPORT_PREFIX = "import:"
UNPINNED = "unpinned"


@dataclass
class ToolOutcome:
    tool: str
    version: str
    digest: str
    status: str  # ok | cached | <a GAP_DETAIL key>
    exit_code: int | None = None
    duration_ms: int = 0
    findings: int = 0
    stderr: bytes = field(default=b"", repr=False)

    @property
    def is_gap(self) -> bool:
        return self.status in GAP_DETAIL


def select(
    profile: RepoProfile, options: ScanOptions, runners: dict[str, Runner]
) -> tuple[list[Runner], list[Runner]]:
    """Runners to run and runners the user excluded, chosen from what the repo contains."""
    requested = (options.only or frozenset()) | options.skip | options.enable
    unknown = sorted(requested - set(runners))
    if unknown:
        raise SelectionError(
            f"unknown tool(s): {', '.join(unknown)}; known: {', '.join(sorted(runners))}"
        )
    chosen, excluded = [], []
    for name in sorted(runners):
        runner = runners[name]
        if not runner.applicable(profile) or (runner.opt_in and name not in options.enable):
            continue
        if name in options.skip or (options.only is not None and name not in options.only):
            excluded.append(runner)
        else:
            chosen.append(runner)
    return chosen, excluded


class ToolScan:
    """One scan's worth of tool runs. Used as the ingest pipeline's extension."""

    def __init__(
        self,
        store: Store,
        runtime: Runtime | None,
        options: ScanOptions,
        *,
        manager: ToolManager | None = None,
        runners: dict[str, Runner] | None = None,
        notify: Callable[[str], None] | None = None,
        intel: IntelCache | None = None,
        fetcher: Fetcher | None = None,
        clock: Clock | None = None,
        run_tools: bool = True,
    ) -> None:
        self.run_tools = run_tools
        self.notify = notify or (lambda _message: None)
        self.intel = intel
        self.fetcher = fetcher
        self.clock = clock or SystemClock()
        self.store = store
        self.runtime = runtime
        self.options = options
        self.manager = manager or ToolManager(runtime)
        self.runners = RUNNERS if runners is None else runners
        self.outcomes: list[ToolOutcome] = []
        self._cache_updates: dict[str, tuple[str, str]] = {}
        on_disk = store.path != ":memory:"
        self.state_dir = Path(store.path).parent if on_disk else None

    # -- pipeline hook ------------------------------------------------------------------
    def extend(self, state: IngestState) -> Extension:
        profile = RepoProfile(
            languages=frozenset(e.lang for e in state.entries.values() if e.lang),
            files=frozenset(state.entries),
            has_git=(state.root / ".git").exists(),
            git_head=state.result.commit_sha,
        )
        chosen: list[Runner] = []
        excluded: list[Runner] = []
        if self.run_tools:
            chosen, excluded = select(profile, self.options, self.runners)
        raws: list[RawFinding] = []
        imported = self.store.conn.execute(
            "SELECT payload FROM tool_cache WHERE tool LIKE ? ORDER BY tool", (IMPORT_PREFIX + "%",)
        )
        for row in imported:  # results brought in with `import-sarif`
            raws += loads(row[0])
        sbom: list[tuple[str, list[SbomPackage]]] = []
        tree_key = f"{state.result.tree_hash}:{profile.git_head or ''}"
        self._refresh_intel(chosen, profile)
        work = Path(tempfile.mkdtemp(prefix="kurojisho-work-", dir=self._work_parent()))
        try:
            for runner in chosen:
                found, packages, outcome = self._run(runner, state.root, profile, work, tree_key)
                raws += found
                if packages:
                    pin = self.manager.pin(runner.pin_key)
                    sbom.append((f"{runner.name}@{pin.version}", packages))
                self.outcomes.append(outcome)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        for runner in excluded:
            known = self.manager.pins.get(runner.pin_key)
            pinned = (known.version, known.digest) if known else (UNPINNED, "")
            self.outcomes.append(ToolOutcome(runner.name, *pinned, "skipped_by_user"))

        graph = build_findings(
            raws,
            hashes=state.hashes,
            functions=FunctionIndex(state.nodes),
            hasher=SecretHasher(load_salt(self.store)),
        )
        nodes = graph.nodes + [self._gap(o) for o in self.outcomes if o.is_gap]
        edges = graph.edges
        # Packages only a vulnerability scanner saw still need a node to hang findings on.
        for finding in graph.nodes:
            purl = finding.props.get("purl") if finding.type is NodeType.FINDING else None
            if purl:
                name = purl.split("/", 1)[1].rsplit("@", 1)[0]
                version = purl.rsplit("@", 1)[1] if "@" in purl else None
                locations = (finding.props["path"],) if finding.props.get("path") else ()
                source = f"{finding.props['tool']}@{finding.props['tool_version']}"
                sbom.append((source, [SbomPackage(purl, name, version, (), locations)]))
        seen = {n.key for n in state.nodes if n.type is NodeType.PACKAGE}
        for source, packages in sbom:
            enrich = source.startswith("syft@")
            fresh = [
                p for p in packages if enrich or node_key(NodeType.PACKAGE, p.purl) not in seen
            ]
            added_nodes, added_edges = merge_sbom(state.nodes, fresh, state.hashes, source)
            seen |= {n.key for n in added_nodes}
            nodes += added_nodes
            edges += added_edges
        advisory_nodes, advisory_edges = build_advisories(
            graph.nodes, IntelData(self.intel) if self.intel is not None else None
        )
        nodes += advisory_nodes + self._intel_gaps(chosen, profile, bool(advisory_nodes))
        edges += advisory_edges
        for runner in chosen:
            present = sorted(f for f in runner.target_config if f in profile.files)
            if present and runner.pin_key in self.manager.pins:
                nodes.append(self._config_gap(runner, present))
        return Extension(
            nodes, graph.edges, graph.scrubber, lambda s, i: self._record(s, i, graph.scrubber)
        )

    def _refresh_intel(self, chosen: list[Runner], profile: RepoProfile) -> None:
        """Bring the databases the chosen tools need up to date, unless offline."""
        if self.intel is None or self.fetcher is None or self.options.offline:
            return
        needed = sorted({s for r in chosen for s in r.intel_sources(profile)})
        if any(r.category == "sca" for r in chosen):
            needed += ["kev", "epss"]
        stale = [s for s in needed if self.intel.stale(s, self.clock)]
        if not stale:
            return
        self.notify(f"refreshing vulnerability data (network): {', '.join(stale)}")
        grype = self.manager.pins.get("grype")
        if "grype-db" in stale and self.runtime is not None and not self.manager.installed("grype"):
            with contextlib.suppress(RuntimeUnavailable):  # the import then fails and is reported
                self.manager.install(["grype"])
        results = refresh(
            self.intel, self.fetcher, self.clock, stale, runtime=self.runtime, grype=grype
        )
        for done in results:
            if done.status == "failed":
                self.notify(f"could not refresh {done.source}: {done.detail}")

    def _intel_gaps(
        self, chosen: list[Runner], profile: RepoProfile, has_advisories: bool
    ) -> list[Node]:
        """Stale or absent intelligence is a gap in what the findings can tell you."""
        used = sorted({s for r in chosen for s in r.intel_sources(profile)})
        feeds = ["kev", "epss"] if has_advisories else []
        if self.intel is None:
            missing, stale = feeds, []
        else:
            intel = self.intel
            missing = [s for s in feeds if not intel.has(s)]
            stale = [s for s in [*used, *feeds] if intel.has(s) and intel.stale(s, self.clock)]
        details = {
            "intel_missing": "exploitation data (KEV/EPSS) is not cached: unknown, not absent",
            "intel_stale": "vulnerability data is over a day old; newer advisories are missed",
        }
        gaps = []
        for reason, sources in (("intel_missing", missing), ("intel_stale", stale)):
            if not sources:
                continue
            gaps.append(
                Node(
                    type=NodeType.COVERAGE_GAP,
                    key=node_key(NodeType.COVERAGE_GAP, "intel", reason),
                    name=f"intel: {reason}",
                    props={
                        "tool": "intel",
                        "tool_version": __version__,
                        "category": "intel",
                        "reason": reason,
                        "detail": details[reason],
                        "sources": sources,
                        "exit_code": None,
                    },
                    provenance=Provenance.TOOL,
                    confidence=1.0,
                    evidence=(Evidence(path=".", source=f"kurojisho@{__version__}", note=reason),),
                )
            )
        return gaps

    def _work_parent(self) -> str | None:
        if self.state_dir is None:
            return None
        parent = self.state_dir / "work"
        parent.mkdir(parents=True, exist_ok=True)
        parent.chmod(0o700)
        return str(parent)

    # -- one tool -----------------------------------------------------------------------
    def _run(
        self, runner: Runner, root: Path, profile: RepoProfile, work: Path, tree_key: str
    ) -> tuple[list[RawFinding], list[SbomPackage], ToolOutcome]:
        if runner.pin_key not in self.manager.pins:
            # Enabled, but this build pins no image or bundle for it: it cannot run.
            return [], [], ToolOutcome(runner.name, UNPINNED, "", "not_installed")
        pin = self.manager.pin(runner.pin_key)
        outcome = ToolOutcome(runner.name, pin.version, pin.digest, "ok")
        sources = runner.intel_sources(profile)
        snapshot = self.intel.snapshot_id(sources) if self.intel is not None and sources else ""
        key = hashlib.sha256(
            "\0".join([runner.name, pin.digest, tree_key, runner.cache_inputs(), snapshot]).encode()
        ).hexdigest()
        if not runner.sensitive:
            row = self.store.conn.execute(
                "SELECT payload FROM tool_cache WHERE tool = ? AND cache_key = ?",
                (runner.name, key),
            ).fetchone()
            if row is not None:
                payload = json.loads(row[0])
                found = loads(payload["findings"])
                packages = [SbomPackage.from_json(p) for p in payload["packages"]]
                outcome.status, outcome.findings = "cached", len(found)
                return found, packages, outcome
        if any(self.intel is None or not self.intel.has(s) for s in sources):
            outcome.status = "offline_db_missing"
            return [], [], outcome
        if self.runtime is None:
            outcome.status = "sandbox_unavailable"
            return [], [], outcome
        if not self.manager.installed(runner.pin_key):
            if self.options.offline:
                outcome.status = "not_installed"
                return [], [], outcome
            self.notify(f"installing {runner.name} {pin.version} (network: pulling {pin.ref})")
            try:
                self.manager.install([runner.pin_key])
            except RuntimeUnavailable:
                outcome.status = "install_failed"
                return [], [], outcome
        out = work / runner.name
        out.mkdir(mode=0o700)
        ctx = RunContext(root, out, pin, profile, self.options)
        ctx.intel = self.intel.root if self.intel is not None else None
        ctx.tools_dir = self.manager.binary_dir(runner.pin_key) if pin.build else None
        outputs: dict[str, bytes] = {}
        try:
            for step in runner.steps(ctx):
                done = self.runtime.run(
                    step.spec, allow_network=pin.network and self.options.verify_secrets
                )
                outcome.duration_ms += done.duration_ms
                outcome.exit_code = done.exit_code
                if not runner.sensitive:
                    outcome.stderr += done.stderr[-MAX_LOG_BYTES:]
                if done.timed_out:
                    outcome.status = "timeout"
                    return [], [], outcome
                if done.exit_code not in step.ok_exit:
                    outcome.status = "failed"
                    return [], [], outcome
                if not step.output:
                    outputs[step.name] = done.stdout
                    continue
                report = out / step.output
                if not report.is_file() or report.is_symlink():
                    outcome.status = "output_missing"
                    return [], [], outcome
                if report.stat().st_size > MAX_OUTPUT_BYTES:
                    outcome.status = "invalid_output"
                    return [], [], outcome
                outputs[step.name] = report.read_bytes()
            found = runner.parse(ctx, outputs)
            packages = runner.packages(ctx, outputs)
        except ToolOutputError:
            outcome.status = "invalid_output"
            return [], [], outcome
        except (SandboxError, OSError):
            outcome.status = "failed"
            return [], [], outcome
        finally:
            if runner.sensitive:
                _wipe(out)
        outcome.findings = len(found)
        if not runner.sensitive:
            payload = {"findings": dumps(found), "packages": [p.to_json() for p in packages]}
            self._cache_updates[runner.name] = (key, json.dumps(payload, sort_keys=True))
        return found, packages, outcome

    # -- records ------------------------------------------------------------------------
    def _gap(self, outcome: ToolOutcome) -> Node:
        runner = self.runners[outcome.tool]
        return Node(
            type=NodeType.COVERAGE_GAP,
            key=node_key(NodeType.COVERAGE_GAP, outcome.tool, outcome.status),
            name=f"{outcome.tool}: {outcome.status}",
            props={
                "tool": outcome.tool,
                "tool_version": outcome.version,
                "category": runner.category,
                "reason": outcome.status,
                "detail": GAP_DETAIL[outcome.status],
                "exit_code": outcome.exit_code,
            },
            provenance=Provenance.TOOL,
            confidence=1.0,
            evidence=(Evidence(path=".", source=f"kurojisho@{__version__}", note=outcome.status),),
        )

    def _config_gap(self, runner: Runner, files: list[str]) -> Node:
        pin = self.manager.pin(runner.pin_key)
        return Node(
            type=NodeType.COVERAGE_GAP,
            key=node_key(NodeType.COVERAGE_GAP, runner.name, "target_config_present"),
            name=f"{runner.name}: target_config_present",
            props={
                "tool": runner.name,
                "tool_version": pin.version,
                "category": runner.category,
                "reason": "target_config_present",
                "detail": "the scanned repository holds files that can narrow this tool's results",
                "files": files,
                "exit_code": None,
            },
            provenance=Provenance.TOOL,
            confidence=1.0,
            evidence=tuple(Evidence(path=f, source=f"kurojisho@{__version__}") for f in files),
        )

    def _record(self, store: Store, scan_id: int, scrubber: Scrubber) -> None:
        for outcome in self.outcomes:
            store.conn.execute(
                "INSERT INTO tool_runs(scan_id, tool, version, digest, status, exit_code, "
                "duration_ms, findings) VALUES(?,?,?,?,?,?,?,?)",
                (scan_id, outcome.tool, outcome.version, outcome.digest, outcome.status,
                 outcome.exit_code, outcome.duration_ms, outcome.findings),
            )  # fmt: skip
        for tool, (key, payload) in self._cache_updates.items():
            store.conn.execute(
                "INSERT INTO tool_cache(tool, cache_key, payload) VALUES(?,?,?) "
                "ON CONFLICT(tool) DO UPDATE SET cache_key = excluded.cache_key, "
                "payload = excluded.payload",
                (tool, key, scrubber.text(payload)),
            )
        if self.state_dir is not None:
            logs = self.state_dir / "logs"
            logs.mkdir(exist_ok=True)
            for outcome in self.outcomes:
                if outcome.stderr:
                    (logs / f"{outcome.tool}.log").write_bytes(scrubber.bytes(outcome.stderr))


def _wipe(directory: Path) -> None:
    """Overwrite then delete raw scanner output that may contain secret values."""
    for path in directory.rglob("*"):
        if path.is_file() and not path.is_symlink():
            try:
                size = path.stat().st_size
                with path.open("r+b") as handle:
                    handle.write(b"\0" * size)
                path.unlink()
            except OSError:
                continue


def scan_with_tools(
    root: Path,
    store: Store,
    clock: Clock,
    *,
    runtime: Runtime | None,
    options: ScanOptions | None = None,
    context_path: Path | None = None,
    full: bool = False,
    manager: ToolManager | None = None,
    runners: dict[str, Runner] | None = None,
    notify: Callable[[str], None] | None = None,
    intel: IntelCache | None = None,
    fetcher: Fetcher | None = None,
) -> tuple[ScanResult, list[ToolOutcome]]:
    options = options or ScanOptions()
    registry = RUNNERS if runners is None else runners
    for name in sorted(options.enable & set(registry)):
        if registry[name].licence_terms and not licence_accepted(name):
            raise LicenceError(
                f"{name} is licence-restricted and its terms have not been accepted. "
                f"{registry[name].licence_terms} If these terms fit your use, run "
                f"`kurojisho tools accept-licence {name} --yes`."
            )
    imports = store.conn.execute(
        "SELECT COUNT(*) FROM tool_cache WHERE tool LIKE ?", (IMPORT_PREFIX + "%",)
    ).fetchone()[0]
    if not options.tools and not imports:
        return scan(root, store, clock, context_path=context_path, full=full), []
    tools = ToolScan(
        store, runtime, options, manager=manager, runners=runners, notify=notify,
        intel=intel, fetcher=fetcher, clock=clock, run_tools=options.tools,
    )  # fmt: skip
    result = scan(root, store, clock, context_path=context_path, full=full, extend=tools.extend)
    return result, tools.outcomes


def import_findings(store: Store, tool: str, findings: list[RawFinding]) -> None:
    """Keep externally produced findings so that every later scan includes them."""
    store.conn.execute(
        "INSERT INTO tool_cache(tool, cache_key, payload) VALUES(?,?,?) "
        "ON CONFLICT(tool) DO UPDATE SET payload = excluded.payload",
        (IMPORT_PREFIX + tool, "import", dumps(findings)),
    )
