"""Command line interface: ``kurojisho init | scan | query``."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from kurojisho import __version__
from kurojisho.clock import clock_from_env, isoformat
from kurojisho.config.context import CONTEXT_FILENAME, ContextError
from kurojisho.config.settings import STATE_DIR, accept_licence, default_db_path
from kurojisho.findings import sarif
from kurojisho.findings.model import ToolOutputError
from kurojisho.ingest.pipeline import ScanError
from kurojisho.intel.cache import IntelCache, cache_root
from kurojisho.intel.fetch import HttpFetcher
from kurojisho.intel.refresh import OSV_ECOSYSTEMS, osv_source, refresh, refresh_nvd
from kurojisho.model import EdgeType
from kurojisho.scanner import SelectionError, import_findings, scan_with_tools
from kurojisho.store import Store, StoreError
from kurojisho.store import queries as q
from kurojisho.store.graph import canonical_export
from kurojisho.tools.manager import ToolManager
from kurojisho.tools.runners import RUNNERS, ScanOptions
from kurojisho.tools.runtime import RuntimeUnavailable, detect_runtime

app = typer.Typer(
    help="KuroJisho: a local, deterministic security knowledge graph.",
    no_args_is_help=True,
    add_completion=False,
)
query_app = typer.Typer(help="Read the stored graph.", no_args_is_help=True)
app.add_typer(query_app, name="query")
tools_app = typer.Typer(help="Install, verify and list the pinned scanners.", no_args_is_help=True)
app.add_typer(tools_app, name="tools")
intel_app = typer.Typer(help="Vulnerability intelligence cache.", no_args_is_help=True)
app.add_typer(intel_app, name="intel")

out = Console()
err = Console(stderr=True)

CONTEXT_TEMPLATE = """\
# Business context for KuroJisho. Everything here is recorded as ASSERTED.
# Uncomment and edit. Paths are globs relative to this file's directory.
#
# assets:
#   - id: payments-api
#     paths: ["services/payments/**"]
#     tier: 1                  # 1 (most critical) to 4
#     data_classes: [PCI, PII] # PII, PCI, PHI, secrets, IP
#     exposure: internet       # internet | partner | internal | none
#     asvs_level: 3            # 2 or 3
#     regulatory: [PCI-DSS]
# defaults: { asvs_level: 2, tier: 3 }
"""

RepoOpt = Annotated[Path, typer.Option("--repo", help="Scanned codebase (locates its graph).")]
DbOpt = Annotated[Path | None, typer.Option("--db", help="Graph database file.")]
JsonOpt = Annotated[bool, typer.Option("--json", help="Machine-readable output.")]
RuntimeOpt = Annotated[
    str | None,
    typer.Option("--runtime", help="Container runtime: docker or podman (default: auto)."),
]


def _names(value: str | None) -> frozenset[str]:
    return frozenset(n.strip() for n in (value or "").split(",") if n.strip())


def _fail(message: str) -> typer.Exit:
    err.print(f"[red]error:[/red] {message}", highlight=False)
    return typer.Exit(2)


def _open(repo: Path, db: Path | None, *, must_exist: bool) -> Store:
    path = db or default_db_path(repo)
    if must_exist and not path.is_file():
        raise _fail(f"no graph at {path}; run `kurojisho scan {repo}` first")
    try:
        return Store(path)
    except StoreError as exc:
        raise _fail(str(exc)) from exc


def _emit(data: Any, as_json: bool, table: Table | None = None) -> None:
    if as_json or table is None:
        typer.echo(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        out.print(table)


def _version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    """KuroJisho command line."""


@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="Codebase to prepare.")] = Path("."),
) -> None:
    """Create the state directory and a starter context file. Existing files are kept."""
    if not path.is_dir():
        raise _fail(f"not a directory: {path}")
    _open(path, None, must_exist=False).close()
    out.print(f"graph store: {default_db_path(path)}", highlight=False)
    context = path / CONTEXT_FILENAME
    if context.exists():
        out.print(f"context file kept: {context}", highlight=False)
    else:
        context.write_text(CONTEXT_TEMPLATE, encoding="utf-8")
        out.print(f"context file created: {context}", highlight=False)
    out.print(f"add [bold]{STATE_DIR}/[/bold] to your .gitignore", highlight=False)


@app.command(name="scan")
def scan_command(
    path: Annotated[Path, typer.Argument(help="Codebase to scan (read-only).")],
    db: DbOpt = None,
    context: Annotated[
        Path | None, typer.Option("--context", help=f"Context file (default: {CONTEXT_FILENAME}).")
    ] = None,
    full: Annotated[bool, typer.Option("--full", help="Ignore the parse cache.")] = False,
    no_tools: Annotated[
        bool, typer.Option("--no-tools", help="Build the code graph only; run no scanners.")
    ] = False,
    tools: Annotated[
        str | None, typer.Option("--tools", help="Run only these scanners (comma-separated).")
    ] = None,
    skip: Annotated[
        str | None,
        typer.Option("--skip", help="Scanners to leave out (recorded as coverage gaps)."),
    ] = None,
    enable: Annotated[
        str | None, typer.Option("--enable", help="Opt-in scanners to switch on (comma-separated).")
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="Never use the network; missing tools become gaps.")
    ] = False,
    verify_secrets: Annotated[
        bool, typer.Option("--verify-secrets", help="Let TruffleHog test found secrets (network).")
    ] = False,
    runtime: RuntimeOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Build or update the graph and run the pinned scanners in a sandbox.

    Target code is parsed, never executed. Scanners run in containers with the target
    read-only and no network. Missing scanner images are pulled first unless --offline.
    """
    if not path.is_dir():
        raise _fail(f"not a directory: {path}")
    options = ScanOptions(
        tools=not no_tools,
        only=_names(tools) if tools is not None else None,
        skip=_names(skip),
        enable=_names(enable),
        offline=offline,
        verify_secrets=verify_secrets,
    )
    engine = None if no_tools else detect_runtime(runtime)
    if not no_tools and engine is None:
        err.print(
            "[yellow]warning:[/yellow] no container runtime found; scanners will not run and "
            "are recorded as coverage gaps",
            highlight=False,
        )
    store = _open(path, db, must_exist=False)
    try:
        result, outcomes = scan_with_tools(
            path,
            store,
            clock_from_env(),
            runtime=engine,
            options=options,
            context_path=context,
            full=full,
            notify=lambda message: err.print(message, highlight=False),
            intel=None if no_tools else IntelCache(cache_root() / "intel"),
            fetcher=None if (no_tools or offline) else make_fetcher(),
        )
    except (ScanError, ContextError, StoreError, SelectionError) as exc:
        raise _fail(str(exc)) from exc
    finally:
        store.close()
    summary = {
        "scan_id": result.scan_id,
        "commit": result.commit_sha,
        **result.summary(),
        "tools": {o.tool: {"status": o.status, "findings": o.findings} for o in outcomes},
    }
    table = Table(title=f"scan #{result.scan_id}", show_header=False)
    for key, value in summary.items():
        if key != "tools":
            table.add_row(key, str(value))
    for outcome in outcomes:
        table.add_row(f"tool: {outcome.tool}", f"{outcome.status} ({outcome.findings} findings)")
    _emit(summary, as_json, table)
    if result.files_with_parse_errors:
        err.print(
            f"[yellow]warning:[/yellow] {len(result.files_with_parse_errors)} file(s) had syntax "
            "errors and were only partly extracted (see File.parse_error_lines)",
            highlight=False,
        )
    gaps = sorted(o.tool for o in outcomes if o.is_gap)
    if gaps:
        err.print(
            f"[yellow]warning:[/yellow] coverage gaps: {', '.join(gaps)} did not produce results "
            "(see CoverageGap nodes); absence of findings there means nothing",
            highlight=False,
        )


@tools_app.command(name="list")
def tools_list(runtime: RuntimeOpt = None, as_json: JsonOpt = False) -> None:
    """Show every pinned scanner, its licence and whether its exact digest is installed."""
    statuses = ToolManager(detect_runtime(runtime)).status()
    rows = [
        {
            "name": s.pin.name,
            "version": s.pin.version,
            "licence": s.pin.licence,
            "image": s.pin.ref,
            "installed": s.installed,
            "verification": s.verification,
        }
        for s in statuses
    ]
    table = Table("tool", "version", "licence", "installed", "verification", "digest")
    for s in statuses:
        table.add_row(
            s.pin.name, s.pin.version, s.pin.licence, "yes" if s.installed else "no",
            s.verification, s.pin.digest[:19] + "…",
        )  # fmt: skip
    _emit(rows, as_json, table)


@app.command(name="import-sarif")
def import_sarif(
    file: Annotated[Path, typer.Argument(help="SARIF 2.1.0 file produced elsewhere, e.g. in CI.")],
    tool: Annotated[str, typer.Option("--tool", help="Name of the tool that produced it.")],
    tool_version: Annotated[str, typer.Option("--tool-version")] = "unknown",
    category: Annotated[str, typer.Option("--category", help="sast or iac.")] = "sast",
    repo: RepoOpt = Path("."),
    db: DbOpt = None,
) -> None:
    """Bring scanner results produced elsewhere into the graph (optional CI mode). They go
    through the same normaliser as KuroJisho's own runs and are marked ``imported``."""
    if not tool.replace("-", "").replace("_", "").isalnum() or category not in ("sast", "iac"):
        raise _fail("--tool must be a simple name and --category one of: sast, iac")
    try:
        findings = sarif.parse(
            file.read_bytes(),
            tool=tool,
            version=tool_version,
            category=category,
            prefixes=("/src/", str(repo.resolve()) + "/"),
            imported=True,
        )
    except OSError as exc:
        raise _fail(f"cannot read {file}") from exc
    except ToolOutputError as exc:
        raise _fail(f"{file}: {exc}") from exc
    store = _open(repo, db, must_exist=False)
    try:
        import_findings(store, tool, findings)
        result, _ = scan_with_tools(
            repo, store, clock_from_env(), runtime=None, options=ScanOptions(tools=False)
        )
    except (ScanError, ContextError, StoreError) as exc:
        raise _fail(str(exc)) from exc
    finally:
        store.close()
    out.print(
        f"imported {len(findings)} result(s) from {tool}; scan #{result.scan_id} "
        f"wrote {result.writes.total} row(s)",
        highlight=False,
    )


@tools_app.command(name="accept-licence")
def tools_accept_licence(
    name: Annotated[str, typer.Argument(help="Licence-gated tool, e.g. codeql.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the terms fit your use.")] = False,
) -> None:
    """Record acceptance of a restricted tool's licence terms."""
    runner = RUNNERS.get(name)
    if runner is None or not runner.licence_terms:
        raise _fail(f"{name!r} has no licence gate")
    out.print(runner.licence_terms, highlight=False)
    if not yes:
        err.print("not recorded: re-run with --yes if these terms fit your use", highlight=False)
        raise typer.Exit(1)
    path = accept_licence(name, isoformat(clock_from_env().now()), runner.licence_terms)
    out.print(f"acceptance recorded in {path}", highlight=False)


@tools_app.command()
def install(
    names: Annotated[
        list[str] | None, typer.Argument(help="Tools to install (default: all).")
    ] = None,
    runtime: RuntimeOpt = None,
) -> None:
    """Pull pinned scanner images by digest. This uses the network."""
    manager = ToolManager(detect_runtime(runtime))
    unknown = sorted(set(names or []) - set(manager.pins))
    if unknown:
        raise _fail(f"unknown tool(s): {', '.join(unknown)}")
    if manager.runtime is None:
        raise _fail("no container runtime (docker or podman) is available")
    pulled: list[str] = []
    failed: list[str] = []
    for name in sorted(names or manager.pins):
        try:
            pulled += manager.install([name])
        except RuntimeUnavailable as exc:
            failed.append(name)
            err.print(f"failed: {name}: {exc}", highlight=False)
    out.print(f"installed: {', '.join(pulled) if pulled else 'nothing to do'}", highlight=False)
    if failed:
        raise typer.Exit(1)


@tools_app.command()
def verify(runtime: RuntimeOpt = None) -> None:
    """Check that every pinned digest is present locally. Exit code 1 if any is missing."""
    statuses = ToolManager(detect_runtime(runtime)).status()
    missing = [s.pin.name for s in statuses if not s.installed]
    for status in statuses:
        mark = "ok     " if status.installed else "MISSING"
        out.print(
            f"{mark} {status.pin.name} {status.pin.version} {status.pin.digest}", highlight=False
        )
    if missing:
        err.print(f"missing: {', '.join(missing)} (run `kurojisho tools install`)", highlight=False)
        raise typer.Exit(1)


def make_fetcher() -> HttpFetcher:
    return HttpFetcher()


ALL_SOURCES = [
    *(osv_source(e) for e in OSV_ECOSYSTEMS),
    "trivy-db",
    "grype-db",
    "govulndb",
    "kev",
    "epss",
]


@intel_app.command(name="refresh")
def intel_refresh(
    force: Annotated[
        bool, typer.Option("--force", help="Refresh even if under a day old.")
    ] = False,
    nvd: Annotated[
        int,
        typer.Option("--nvd", min=0, help="Also fetch up to N NVD records for CVEs in the graph."),
    ] = 0,
    repo: RepoOpt = Path("."),
    db: DbOpt = None,
    runtime: RuntimeOpt = None,
) -> None:
    """Download vulnerability data (OSV, Trivy DB, Grype DB, CISA KEV, EPSS). Uses the network."""
    import os
    import time

    cache = IntelCache(cache_root() / "intel")
    engine = detect_runtime(runtime)
    manager = ToolManager(engine)
    if engine is not None and not manager.installed("grype"):
        try:
            manager.install(["grype"])  # Grype itself unpacks and indexes its database
        except RuntimeUnavailable as exc:
            err.print(f"grype could not be installed: {exc}", highlight=False)
    fetcher, clock = make_fetcher(), clock_from_env()
    results = refresh(
        cache,
        fetcher,
        clock,
        ALL_SOURCES,
        runtime=engine,
        grype=manager.pins.get("grype"),
        force=force,
    )
    if nvd:
        path = db or default_db_path(repo)
        cves: list[str] = []
        if path.is_file():
            with _open(repo, db, must_exist=True) as store:
                for node in q.find_nodes(store, node_type="Advisory"):
                    cves += [a for a in node["props"]["aliases"] if a.startswith("CVE-")]
        results.append(
            refresh_nvd(cache, fetcher, clock, cves, budget=nvd, sleep=time.sleep,
                        api_key=os.environ.get("NVD_API_KEY"))
        )  # fmt: skip
    for done in results:
        out.print(f"{done.status:8} {done.source} {done.detail}".rstrip(), highlight=False)
    out.print(f"cache: {cache.root}", highlight=False)
    if any(r.status == "failed" for r in results):
        raise typer.Exit(1)


@intel_app.command(name="status")
def intel_status(as_json: JsonOpt = False) -> None:
    """Show what is cached, how old it is, and the snapshot id scans record."""
    cache = IntelCache(cache_root() / "intel")
    clock = clock_from_env()
    rows = [
        {
            "source": name,
            "fetched_at": entry["fetched_at"],
            "age_hours": round(cache.age_hours(name, clock) or 0.0, 1),
            "stale": cache.stale(name, clock),
            "sha256": entry["sha256"],
        }
        for name, entry in sorted(cache.sources.items())
    ]
    table = Table("source", "fetched", "age (h)", "stale", "sha256")
    for row in rows:
        table.add_row(row["source"], row["fetched_at"], str(row["age_hours"]),
                      "yes" if row["stale"] else "no", row["sha256"][:16] + "…")  # fmt: skip
    _emit(
        {"cache": str(cache.root), "snapshot": cache.snapshot_id(), "sources": rows}, as_json, table
    )


def _one(store: Store, ref: str) -> dict[str, Any]:
    matches = q.resolve_ref(store, ref)
    if not matches:
        raise _fail(f"no node matches {ref!r}")
    if len(matches) > 1:
        listing = "\n  ".join(m["key"] for m in matches[:10])
        raise _fail(f"{ref!r} is ambiguous ({len(matches)} matches):\n  {listing}")
    return matches[0]


def _key(store: Store, node: str) -> str:
    found = q.get_node(store, node)
    return found["key"] if found else node


@query_app.command()
def stats(repo: RepoOpt = Path("."), db: DbOpt = None, as_json: JsonOpt = False) -> None:
    """Node and edge counts by type, and how calls were resolved."""
    with _open(repo, db, must_exist=True) as store:
        data = q.stats(store)
    table = Table("kind", "type", "count")
    for kind, counts in data.items():
        for name, count in counts.items():
            table.add_row(kind, name, str(count))
    _emit(data, as_json, table)


@query_app.command()
def nodes(
    node_type: Annotated[str | None, typer.Option("--type", help="e.g. Function, Package.")] = None,
    name: Annotated[str | None, typer.Option("--name", help="Exact node name.")] = None,
    limit: Annotated[int, typer.Option("--limit", min=0, help="0 = no limit.")] = 50,
    repo: RepoOpt = Path("."),
    db: DbOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """List nodes."""
    with _open(repo, db, must_exist=True) as store:
        rows = q.find_nodes(store, node_type=node_type, name=name, limit=limit)
    table = Table("key", "provenance", "confidence")
    for row in rows:
        table.add_row(row["key"], row["provenance"], f"{row['confidence']:.2f}")
    _emit(rows, as_json, table)


@query_app.command()
def show(
    ref: Annotated[str, typer.Argument(help="Node id, key, key suffix or name.")],
    repo: RepoOpt = Path("."),
    db: DbOpt = None,
) -> None:
    """Show one node with its provenance and evidence."""
    with _open(repo, db, must_exist=True) as store:
        _emit(_one(store, ref), True)


def _neighbours(
    ref: str, direction: q.Direction, repo: Path, db: Path | None, as_json: bool
) -> None:
    with _open(repo, db, must_exist=True) as store:
        node = _one(store, ref)
        steps = q.neighbours(store, node["id"], EdgeType.CALLS, direction)
        rows = [
            {
                "function": _key(store, s.dst if direction == "out" else s.src),
                "resolution": s.props.get("resolution"),
                "confidence": s.confidence,
            }
            for s in steps
        ]
    rows.sort(key=lambda r: (r["function"], str(r["resolution"])))
    table = Table("function", "resolution", "confidence")
    for row in rows:
        table.add_row(str(row["function"]), str(row["resolution"]), f"{row['confidence']:.2f}")
    _emit(rows, as_json, table)


@query_app.command()
def callers(
    ref: Annotated[str, typer.Argument(help="Function reference.")],
    repo: RepoOpt = Path("."),
    db: DbOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Functions that call REF."""
    _neighbours(ref, "in", repo, db, as_json)


@query_app.command()
def callees(
    ref: Annotated[str, typer.Argument(help="Function reference.")],
    repo: RepoOpt = Path("."),
    db: DbOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Functions that REF calls."""
    _neighbours(ref, "out", repo, db, as_json)


@query_app.command()
def path(
    src: Annotated[str, typer.Argument(help="Start node.")],
    dst: Annotated[str, typer.Argument(help="End node.")],
    edge: Annotated[
        list[EdgeType] | None, typer.Option("--edge", help="Edge types to follow (default CALLS).")
    ] = None,
    max_depth: Annotated[int, typer.Option("--max-depth", min=1)] = q.DEFAULT_MAX_DEPTH,
    repo: RepoOpt = Path("."),
    db: DbOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Shortest path between two nodes (recursive CTE). Exit code 1 when there is none."""
    with _open(repo, db, must_exist=True) as store:
        start, end = _one(store, src), _one(store, dst)
        steps = q.shortest_path(
            store, start["id"], end["id"], edge_types=edge or [EdgeType.CALLS], max_depth=max_depth
        )
        if steps is None:
            err.print("no path found (unknown is not the same as unreachable)", highlight=False)
            raise typer.Exit(1)
        rows = [{**asdict(s), "src": _key(store, s.src), "dst": _key(store, s.dst)} for s in steps]
    table = Table("from", "edge", "to", "confidence")
    for row in rows:
        label = row["edge_type"]
        if row["props"].get("resolution"):
            label += f" ({row['props']['resolution']})"
        table.add_row(row["src"], label, row["dst"], f"{row['confidence']:.2f}")
    _emit(rows, as_json, table)


@query_app.command()
def export(
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write to a file.")] = None,
    repo: RepoOpt = Path("."),
    db: DbOpt = None,
) -> None:
    """Deterministic JSON export of the live graph."""
    with _open(repo, db, must_exist=True) as store:
        text = canonical_export(store)
    if output is None:
        typer.echo(text, nl=False)
    else:
        output.write_text(text, encoding="utf-8")
