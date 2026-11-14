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
from kurojisho.clock import clock_from_env
from kurojisho.config.context import CONTEXT_FILENAME, ContextError
from kurojisho.config.settings import STATE_DIR, default_db_path
from kurojisho.ingest.pipeline import ScanError, scan
from kurojisho.model import EdgeType
from kurojisho.store import Store, StoreError
from kurojisho.store import queries as q
from kurojisho.store.graph import canonical_export

app = typer.Typer(
    help="KuroJisho: a local, deterministic security knowledge graph.",
    no_args_is_help=True,
    add_completion=False,
)
query_app = typer.Typer(help="Read the stored graph.", no_args_is_help=True)
app.add_typer(query_app, name="query")

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
    as_json: JsonOpt = False,
) -> None:
    """Build or update the graph. Target code is parsed, never executed; no network."""
    if not path.is_dir():
        raise _fail(f"not a directory: {path}")
    store = _open(path, db, must_exist=False)
    try:
        result = scan(path, store, clock_from_env(), context_path=context, full=full)
    except (ScanError, ContextError, StoreError) as exc:
        raise _fail(str(exc)) from exc
    finally:
        store.close()
    summary = {"scan_id": result.scan_id, "commit": result.commit_sha, **result.summary()}
    table = Table(title=f"scan #{result.scan_id}", show_header=False)
    for key, value in summary.items():
        table.add_row(key, str(value))
    _emit(summary, as_json, table)
    if result.files_with_parse_errors:
        err.print(
            f"[yellow]warning:[/yellow] {len(result.files_with_parse_errors)} file(s) had syntax "
            "errors and were only partly extracted (see File.parse_error_lines)",
            highlight=False,
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
