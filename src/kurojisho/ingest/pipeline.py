"""Scan orchestration: walk, extract (only what changed), resolve, diff into the store."""

from __future__ import annotations

import hashlib
import posixpath
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Protocol

from kurojisho import __version__
from kurojisho.clock import Clock, isoformat
from kurojisho.config.context import CONTEXT_FILENAME, Context, load_context
from kurojisho.deploy.graph import build_deploy
from kurojisho.deploy.parse import classify, parse_deploy
from kurojisho.enrich import enrich
from kurojisho.enrich.catalogue import catalogue_version
from kurojisho.enrich.symbols import build_symbols
from kurojisho.ingest.assets import build_assets
from kurojisho.ingest.code.build import build_code_graph
from kurojisho.ingest.code.extract import FileFacts
from kurojisho.ingest.code.parser import EXTRACTOR_VERSION, MAX_SOURCE_BYTES, extract
from kurojisho.ingest.deps import MAX_MANIFEST_BYTES, manifest_kind, parse_manifests
from kurojisho.ingest.deps.graph import build_packages
from kurojisho.ingest.keys import REPO_KEY, container_id, container_key, file_id, file_key
from kurojisho.ingest.walker import FileEntry, WalkResult, read_git_head, walk
from kurojisho.model import Edge, EdgeType, Evidence, Node, NodeType, Provenance
from kurojisho.remediate.build import build_remediations
from kurojisho.store import Store, WriteStats
from kurojisho.triage import triage

WALKER = "walker"


class ScanError(RuntimeError):
    """The scan could not start. Nothing has been written."""


class Scrubs(Protocol):
    """Anything that can remove known secret values before data is persisted."""

    def text(self, value: str) -> str: ...
    def node(self, node: Node) -> Node: ...
    def edge(self, edge: Edge) -> Edge: ...


@dataclass
class IngestState:
    """What ingest built, handed to an extension before anything is written."""

    root: Path
    entries: dict[str, FileEntry]
    hashes: dict[str, str]
    nodes: list[Node]
    edges: list[Edge]
    result: ScanResult


@dataclass
class Extension:
    """Extra graph content (findings, coverage gaps) to commit in the same transaction."""

    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    scrubber: Scrubs | None = None
    after_apply: Callable[[Store, int], None] | None = None


@dataclass
class ScanResult:
    scan_id: int
    commit_sha: str | None
    tree_hash: str
    files_total: int
    files_parsed: list[str] = field(default_factory=list)
    files_from_cache: int = 0
    files_with_parse_errors: list[str] = field(default_factory=list)
    writes: WriteStats = field(default_factory=WriteStats)

    def summary(self) -> dict[str, Any]:
        return {
            "files_total": self.files_total,
            "files_parsed": len(self.files_parsed),
            "files_from_cache": self.files_from_cache,
            "files_with_parse_errors": len(self.files_with_parse_errors),
            **asdict(self.writes),
        }


def _read_text(entry: FileEntry, limit: int) -> str | None:
    if entry.size > limit:
        return None
    try:
        return entry.abs_path.read_bytes().decode("utf-8", "replace")
    except OSError:
        return None


def _load_context(
    root: Path, explicit: Path | None, entries: dict[str, FileEntry]
) -> tuple[Context, str, str]:
    """Returns (context, evidence path, content hash). Raises before anything is written."""
    if explicit is None and CONTEXT_FILENAME not in entries:
        return Context(), "", ""
    path = explicit or root / CONTEXT_FILENAME
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ScanError(f"cannot read context file {path}") from exc
    try:
        label = path.resolve().relative_to(root).as_posix()
    except ValueError:
        label = f"<external>/{path.name}"
    context = load_context(raw.decode("utf-8", "replace"), label)
    return context, label, hashlib.sha256(raw).hexdigest()


def _extract_all(
    walked: WalkResult, cache: dict[str, tuple[str, str]], result: ScanResult
) -> tuple[dict[str, FileEntry], dict[str, FileFacts], dict[str, str]]:
    """Facts for every parseable source file, re-parsing only files whose hash changed."""
    entries: dict[str, FileEntry] = {}
    facts: dict[str, FileFacts] = {}
    skipped: dict[str, str] = {}
    for entry in walked.files:
        entries[entry.path] = entry
        lang = entry.lang
        if lang is None:
            continue
        if entry.size > MAX_SOURCE_BYTES:
            skipped[entry.path] = "too_large"
            continue
        cached = cache.get(entry.path)
        if cached is not None and cached[0] == entry.content_hash:
            facts[entry.path] = FileFacts.from_json(cached[1])
            result.files_from_cache += 1
            continue
        try:
            source = entry.abs_path.read_bytes()
        except OSError:
            skipped[entry.path] = "unreadable"
            continue
        # The file may have changed since it was hashed; the bytes parsed are the truth.
        entry = replace(entry, content_hash=hashlib.sha256(source).hexdigest(), size=len(source))
        entries[entry.path] = entry
        facts[entry.path] = extract(lang, source)
        result.files_parsed.append(entry.path)
    return entries, facts, skipped


def _structure(
    root: Path,
    walked: WalkResult,
    entries: dict[str, FileEntry],
    facts: dict[str, FileFacts],
    skipped: dict[str, str],
    code_props: dict[str, dict[str, Any]],
    manifest_notes: dict[str, list[str]],
    context_label: str,
) -> tuple[list[Node], list[Edge]]:
    """Repo, Module and File nodes with their CONTAINS edges."""
    nodes: list[Node] = []
    edges: list[Edge] = []
    languages = Counter(e.lang for e in entries.values() if e.lang)
    nodes.append(
        Node(
            type=NodeType.REPO,
            key=REPO_KEY,
            name=root.name,
            props={
                "name": root.name,
                "languages": dict(sorted(languages.items())),
                "context_file": context_label or None,
                # Everything the walker did not read is listed: an unread path is a gap.
                "skipped_dirs": walked.skipped_dirs,
                "skipped_links": walked.skipped_links,
                "skipped_special": walked.skipped_special,
                "unreadable": walked.unreadable,
            },
            provenance=Provenance.EXTRACTED,
            confidence=1.0,
            evidence=(Evidence(path=".", source=WALKER),),
        )
    )
    directories: set[str] = set()
    for path in entries:
        current = posixpath.dirname(path)
        while current and current not in directories:
            directories.add(current)
            current = posixpath.dirname(current)

    def contains(parent: str, child_id: str, evidence: Evidence, owner: str | None) -> None:
        edges.append(
            Edge(
                type=EdgeType.CONTAINS,
                src=container_id(parent),
                dst=child_id,
                owner_file=owner,
                provenance=Provenance.EXTRACTED,
                confidence=1.0,
                evidence=(evidence,),
            )
        )

    for directory in sorted(directories):
        evidence = Evidence(path=directory, source=WALKER)
        node = Node(
            type=NodeType.MODULE,
            key=container_key(directory),
            name=posixpath.basename(directory),
            props={"path": directory},
            provenance=Provenance.EXTRACTED,
            confidence=1.0,
            evidence=(evidence,),
        )
        nodes.append(node)
        contains(posixpath.dirname(directory), node.id, evidence, None)
    for path in sorted(entries):
        entry = entries[path]
        props: dict[str, Any] = {
            "path": path,
            "lang": entry.lang,
            "size": entry.size,
            "content_hash": entry.content_hash,
        }
        if entry.lang is not None:
            file_facts = facts.get(path)
            if file_facts is None:
                props["parse_status"] = "skipped"
                props["parse_skip_reason"] = skipped.get(path, "unknown")
            else:
                errors = file_facts.parse_error_lines
                props["parse_status"] = "partial" if errors else "ok"
                props["parse_error_lines"] = errors
                props["extraction_notes"] = file_facts.notes
                props["package"] = file_facts.package or None
        props.update(code_props.get(path, {}))
        kind = manifest_kind(path)
        if kind is not None:
            props["manifest"] = kind
            props["manifest_notes"] = manifest_notes.get(path, [])
        evidence = Evidence(path=path, source=WALKER, content_hash=entry.content_hash)
        nodes.append(
            Node(
                type=NodeType.FILE,
                key=file_key(path),
                name=posixpath.basename(path),
                owner_file=path,
                props=props,
                provenance=Provenance.EXTRACTED,
                confidence=1.0,
                evidence=(evidence,),
            )
        )
        contains(posixpath.dirname(path), file_id(path), evidence, path)
    return nodes, edges


def scan(
    root: Path,
    store: Store,
    clock: Clock,
    *,
    context_path: Path | None = None,
    full: bool = False,
    extend: Callable[[IngestState], Extension] | None = None,
) -> ScanResult:
    """Bring the stored graph in line with the tree at ``root``.

    Only files whose content hash changed are parsed. The whole graph is then rebuilt in
    memory from cached facts and diffed against the store, so an unchanged tree writes no
    node or edge rows and an incremental scan always equals a fresh one.
    """
    root = root.resolve()
    if not root.is_dir():
        raise ScanError(f"not a directory: {root}")
    walked = walk(root)
    reuse = not full and store.get_meta("extractor_version") == EXTRACTOR_VERSION
    cache = store.cached_files()
    result = ScanResult(0, read_git_head(root), "", len(walked.files))
    entries, facts, skipped = _extract_all(walked, cache if reuse else {}, result)
    walked.files = [entries[e.path] for e in walked.files]
    result.tree_hash = walked.tree_hash()
    result.files_with_parse_errors = sorted(p for p, f in facts.items() if f.parse_error_lines)
    context, context_label, context_hash = _load_context(root, context_path, entries)

    hashes = {path: entry.content_hash for path, entry in entries.items()}
    manifests = parse_manifests(
        sorted(entries), lambda p: _read_text(entries[p], MAX_MANIFEST_BYTES)
    )
    code = build_code_graph(hashes, facts, manifests.go_modules, manifests.python_roots)
    nodes, edges = _structure(
        root, walked, entries, facts, skipped, code.file_props, manifests.notes, context_label
    )
    package_nodes, package_edges = build_packages(manifests.deps, hashes)
    asset_nodes, asset_edges = build_assets(context, context_label, context_hash, sorted(entries))
    enriched = enrich(code, facts, hashes)
    deploy_files = {
        p: _read_text(entries[p], MAX_MANIFEST_BYTES) for p in sorted(entries) if classify(p)
    }
    code_dirs = {posixpath.dirname(p) for p, e in entries.items() if e.lang}
    deploy_nodes, deploy_edges = build_deploy(
        parse_deploy(deploy_files), context, sorted(entries), hashes, code_dirs
    )
    nodes += code.nodes + package_nodes + asset_nodes + enriched.nodes + deploy_nodes
    edges += code.edges + package_edges + asset_edges + enriched.edges + deploy_edges

    extension = Extension()
    if extend is not None:
        extension = extend(IngestState(root, entries, hashes, nodes, edges, result))
        nodes += extension.nodes
        edges += extension.edges
    symbol_nodes, symbol_edges = build_symbols(enriched.code, nodes, edges)
    nodes += symbol_nodes
    edges += symbol_edges
    nodes = triage(nodes, edges, context, bool(context_label))
    fix_nodes, fix_edges = build_remediations(nodes)
    nodes += fix_nodes
    edges += fix_edges
    scrub = extension.scrubber
    if scrub is not None:
        # A secret a scanner found may also sit in something ingest extracted.
        cleaned = [scrub.node(n) for n in nodes]
        moved = {
            old.id: new.id for old, new in zip(nodes, cleaned, strict=True) if old.id != new.id
        }
        nodes = cleaned
        edges = [scrub.edge(e) for e in edges]
        if moved:  # a scrubbed key changes the node id; keep edges attached
            edges = [
                e.model_copy(
                    update={"src": moved.get(e.src, e.src), "dst": moved.get(e.dst, e.dst)}
                )
                for e in edges
            ]

    with store.transaction():
        result.scan_id = store.begin_scan(
            commit_sha=result.commit_sha,
            tree_hash=result.tree_hash,
            started_at=isoformat(clock.now()),
            tool_version=__version__,
        )
        result.writes = store.apply(nodes, edges, result.scan_id)
        for path in result.files_parsed:
            cached = facts[path].to_json()
            store.put_file(path, hashes[path], scrub.text(cached) if scrub else cached)
        for path in sorted(set(cache) - set(facts)):
            store.delete_file(path)
        store.set_meta("extractor_version", EXTRACTOR_VERSION)
        store.set_meta("catalogue_version", catalogue_version())
        if extension.after_apply is not None:
            extension.after_apply(store, result.scan_id)
        store.finish_scan(result.scan_id, result.summary())
    return result
