"""Turn per-file facts plus cross-file resolution into code-layer nodes and edges."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from kurojisho.ingest.code.extract import Def, FileFacts
from kurojisho.ingest.code.resolve import Resolver, Target
from kurojisho.ingest.keys import container_id, file_id
from kurojisho.model import (
    RESOLUTION_CONFIDENCE,
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    Provenance,
    Resolution,
    node_id,
    node_key,
)

MODULE_BODY = "<module>"
DYNAMIC_TARGET = "<dynamic>"
MAX_EDGE_EVIDENCE = 25
MAX_UNRESOLVED = 200
#: A name shared by more definitions than this says nothing about which one is called.
#: Such calls become ``dynamic_unknown`` (never dropped) instead of fanning out to all of them.
MAX_NAME_MATCH_CANDIDATES = 20


@dataclass
class CodeGraph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    #: extra File-node properties contributed by the code layer, per path
    file_props: dict[str, dict[str, Any]] = field(default_factory=dict)


def def_key(path: str, definition: Def) -> str:
    kind = NodeType.CLASS if definition.kind == "class" else NodeType.FUNCTION
    return node_key(kind, path, definition.qualname)


def synthetic_key(path: str, name: str) -> str:
    return node_key(NodeType.FUNCTION, path, name)


class _Builder:
    def __init__(self, hashes: dict[str, str], facts: dict[str, FileFacts], resolver: Resolver):
        self.hashes = hashes
        self.facts = facts
        self.resolver = resolver
        self.graph = CodeGraph()
        self._synthetic: set[str] = set()

    def ev(
        self, path: str, start: int | None = None, end: int | None = None, note: str | None = None
    ) -> Evidence:
        return Evidence(
            path=path,
            source=f"tree-sitter:{self.facts[path].lang}",
            start_line=start,
            end_line=end if start is not None else None,
            content_hash=self.hashes[path],
            note=note,
        )

    def target_id(self, target: Target) -> str:
        return node_id(def_key(target.path, self.resolver.defs[target]))

    def synthetic(self, path: str, name: str) -> str:
        key = synthetic_key(path, name)
        if key not in self._synthetic:
            self._synthetic.add(key)
            dynamic = name == DYNAMIC_TARGET
            note = (
                "placeholder for call targets that cannot be determined statically"
                if dynamic
                else "module-level statements"
            )
            node = Node(
                type=NodeType.FUNCTION,
                key=key,
                name=name,
                owner_file=path,
                props={
                    "lang": self.facts[path].lang,
                    "path": path,
                    "synthetic": True,
                    "role": "dynamic_target" if dynamic else "module_body",
                },
                provenance=Provenance.INFERRED if dynamic else Provenance.EXTRACTED,
                confidence=1.0,
                evidence=(self.ev(path, note=note),),
            )
            self.graph.nodes.append(node)
            self.graph.edges.append(
                Edge(
                    type=EdgeType.DEFINES,
                    src=file_id(path),
                    dst=node.id,
                    owner_file=path,
                    provenance=node.provenance,
                    confidence=1.0,
                    evidence=node.evidence,
                )
            )
        return node_id(key)

    # -- per file -----------------------------------------------------------------------
    def build(self) -> CodeGraph:
        for path in sorted(self.facts):
            unresolved = self._calls(path)
            self._definitions(path, unresolved)
            self._routes(path)
            self._imports(path)
        return self.graph

    def _parent_id(self, path: str, definition: Def) -> str:
        if definition.parent is None:
            return file_id(path)
        local = Target(path, definition.parent)
        if local in self.resolver.defs:
            return self.target_id(local)
        scope = self.resolver.scope_key(path)
        owners = [
            t
            for t in self.resolver.members.get((scope, None, definition.parent), [])
            if self.resolver.defs[t].kind == "class"
        ]
        return self.target_id(owners[0]) if owners else file_id(path)

    def _definitions(self, path: str, unresolved: dict[str | None, list[str]]) -> None:
        facts = self.facts[path]
        for definition in facts.defs:
            span = (definition.start_line, definition.end_line)
            evidence = (self.ev(path, *span),)
            props: dict[str, Any] = {
                "lang": facts.lang,
                "path": path,
                "qualname": definition.qualname,
                "kind": definition.subkind,
                "span": list(span),
                "visibility": definition.visibility,
                "decorators": definition.decorators,
            }
            if definition.kind == "class":
                props["bases"] = definition.bases
                props["bases_unresolved"] = self._inherits(path, definition, evidence)
            else:
                props["signature"] = definition.signature
                props["is_method"] = definition.is_method
                props["calls_unresolved"] = unresolved.get(definition.qualname, [])
            node = Node(
                type=NodeType.CLASS if definition.kind == "class" else NodeType.FUNCTION,
                key=def_key(path, definition),
                name=definition.name,
                owner_file=path,
                props=props,
                provenance=Provenance.EXTRACTED,
                confidence=1.0,
                evidence=evidence,
            )
            self.graph.nodes.append(node)
            self.graph.edges.append(
                Edge(
                    type=EdgeType.DEFINES,
                    src=self._parent_id(path, definition),
                    dst=node.id,
                    owner_file=path,
                    provenance=Provenance.EXTRACTED,
                    confidence=1.0,
                    evidence=evidence,
                )
            )
        if None in unresolved:
            # Module-level calls that resolved nowhere are kept on the File node.
            self.graph.file_props.setdefault(path, {})["calls_unresolved"] = unresolved[None]

    def _inherits(self, path: str, definition: Def, evidence: tuple[Evidence, ...]) -> list[str]:
        missing = []
        src = node_id(def_key(path, definition))
        seen: set[str] = set()
        for base in definition.bases:
            targets, how = self.resolver.resolve_class(path, base, definition.parent)
            targets = tuple(t for t in targets if self.target_id(t) != src)
            if how is None or not targets:
                missing.append(base)
                continue
            if how is Resolution.NAME_MATCH and len(targets) > MAX_NAME_MATCH_CANDIDATES:
                missing.append(f"{base} ({len(targets)} candidates)")
                continue
            exact = how is Resolution.EXACT
            for target in targets:
                dst = self.target_id(target)
                if dst in seen:
                    continue
                seen.add(dst)
                same_file = target.path == path
                self.graph.edges.append(
                    Edge(
                        type=EdgeType.INHERITS,
                        src=src,
                        dst=dst,
                        owner_file=path,
                        props={"base": base, "resolution": how.value, "candidates": len(targets)},
                        provenance=Provenance.EXTRACTED if exact else Provenance.INFERRED,
                        confidence=(1.0 if same_file else 0.9)
                        if exact
                        else RESOLUTION_CONFIDENCE[Resolution.NAME_MATCH],
                        evidence=evidence,
                    )
                )
        return sorted(set(missing))

    def _routes(self, path: str) -> None:
        facts = self.facts[path]
        seen: dict[str, int] = defaultdict(int)
        for route in facts.routes:
            label = f"{route.method} {route.path}"
            seen[label] += 1
            suffix = "" if seen[label] == 1 else f"#{seen[label]}"
            evidence = (self.ev(path, route.start_line, route.end_line),)
            node = Node(
                type=NodeType.ROUTE,
                key=node_key(NodeType.ROUTE, path, label + suffix),
                name=label,
                owner_file=path,
                props={
                    "lang": facts.lang,
                    "path": path,
                    "method": route.method,
                    "path_pattern": route.path,
                    "handler": route.handler,
                    "framework": facts.framework or "unknown",
                    "span": [route.start_line, route.end_line],
                },
                provenance=Provenance.EXTRACTED,
                confidence=1.0,
                evidence=evidence,
            )
            self.graph.nodes.append(node)
            self.graph.edges.append(
                Edge(
                    type=EdgeType.DEFINES,
                    src=file_id(path),
                    dst=node.id,
                    owner_file=path,
                    provenance=Provenance.EXTRACTED,
                    confidence=1.0,
                    evidence=evidence,
                )
            )

    def _imports(self, path: str) -> None:
        internal: dict[str, list[tuple[int, str, float]]] = defaultdict(list)
        external: set[str] = set()
        for item in self.resolver.imports[path]:
            imp = item.imp
            spec = "." * imp.level + imp.module
            if not item.internal:
                external.add(spec or imp.name or "")
                continue
            targets = [file_id(f) for f in item.files if f != path]
            if item.directory is not None:
                targets.append(container_id(item.directory))
            for dst in targets:
                internal[dst].append((imp.line, spec, item.confidence))
        for dst in sorted(internal):
            sites = sorted(set(internal[dst]))
            self.graph.edges.append(
                Edge(
                    type=EdgeType.IMPORTS,
                    src=file_id(path),
                    dst=dst,
                    owner_file=path,
                    props={"modules": sorted({s for _, s, _ in sites})},
                    provenance=Provenance.EXTRACTED,
                    confidence=min(c for _, _, c in sites),
                    evidence=tuple(self.ev(path, n, n) for n in sorted({n for n, _, _ in sites})),
                )
            )
        props = self.graph.file_props.setdefault(path, {})
        props["imports_external"] = sorted(external - {""})

    def _calls(self, path: str) -> dict[str | None, list[str]]:
        """Emit CALLS edges; return unresolved callee labels per caller qualname."""
        # (caller, dst id, resolution) -> (lines, candidate count, reasons)
        grouped: dict[tuple[str | None, str, Resolution], tuple[set[int], int, set[str]]] = {}
        unresolved: dict[str | None, set[str]] = defaultdict(set)
        for call in self.facts[path].calls:
            result = self.resolver.resolve_call(path, call)
            if result.resolution is None:
                unresolved[call.caller].add(result.label or call.name)
                continue
            how, reason = result.resolution, result.reason
            too_many = len(result.targets) > MAX_NAME_MATCH_CANDIDATES
            if how is Resolution.NAME_MATCH and too_many:
                how, reason = Resolution.DYNAMIC_UNKNOWN, "too_many_candidates"
                unresolved[call.caller].add(f"{call.name} ({len(result.targets)} candidates)")
            if how is Resolution.DYNAMIC_UNKNOWN:
                destinations = [self.synthetic(path, DYNAMIC_TARGET)]
            else:
                destinations = [self.target_id(t) for t in result.targets]
            for dst in destinations:
                lines, _, reasons = grouped.setdefault(
                    (call.caller, dst, how), (set(), len(destinations), set())
                )
                lines.add(call.line)
                if reason:
                    reasons.add(reason)
        for (caller, dst, how), (lines, candidates, reasons) in sorted(
            grouped.items(), key=lambda kv: (kv[0][0] or "", kv[0][1], kv[0][2].value)
        ):
            if caller is None:
                src = self.synthetic(path, MODULE_BODY)
            else:
                src = self.target_id(Target(path, caller))
            props: dict[str, Any] = {"resolution": how.value, "call_sites": len(lines)}
            if how is Resolution.NAME_MATCH:
                props["candidates"] = candidates
            if reasons:
                props["reasons"] = sorted(reasons)
            self.graph.edges.append(
                Edge(
                    type=EdgeType.CALLS,
                    src=src,
                    dst=dst,
                    discriminator=how.value,
                    owner_file=path,
                    props=props,
                    provenance=Provenance.INFERRED,
                    confidence=RESOLUTION_CONFIDENCE[how],
                    evidence=tuple(self.ev(path, n, n) for n in sorted(lines)[:MAX_EDGE_EVIDENCE]),
                )
            )
        return {k: sorted(v)[:MAX_UNRESOLVED] for k, v in unresolved.items()}


def build_code_graph(
    hashes: dict[str, str],
    facts: dict[str, FileFacts],
    go_modules: dict[str, str] | None = None,
    python_roots: list[str] | None = None,
) -> CodeGraph:
    resolver = Resolver(facts, go_modules, python_roots)
    return _Builder(hashes, facts, resolver).build()
