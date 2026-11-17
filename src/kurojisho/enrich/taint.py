"""Taint from untrusted sources to dangerous calls, by names alone.

tree-sitter gives no types and this pass keeps no statement order, so it is a deliberate
over-approximation inside a function (a value once tainted stays tainted) and an
under-approximation across the things it cannot see: object fields, containers, callbacks
and globals. A missing flow therefore never means "safe"; triage treats it as unknown.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from kurojisho.enrich.catalogue import EXACT, NAME_ONLY, Catalogue, SanitizerSpec, SinkSpec
from kurojisho.enrich.code import Code, FuncKey
from kurojisho.enrich.entrypoints import EntryPoint
from kurojisho.ingest.code.extract import Call, Flow
from kurojisho.ingest.code.resolve import SELF_NAMES, Target
from kurojisho.model import Edge, EdgeType, Node, NodeType, Provenance, node_key

MAX_ROUNDS = 8  # passes over the whole program; deeper call chains are cut off
MAX_LOCAL_PASSES = 6
MAX_TAINTS = 24  # per value
MAX_SANITIZERS = 4  # per taint
QUALIFYING = 0.8

#: origin ("src" | "param", index), sanitizer site ids applied on the way, confidence
Taint = tuple[tuple[str, int], frozenset[int], float]
_PARAM_SOURCE = {"http": "http_param", "webhook": "body", "grpc": "body"}
_PARAM_SOURCE |= {"queue_consumer": "queue_message", "cli": "cli_arg"}


@dataclass(frozen=True)
class SourceSite:
    path: str
    func: str | None
    line: int
    kind: str
    label: str
    confidence: float


@dataclass(frozen=True)
class SinkSite:
    path: str
    func: str | None
    line: int
    ref: str
    cwe: str
    api: str
    confidence: float


@dataclass(frozen=True)
class SanitizerSite:
    path: str
    func: str | None
    line: int
    ref: str
    api: str
    protects: tuple[str, ...]
    strength: str
    confidence: float


@dataclass
class _Classified:
    sinks: list[tuple[SinkSpec, float]] = field(default_factory=list)
    sanitizer: tuple[SanitizerSpec, float] | None = None
    source: tuple[str, str, float] | None = None  # kind, label, confidence
    targets: tuple[Target, ...] = ()
    resolution: float = 0.0


@dataclass
class _Function:
    key: FuncKey
    params: list[str]
    statements: list[Call | Flow]
    env: dict[str, set[Taint]] = field(default_factory=lambda: defaultdict(set))
    results: dict[str, set[Taint]] = field(default_factory=dict)
    returns: set[Taint] = field(default_factory=set)
    #: (sink site id, taint) -> functions from where the taint entered down to the sink
    hits: dict[tuple[int, Taint], tuple[FuncKey, ...]] = field(default_factory=dict)


def _trim(taints: set[Taint]) -> set[Taint]:
    """Keep the best-supported copy of each (origin, sanitizers) and bound the set."""
    best: dict[tuple[tuple[str, int], frozenset[int]], float] = {}
    for origin, sanitizers, confidence in taints:
        key = (origin, sanitizers)
        best[key] = max(confidence, best.get(key, 0.0))
    ordered = sorted(best.items(), key=lambda kv: (kv[0][0], sorted(kv[0][1])))
    return {(k[0], k[1], c) for k, c in ordered[:MAX_TAINTS]}


class TaintAnalysis:
    def __init__(self, code: Code, entries: list[EntryPoint]) -> None:
        self.code = code
        self.sources: dict[SourceSite, int] = {}
        self.sinks: dict[SinkSite, int] = {}
        self.sanitizers: dict[SanitizerSite, int] = {}
        self._classified: dict[tuple[str, str], _Classified] = {}
        self._functions: dict[FuncKey, _Function] = {}
        self._handler_kinds: dict[FuncKey, tuple[str, float]] = {}
        for entry in entries:
            kind = _PARAM_SOURCE.get(entry.kind)
            if kind is None:
                continue
            for key, confidence in entry.handlers.items():
                known = self._handler_kinds.get(key)
                if known is None or confidence > known[1]:
                    self._handler_kinds[key] = (kind, confidence)

    # -- site registries ----------------------------------------------------------------
    def _source(self, site: SourceSite) -> int:
        return self.sources.setdefault(site, len(self.sources))

    def _sink(self, site: SinkSite) -> int:
        return self.sinks.setdefault(site, len(self.sinks))

    def _sanitizer(self, site: SanitizerSite) -> int:
        return self.sanitizers.setdefault(site, len(self.sanitizers))

    # -- classification -----------------------------------------------------------------
    def _classify(self, path: str, call: Call, catalogue: Catalogue | None) -> _Classified:
        cached = self._classified.get((path, call.ref))
        if cached is not None:
            return cached
        out = _Classified()
        out.targets, out.resolution = self.code.resolve(path, call)
        if catalogue is not None:
            full = f"{call.receiver}.{call.name}" if call.receiver else call.name
            qualified = self.code.qualify(path, full)
            first_party = out.resolution >= EXACT
            bare = not call.receiver and call.name not in self.code.aliases(path)

            def match(spec: SinkSpec | SanitizerSpec) -> float:
                if spec.api is not None:
                    return EXACT if qualified == spec.api else 0.0
                if spec.builtin is not None:
                    return EXACT if bare and not out.targets and call.name == spec.builtin else 0.0
                # A bare name says little; if the call lands in our own code we follow it
                # instead of guessing what it does.
                return NAME_ONLY if call.name == spec.name and not first_party else 0.0

            for sink in catalogue.sinks:
                confidence = match(sink)
                if confidence:
                    out.sinks.append((sink, confidence))
            for sanitizer in catalogue.sanitizers:
                confidence = match(sanitizer)
                if confidence:
                    out.sanitizer = (sanitizer, confidence)
                    break
            for source in catalogue.sources:
                if source.call and call.name == source.name and not first_party:
                    out.source = (source.kind, f"{call.name}()", NAME_ONLY)
                    break
        self._classified[(path, call.ref)] = out
        return out

    def _name_source(self, path: str, atom: str, catalogue: Catalogue) -> tuple[str, float] | None:
        qualified = self.code.qualify(path, atom)
        for spec in catalogue.sources:
            if spec.call:
                continue
            if spec.api is not None:
                if qualified is not None and (
                    qualified == spec.api or qualified.startswith(spec.api + ".")
                ):
                    return spec.kind, EXACT
            elif spec.name is not None and (atom == spec.name or atom.startswith(spec.name + ".")):
                return spec.kind, NAME_ONLY
        return None

    # -- per function -------------------------------------------------------------------
    def _load(self) -> None:
        for path in sorted(self.code.facts):
            facts = self.code.facts[path]
            grouped: dict[str | None, list[Call | Flow]] = defaultdict(list)
            for call in facts.calls:
                grouped[call.caller].append(call)
            for flow in facts.flows:
                grouped[flow.func].append(flow)
            catalogue = self.code.catalogue(path)
            ignore = set(catalogue.ignore_params) if catalogue else set()
            for qualname in sorted(grouped, key=lambda q: q or ""):
                key = (path, qualname)
                definition = self.code.definition(key)
                params = definition.params if definition is not None else []
                statements = sorted(grouped[qualname], key=_order)
                function = _Function(key, params, statements)
                handler = self._handler_kinds.get(key)
                for index, param in enumerate(params):
                    function.env[param].add((("param", index), frozenset(), 1.0))
                    if handler is not None and param not in ignore and definition is not None:
                        confidence = min(EXACT, handler[1])
                        site = SourceSite(
                            path,
                            qualname,
                            definition.start_line,
                            handler[0],
                            f"param:{param}",
                            confidence,
                        )
                        function.env[param].add(
                            (("src", self._source(site)), frozenset(), confidence)
                        )
                self._functions[key] = function

    def _read(self, function: _Function, atoms: list[str], line: int) -> set[Taint]:
        path, qualname = function.key
        catalogue = self.code.catalogue(path)
        out: set[Taint] = set()
        for atom in atoms:
            if atom.startswith("@"):
                out |= function.results.get(atom, set())
                continue
            parts = atom.split(".")
            for size in range(1, len(parts) + 1):
                out |= function.env.get(".".join(parts[:size]), set())
            prefix = atom + "."
            for name, taints in function.env.items():
                if name.startswith(prefix):
                    out |= taints
            if catalogue is not None:
                found = self._name_source(path, atom, catalogue)
                if found is not None:
                    site = SourceSite(path, qualname, line, found[0], atom, found[1])
                    out.add((("src", self._source(site)), frozenset(), found[1]))
        return out

    def _call(self, function: _Function, call: Call) -> set[Taint]:
        path, qualname = function.key
        catalogue = self.code.catalogue(path)
        info = self._classify(path, call, catalogue)
        args = [self._read(function, atoms, call.line) for atoms in call.args]
        base = self._read(function, call.base, call.line)
        everything = set(base).union(*args) if args else set(base)

        for spec, confidence in info.sinks:
            if not spec.receiver and not call.args:
                continue  # nothing is passed in: not the dangerous form of this call
            site = self._sink(
                SinkSite(path, qualname, call.line, call.ref, spec.cwe, spec.label, confidence)
            )
            reaching: set[Taint] = set(base) if spec.receiver else set()
            if spec.args is None and not spec.receiver:
                reaching = reaching.union(*args)
            for index in spec.args or ():
                if index < len(args):
                    reaching |= args[index]
            for taint in reaching:
                function.hits.setdefault((site, taint), (function.key,))

        if info.sanitizer is not None:
            spec_, confidence = info.sanitizer
            site = self._sanitizer(
                SanitizerSite(
                    path,
                    qualname,
                    call.line,
                    call.ref,
                    spec_.label,
                    spec_.protects,
                    spec_.strength,
                    confidence,
                )
            )
            return {
                (origin, frozenset(sorted(applied | {site})[:MAX_SANITIZERS]), c)
                for origin, applied, c in everything
            }

        result: set[Taint] = set()
        if info.source is not None:
            kind, label, confidence = info.source
            source = SourceSite(path, qualname, call.line, kind, label, confidence)
            result.add((("src", self._source(source)), frozenset(), confidence))
        for target in info.targets:
            callee = self._functions.get((target.path, target.qualname))
            if callee is None:
                continue
            offset = _self_offset(self.code, target, callee.params, len(args))

            def bind(taint: Taint, offset: int = offset) -> set[Taint]:
                origin, applied, confidence = taint
                if origin[0] == "src":
                    return {(origin, applied, min(confidence, info.resolution))}
                index = origin[1] - offset
                if not 0 <= index < len(args):
                    return set()
                return {
                    (o, a | applied, min(c, confidence, info.resolution)) for o, a, c in args[index]
                }

            for taint in callee.returns:
                result |= bind(taint)
            for (site, taint), via in list(callee.hits.items()):
                if taint[0][0] != "param" or function.key in via:
                    continue
                for bound in bind(taint):
                    function.hits.setdefault((site, bound), (function.key, *via))
        if not info.targets or info.resolution < EXACT:
            result |= everything  # unknown code: assume it passes its inputs through
        return result

    def _run(self, function: _Function) -> bool:
        before = (len(function.returns), len(function.hits))
        for _ in range(MAX_LOCAL_PASSES):
            changed = False
            for statement in function.statements:
                if isinstance(statement, Call):
                    result = _trim(self._call(function, statement))
                    if result != function.results.get(statement.ref):
                        function.results[statement.ref] = result
                        changed = True
                    continue
                taints = self._read(function, statement.atoms, statement.line)
                if statement.kind == "return":
                    merged = _trim(function.returns | taints)
                    if merged != function.returns:
                        function.returns = merged
                        changed = True
                    continue
                for target in statement.targets:
                    merged = _trim(function.env[target] | taints)
                    if merged != function.env[target]:
                        function.env[target] = merged
                        changed = True
            if not changed:
                break
        return before != (len(function.returns), len(function.hits))

    def run(self) -> TaintAnalysis:
        self._load()
        for _ in range(MAX_ROUNDS):
            changed = False
            for key in sorted(self._functions, key=lambda k: (k[0], k[1] or "")):
                changed |= self._run(self._functions[key])
            if not changed:
                break
        return self

    # -- graph --------------------------------------------------------------------------
    def build(self) -> tuple[list[Node], list[Edge]]:
        code = self.code
        nodes: list[Node] = []
        edges: list[Edge] = []
        source_at = {index: site for site, index in self.sources.items()}
        sanitizer_at = {index: site for site, index in self.sanitizers.items()}
        sink_nodes: dict[int, Node] = {}
        source_nodes: dict[int, Node] = {}

        def located(node: Node, key: FuncKey, path: str) -> None:
            nodes.append(node)
            edges.append(
                Edge(
                    type=EdgeType.LOCATED_IN,
                    src=node.id,
                    dst=code.func_id(key),
                    owner_file=path,
                    props={"by": "span"},
                    provenance=node.provenance,
                    confidence=node.confidence,
                    evidence=node.evidence,
                )
            )

        for sink, index in self.sinks.items():
            exact = sink.confidence >= EXACT
            sink_nodes[index] = Node(
                type=NodeType.SINK,
                key=node_key(NodeType.SINK, sink.path, sink.ref, sink.cwe, sink.api),
                name=sink.api,
                owner_file=sink.path,
                props={
                    "cwe": sink.cwe,
                    "api": sink.api,
                    "path": sink.path,
                    "line": sink.line,
                    "function": sink.func,
                    "match": "exact" if exact else "name",
                },
                provenance=Provenance.EXTRACTED if exact else Provenance.INFERRED,
                confidence=sink.confidence,
                evidence=(code.ev(sink.path, sink.line, note=f"sink:{sink.api}"),),
            )
            located(sink_nodes[index], (sink.path, sink.func), sink.path)

        # (source id, sink id) -> every way the taint got there
        paths: dict[tuple[int, int], list[tuple[frozenset[int], float, tuple[FuncKey, ...]]]]
        paths = defaultdict(list)
        for function in self._functions.values():
            for (sink_id, (origin, applied, confidence)), via in function.hits.items():
                if origin[0] == "src":
                    paths[(origin[1], sink_id)].append((applied, confidence, via))

        used_sanitizers: set[int] = set()
        sink_site = {index: site for site, index in self.sinks.items()}
        for source_id, sink_id in sorted(paths):
            source, sink = source_at[source_id], sink_site[sink_id]
            if source_id not in source_nodes:
                exact = source.confidence >= EXACT
                source_nodes[source_id] = Node(
                    type=NodeType.SOURCE,
                    key=node_key(
                        NodeType.SOURCE,
                        source.path,
                        source.func or "<module>",
                        str(source.line),
                        source.label,
                    ),
                    name=source.label,
                    owner_file=source.path,
                    props={
                        "kind": source.kind,
                        "label": source.label,
                        "path": source.path,
                        "line": source.line,
                        "function": source.func,
                        "match": "exact" if exact else "name",
                    },
                    provenance=Provenance.INFERRED,
                    confidence=source.confidence,
                    evidence=(code.ev(source.path, source.line, note=f"source:{source.label}"),),
                )
                located(source_nodes[source_id], (source.path, source.func), source.path)
            ways = sorted(
                paths[(source_id, sink_id)], key=lambda w: (len(w[2]), w[2], sorted(w[0]))
            )
            strong: list[float] = []  # per way: confidence of its best strong sanitizer
            applied_all: set[int] = set()
            for applied, _, _ in ways:
                applied_all |= applied
                best = [
                    sanitizer_at[s].confidence
                    for s in applied
                    if sanitizer_at[s].strength == "strong" and sink.cwe in sanitizer_at[s].protects
                ]
                strong.append(max(best) if best else 0.0)
            relevant = sorted(s for s in applied_all if sink.cwe in sanitizer_at[s].protects)
            used_sanitizers |= set(relevant)
            all_strong = all(strong)
            confidence = min(max(w[1] for w in ways), sink.confidence)
            edges.append(
                Edge(
                    type=EdgeType.FLOWS_TO,
                    src=source_nodes[source_id].id,
                    dst=sink_nodes[sink_id].id,
                    owner_file=sink.path,
                    props={
                        "cwe": sink.cwe,
                        "source_kind": source.kind,
                        "via": [f"{p}::{q or '<module>'}" for p, q in ways[0][2]],
                        "ways": len(ways),
                        "sanitized_by": sorted({sanitizer_at[s].api for s in relevant}),
                        "sanitized": "strong" if all_strong else "partial" if relevant else "none",
                        # 0.0 unless every way passes a strong sanitizer for this weakness
                        "sanitizer_confidence": min(strong) if all_strong else 0.0,
                    },
                    provenance=Provenance.INFERRED,
                    confidence=confidence,
                    evidence=(
                        code.ev(source.path, source.line, note=f"source:{source.label}"),
                        code.ev(sink.path, sink.line, note=f"sink:{sink.api}"),
                    ),
                )
            )
        for index in sorted(used_sanitizers):
            site = sanitizer_at[index]
            exact = site.confidence >= EXACT
            node = Node(
                type=NodeType.SANITIZER,
                key=node_key(NodeType.SANITIZER, site.path, site.ref, site.api),
                name=site.api,
                owner_file=site.path,
                props={
                    "api": site.api,
                    "protects_cwe": list(site.protects),
                    "strength": site.strength,
                    "path": site.path,
                    "line": site.line,
                    "function": site.func,
                    "match": "exact" if exact else "name",
                },
                provenance=Provenance.EXTRACTED if exact else Provenance.INFERRED,
                confidence=site.confidence,
                evidence=(code.ev(site.path, site.line, note=f"sanitizer:{site.api}"),),
            )
            located(node, (site.path, site.func), site.path)
        return nodes, edges


def _order(statement: Call | Flow) -> tuple[int, int, int]:
    """Inner calls end before the calls and assignments that use them."""
    if isinstance(statement, Call):
        end = int(statement.ref.rpartition(":")[2] or 0) if statement.ref else 0
        return (statement.line, 0, end)
    return (statement.line, 1, 0)


def _self_offset(code: Code, target: Target, params: list[str], argc: int) -> int:
    names = SELF_NAMES.get(code.family(target.path), set())
    return 1 if params and params[0] in names and argc < len(params) else 0
