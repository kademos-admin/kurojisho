"""EntryPoint nodes, the functions that handle them, and the controls that guard them."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from kurojisho.enrich.catalogue import EXACT, NAME_ONLY, Catalogue, ControlSpec, glob
from kurojisho.enrich.code import MAX_CANDIDATES, Code, FuncKey
from kurojisho.ingest.code.extract import Call, Def, RouteFact
from kurojisho.ingest.code.resolve import Target
from kurojisho.model import Edge, EdgeType, Node, NodeType, Provenance, node_key

#: Kinds an outside party can call. The rest (cli, queue, cron) start inside the system.
EXTERNAL_KINDS = frozenset({"http", "webhook", "grpc", "mcp_tool", "llm_tool"})
_VIEW_METHODS = ("delete", "dispatch", "get", "patch", "post", "put")
_WEBHOOK_MARKS = ("webhook", "/hooks/", "/hook/")
INLINE_HANDLER = 0.7  # an anonymous callback: we know the scope it was written in


@dataclass(frozen=True)
class ControlHit:
    kind: str
    label: str
    confidence: float
    where: str
    line: int


@dataclass
class EntryPoint:
    path: str
    kind: str
    method: str
    pattern: str
    line: int
    end_line: int
    confidence: float
    framework: str = ""
    handler: str | None = None
    handlers: dict[FuncKey, float] = field(default_factory=dict)
    middleware: tuple[str, ...] = ()
    controls: list[ControlHit] = field(default_factory=list)
    key: str = ""

    @property
    def external(self) -> bool:
        return self.kind in EXTERNAL_KINDS

    @property
    def auth(self) -> tuple[str, float]:
        """(``true`` / ``false`` / ``unknown``, confidence). Absence of a control we know is
        not evidence of no control, so the default is ``unknown``."""
        guards = [c.confidence for c in self.controls if c.kind in ("authn", "authz")]
        if guards:
            return "true", max(guards)
        anonymous = [c.confidence for c in self.controls if c.kind == "anonymous"]
        if anonymous:
            return "false", max(anonymous)
        return "unknown", 0.0


def _head(decorator: str) -> str:
    return decorator.split("(", 1)[0].strip()


def _route_handlers(code: Code, path: str, route: RouteFact) -> dict[FuncKey, float]:
    resolver = code.resolver
    if route.handler is None:
        return {(path, route.scope): INLINE_HANDLER}
    if Target(path, route.handler) in resolver.defs:
        return {(path, route.handler): 1.0}
    head, _, last = route.handler.rpartition(".")
    call = Call(route.scope, "attr" if head else "name", last, route.start_line, head, -1)
    targets, confidence = code.resolve(path, call)
    out: dict[FuncKey, float] = {}
    for target in targets:
        if resolver.defs[target].name not in ("__init__", "constructor", "<init>"):
            out[(target.path, target.qualname)] = confidence
    if out:
        return out
    # A class used as a view (Django ``View.as_view()``): its verb methods handle the route.
    classes, how = resolver.resolve_class(path, route.handler, route.scope)
    for cls in classes if how is not None else ():
        scope = resolver.scope_key(cls.path)
        for name in _VIEW_METHODS:
            for method in resolver.members.get((scope, cls.qualname, name), []):
                out[(method.path, method.qualname)] = 0.9 if len(classes) == 1 else NAME_ONLY
    if out or not head:
        return out
    # ``handlers.update`` where ``handlers`` is an object built at runtime: all that is
    # left is the method name. Every same-named function is a candidate, as a guess.
    family = code.family(path)
    named = sorted(
        {*resolver.methods.get((family, last), []), *resolver.functions.get((family, last), [])}
    )
    if len(named) <= MAX_CANDIDATES:
        out = {(t.path, t.qualname): NAME_ONLY for t in named}
    return out


def _from_routes(code: Code, path: str) -> list[EntryPoint]:
    facts = code.facts[path]
    out = []
    for route in facts.routes:
        lowered = route.path.lower()
        kind = "webhook" if any(mark in lowered for mark in _WEBHOOK_MARKS) else "http"
        out.append(
            EntryPoint(
                path=path,
                kind=kind,
                method=route.method,
                pattern=route.path,
                line=route.start_line,
                end_line=route.end_line,
                confidence=1.0,
                framework=facts.framework or "unknown",
                handler=route.handler,
                handlers=_route_handlers(code, path, route),
                middleware=tuple(route.middleware),
            )
        )
    return out


def _from_catalogue(code: Code, path: str, catalogue: Catalogue) -> list[EntryPoint]:
    facts = code.facts[path]
    out = []
    for definition in facts.defs:
        if definition.kind != "function":
            continue
        heads = [_head(d) for d in definition.decorators]
        best: tuple[float, str] | None = None
        for spec in catalogue.entrypoints:
            confidence = 0.0
            if spec.api is not None:
                if any(code.qualify(path, h) == spec.api for h in heads):
                    confidence = EXACT
            elif spec.name is not None:
                if any(glob(spec.name, h) for h in heads):
                    confidence = NAME_ONLY
            elif spec.function == definition.name:
                package_ok = spec.package is None or facts.package == spec.package
                signature_ok = spec.signature is None or glob(spec.signature, definition.signature)
                if package_ok and signature_ok:
                    confidence = EXACT
            if confidence and (best is None or confidence > best[0]):
                best = (confidence, spec.kind)
        if best is not None:
            out.append(
                EntryPoint(
                    path=path,
                    kind=best[1],
                    method="",
                    pattern=definition.qualname,
                    line=definition.start_line,
                    end_line=definition.start_line,
                    confidence=best[0],
                    framework=facts.framework or "",
                    handler=definition.qualname,
                    handlers={(path, definition.qualname): 1.0},
                )
            )
    return out


# -- controls ---------------------------------------------------------------------------
def _match(code: Code, path: str, spec: ControlSpec, text: str, where: str) -> float:
    if where == "signature":
        return NAME_ONLY if spec.signature is not None and glob(spec.signature, text) else 0.0
    if spec.api is not None:
        return EXACT if code.qualify(path, text) == spec.api else 0.0
    if spec.name is not None:
        subject = text if "." in spec.name else text.rpartition(".")[2]
        return NAME_ONLY if glob(spec.name, subject) else 0.0
    return 0.0


def _global_middleware(code: Code, path: str) -> list[tuple[str, int]]:
    """Names passed to ``app.use(...)`` / ``router.Use(...)`` anywhere in the file."""
    by_ref = {c.ref: c for c in code.facts[path].calls}
    out = []
    for call in code.facts[path].calls:
        if call.kind != "attr" or call.name not in ("use", "Use"):
            continue
        for atoms in call.args:
            for atom in atoms:
                inner = by_ref.get(atom)
                if inner is not None:
                    name = f"{inner.receiver}.{inner.name}" if inner.receiver else inner.name
                    out.append((name, call.line))
                elif not atom.startswith("@"):
                    out.append((atom, call.line))
    return out


def _controls(code: Code, entry: EntryPoint, catalogue: Catalogue) -> list[ControlHit]:
    candidates: list[tuple[str, str, int, str]] = []  # text, where, line, file
    for path, qualname in sorted(entry.handlers, key=lambda k: (k[0], k[1] or "")):
        definition: Def | None = code.definition((path, qualname))
        if definition is None:
            continue
        owners = [definition]
        if definition.parent:
            parent = code.definition((path, definition.parent))
            if parent is not None:
                owners.append(parent)
        for owner in owners:
            for decorator in owner.decorators:
                candidates.append((_head(decorator), "decorator", owner.start_line, path))
                # NestJS-style ``UseGuards(AuthGuard)``: the argument names the control too.
                inner = decorator.partition("(")[2].rstrip(")").strip()
                if inner and inner.replace(".", "").replace("_", "").isalnum():
                    candidates.append((inner, "decorator", owner.start_line, path))
        candidates.append((definition.signature, "signature", definition.start_line, path))
    for name in entry.middleware:
        candidates.append((name, "middleware", entry.line, entry.path))
    if entry.kind in ("http", "webhook"):
        for name, line in _global_middleware(code, entry.path):
            candidates.append((name, "global", line, entry.path))
    hits: dict[tuple[str, str], ControlHit] = {}
    for text, where, line, path in candidates:
        if not text:
            continue
        for spec in catalogue.controls:
            confidence = _match(code, path, spec, text, where)
            if where == "global":  # registration order relative to the route is not checked
                confidence = min(confidence, NAME_ONLY)
            if not confidence:
                continue
            label = text if where != "signature" else spec.label
            hit = ControlHit(spec.kind, label, confidence, where, line)
            previous = hits.get((spec.kind, label))
            if previous is None or confidence > previous.confidence:
                hits[(spec.kind, label)] = hit
    return sorted(hits.values(), key=lambda h: (h.kind, h.label))


def find_entrypoints(code: Code) -> list[EntryPoint]:
    found: list[EntryPoint] = []
    for path in sorted(code.facts):
        catalogue = code.catalogue(path)
        entries = _from_routes(code, path)
        if catalogue is not None:
            entries += _from_catalogue(code, path, catalogue)
        seen: dict[str, int] = defaultdict(int)
        for entry in entries:
            if catalogue is not None:
                entry.controls = _controls(code, entry, catalogue)
            label = " ".join(p for p in (entry.kind, entry.method, entry.pattern) if p)
            seen[label] += 1
            suffix = "" if seen[label] == 1 else f"#{seen[label]}"
            entry.key = node_key(NodeType.ENTRY_POINT, path, label + suffix)
        found += entries
    return found


def build_entrypoints(code: Code, entries: list[EntryPoint]) -> tuple[list[Node], list[Edge]]:
    nodes: list[Node] = []
    edges: list[Edge] = []
    controls: dict[str, Node] = {}
    for entry in entries:
        auth, auth_confidence = entry.auth
        evidence = (code.ev(entry.path, entry.line, entry.end_line),)
        from_route = entry.kind in ("http", "webhook")
        node = Node(
            type=NodeType.ENTRY_POINT,
            key=entry.key,
            name=" ".join(p for p in (entry.method, entry.pattern) if p),
            owner_file=entry.path,
            props={
                "kind": entry.kind,
                "method": entry.method or None,
                "path_pattern": entry.pattern,
                "path": entry.path,
                "external": entry.external,
                "framework": entry.framework or None,
                "handler": entry.handler,
                "handler_resolved": bool(entry.handlers),
                "auth_required": auth,
                "auth_confidence": auth_confidence,
                "controls": sorted({c.kind for c in entry.controls}),
            },
            provenance=Provenance.EXTRACTED if from_route else Provenance.INFERRED,
            confidence=entry.confidence,
            evidence=evidence,
        )
        nodes.append(node)
        targets: dict[str, float] = {}
        for key, confidence in entry.handlers.items():
            dst = code.func_id(key)
            targets[dst] = max(confidence, targets.get(dst, 0.0))
        for dst in sorted(targets):
            exact = targets[dst] >= 1.0
            edges.append(
                Edge(
                    type=EdgeType.HANDLES,
                    src=node.id,
                    dst=dst,
                    owner_file=entry.path,
                    provenance=Provenance.EXTRACTED if exact else Provenance.INFERRED,
                    confidence=targets[dst],
                    evidence=evidence,
                )
            )
        for hit in entry.controls:
            control_key = node_key(NodeType.CONTROL, entry.path, hit.kind, hit.label)
            exact = hit.confidence >= EXACT
            control_evidence = (code.ev(entry.path, hit.line, note=f"{hit.where}:{hit.label}"),)
            if control_key not in controls:
                controls[control_key] = Node(
                    type=NodeType.CONTROL,
                    key=control_key,
                    name=hit.label,
                    owner_file=entry.path,
                    props={
                        "kind": hit.kind,
                        "impl_ref": hit.label,
                        "match": "exact" if exact else "name",
                    },
                    provenance=Provenance.EXTRACTED if exact else Provenance.INFERRED,
                    confidence=hit.confidence,
                    evidence=control_evidence,
                )
            edges.append(
                Edge(
                    type=EdgeType.GUARDED_BY,
                    src=node.id,
                    dst=controls[control_key].id,
                    owner_file=entry.path,
                    props={"where": hit.where, "kind": hit.kind},
                    provenance=Provenance.EXTRACTED if exact else Provenance.INFERRED,
                    confidence=hit.confidence,
                    evidence=control_evidence,
                )
            )
    return nodes + [controls[k] for k in sorted(controls)], edges
