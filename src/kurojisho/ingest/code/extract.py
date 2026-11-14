"""Language-neutral facts extracted from one source file, and the shared tree walker.

Facts are a pure function of (path, bytes). They are cached per file, and all cross-file
resolution happens later from the facts alone, so unchanged files are never re-parsed.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar

from tree_sitter import Node as TSNode

MAX_PARSE_ERROR_LINES = 20
MAX_SIGNATURE = 300


@dataclass
class Def:
    kind: str  # "class" | "function"
    subkind: str  # class/interface/struct/enum/record | function/method/constructor
    name: str
    qualname: str
    parent: str | None
    start_line: int
    end_line: int
    signature: str = ""
    visibility: str = "public"
    decorators: list[str] = field(default_factory=list)
    bases: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    local_names: list[str] = field(default_factory=list)
    receiver: str = ""
    is_method: bool = False


@dataclass
class Import:
    module: str
    name: str | None  # imported symbol; None = the module itself; "*" = wildcard
    alias: str  # local binding ("" when the statement binds nothing usable)
    line: int
    level: int = 0  # Python relative-import dots
    kind: str = ""  # "static" for Java static imports


@dataclass
class Call:
    caller: str | None  # qualname of the enclosing function; None at module level
    kind: str  # "name" | "attr" | "new" | "dynamic"
    name: str
    line: int
    receiver: str = ""
    argc: int = 0
    reason: str = ""


@dataclass
class RouteFact:
    method: str
    path: str
    handler: str | None
    start_line: int
    end_line: int


@dataclass
class FileFacts:
    lang: str
    package: str = ""
    framework: str = ""
    defs: list[Def] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    routes: list[RouteFact] = field(default_factory=list)
    parse_error_lines: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> FileFacts:
        data: dict[str, Any] = json.loads(raw)
        return cls(
            lang=data["lang"],
            package=data["package"],
            framework=data["framework"],
            defs=[Def(**d) for d in data["defs"]],
            imports=[Import(**i) for i in data["imports"]],
            calls=[Call(**c) for c in data["calls"]],
            routes=[RouteFact(**r) for r in data["routes"]],
            parse_error_lines=data["parse_error_lines"],
            notes=data["notes"],
        )


@dataclass(frozen=True)
class Ctx:
    """Traversal context: nearest enclosing definition and nearest enclosing function."""

    scope: str | None = None
    func: str | None = None


def text(node: TSNode | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", "replace")


_STRING_LITERAL = re.compile(r"""("{3}|'{3}|["'`])(?:\\.|(?!\1).)*?\1""", re.DOTALL)


def squash(value: str) -> str:
    """One-line form of a signature or decorator for display.

    String literals are blanked: a default argument or decorator argument can hold a
    hard-coded credential, and raw secrets must never reach the store.
    """
    out = " ".join(_STRING_LITERAL.sub('"…"', value).split())
    return out if len(out) <= MAX_SIGNATURE else out[: MAX_SIGNATURE - 1] + "…"


def line(node: TSNode) -> int:
    return node.start_point.row + 1


def end_line(node: TSNode) -> int:
    return node.end_point.row + 1


def named(node: TSNode | None) -> list[TSNode]:
    return [] if node is None else [c for c in node.children if c.is_named]


def has_token(node: TSNode, token: str) -> bool:
    return any(c.type == token for c in node.children)


class Extractor:
    """Iterative depth-first walk (no recursion: deeply nested sources must not crash us).

    Subclasses implement :meth:`visit`, which may register facts and returns the context for
    the node's children, or ``SKIP`` to prune the subtree.
    """

    lang: ClassVar[str] = ""
    SKIP: ClassVar[Ctx] = Ctx(scope="\0skip")
    #: import module -> framework label; the first imported one (sorted) wins.
    frameworks: ClassVar[dict[str, str]] = {}

    def __init__(self) -> None:
        self.facts = FileFacts(lang=self.lang)
        self._by_qualname: dict[str, Def] = {}
        self._seen: dict[str, int] = {}
        self._errors: set[int] = set()

    # -- registration helpers -----------------------------------------------------------
    def add_def(
        self, kind: str, subkind: str, name: str, node: TSNode, ctx: Ctx, **extra: Any
    ) -> Def:
        parent = extra.pop("parent", ctx.scope)
        base = f"{parent}.{name}" if parent else name
        count = self._seen.get(base, 0) + 1
        self._seen[base] = count
        qualname = base if count == 1 else f"{base}#{count}"
        span = extra.pop("span", node)
        definition = Def(
            kind=kind,
            subkind=subkind,
            name=name,
            qualname=qualname,
            parent=parent,
            start_line=line(span),
            end_line=end_line(span),
            **extra,
        )
        self.facts.defs.append(definition)
        self._by_qualname[qualname] = definition
        return definition

    def add_call(self, ctx: Ctx, kind: str, name: str, node: TSNode, **extra: Any) -> None:
        self.facts.calls.append(
            Call(caller=ctx.func, kind=kind, name=name, line=line(node), **extra)
        )

    def add_local(self, ctx: Ctx, name: str) -> None:
        owner = self._by_qualname.get(ctx.func or "")
        if owner is not None and name and name not in owner.local_names:
            owner.local_names.append(name)

    def note(self, kind: str, node: TSNode) -> None:
        self.facts.notes.append(f"{kind}:{line(node)}")

    # -- traversal ----------------------------------------------------------------------
    def visit(self, node: TSNode, ctx: Ctx) -> Ctx | None:
        raise NotImplementedError

    def finish(self) -> None:
        """Hook for whole-file post-processing."""

    def run(self, root: TSNode) -> FileFacts:
        stack: list[tuple[TSNode, Ctx]] = [(root, Ctx())]
        while stack:
            node, ctx = stack.pop()
            if node.type == "ERROR" or node.is_missing:
                self._errors.add(line(node))
            child_ctx = ctx
            if node.is_named:
                result = self.visit(node, ctx)
                if result is self.SKIP:
                    continue
                if result is not None:
                    child_ctx = result
            stack.extend((child, child_ctx) for child in reversed(node.children))
        self.finish()
        facts = self.facts
        modules = sorted({i.module for i in facts.imports})
        facts.framework = next(
            (
                label
                for m in modules
                for key, label in self.frameworks.items()
                if _is_or_under(m, key)
            ),
            "",
        )
        facts.parse_error_lines = sorted(self._errors)[:MAX_PARSE_ERROR_LINES]
        for definition in facts.defs:
            definition.local_names.sort()
        facts.imports.sort(key=lambda i: (i.line, i.module, i.name or "", i.alias))
        facts.calls.sort(key=lambda c: (c.line, c.kind, c.receiver, c.name, c.caller or ""))
        facts.routes.sort(key=lambda r: (r.start_line, r.path, r.method))
        facts.notes.sort()
        return facts


def _is_or_under(module: str, key: str) -> bool:
    return module == key or module.startswith((key + ".", key + "/"))
