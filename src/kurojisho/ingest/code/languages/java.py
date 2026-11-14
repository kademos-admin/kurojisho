"""Java extractor."""

from __future__ import annotations

from typing import ClassVar

from tree_sitter import Node as TSNode

from kurojisho.ingest.code.extract import (
    Ctx,
    Extractor,
    Import,
    RouteFact,
    end_line,
    line,
    named,
    squash,
    text,
)

_TYPE_NODES = {
    "class_declaration": "class",
    "interface_declaration": "interface",
    "enum_declaration": "enum",
    "record_declaration": "record",
}
_MAPPINGS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
    "RequestMapping": "ANY",
}
_REFLECT_ALWAYS = {"getMethod", "getDeclaredMethod", "getDeclaredConstructor"}
_REFLECT_IF_SIGNALLED = {"invoke", "newInstance"}
CONSTRUCTOR = "<init>"


def string_literal(node: TSNode | None) -> str | None:
    if node is None or node.type != "string_literal":
        return None
    return text(node)[1:-1]


def dotted(node: TSNode | None) -> str:
    if node is None:
        return ""
    if node.type in ("identifier", "this", "super", "type_identifier"):
        return text(node)
    if node.type in ("field_access", "scoped_identifier", "scoped_type_identifier"):
        return "".join(text(node).split())
    return ""


def _type_name(node: TSNode | None) -> str:
    """Simple class name of a type: drops generics and package qualifiers."""
    if node is None:
        return ""
    if node.type == "generic_type":
        return _type_name(named(node)[0]) if named(node) else ""
    if node.type == "scoped_type_identifier":
        return text(node).rpartition(".")[2].strip()
    return text(node) if node.type == "type_identifier" else ""


class JavaExtractor(Extractor):
    lang = "java"
    frameworks: ClassVar[dict[str, str]] = {
        "jakarta.ws.rs": "jax-rs",
        "javax.ws.rs": "jax-rs",
        "org.springframework": "spring",
    }

    def __init__(self) -> None:
        super().__init__()
        self._prefix: dict[str, str] = {}  # class qualname -> class-level route prefix
        self._reflective = False

    def visit(self, node: TSNode, ctx: Ctx) -> Ctx | None:
        kind = node.type
        if kind == "package_declaration":
            self.facts.package = next((dotted(c) for c in named(node) if dotted(c)), "")
        elif kind == "import_declaration":
            self._import(node)
        elif kind in _TYPE_NODES:
            return self._type(node, ctx)
        elif kind in ("method_declaration", "constructor_declaration"):
            return self._method(node, ctx)
        elif kind == "method_invocation":
            self._call(node, ctx)
        elif kind == "object_creation_expression":
            name = _type_name(node.child_by_field_name("type"))
            argc = len(named(node.child_by_field_name("arguments")))
            if name:
                self.add_call(ctx, "new", name, node, argc=argc)
        elif kind == "method_reference":
            parts = named(node)
            if len(parts) == 2 and parts[1].type == "identifier":
                self.add_call(ctx, "attr", text(parts[1]), node, receiver=dotted(parts[0]), argc=-1)
        return None

    def finish(self) -> None:
        if not self._reflective:
            return
        for call in self.facts.calls:
            if call.kind == "attr" and call.name in _REFLECT_IF_SIGNALLED:
                call.kind, call.reason, call.receiver = "dynamic", "reflection", ""

    def _import(self, node: TSNode) -> None:
        path = next((dotted(c) for c in named(node) if dotted(c)), "")
        static = any(c.type == "static" for c in node.children)
        wildcard = any(c.type == "asterisk" for c in node.children)
        if path.startswith("java.lang.reflect"):
            self._reflective = True
        kind = "static" if static else ""
        if wildcard:
            self.facts.imports.append(Import(path, "*", "", line(node), kind=kind))
        else:
            module, _, name = path.rpartition(".")
            self.facts.imports.append(Import(module, name, name, line(node), kind=kind))

    def _type(self, node: TSNode, ctx: Ctx) -> Ctx:
        name = text(node.child_by_field_name("name"))
        bases = []
        for clause in named(node):
            if clause.type == "superclass":
                bases += [_type_name(c) for c in named(clause)]
            elif clause.type in ("super_interfaces", "extends_interfaces"):
                bases += [_type_name(t) for lst in named(clause) for t in named(lst)]
        annotations = _annotations(node)
        definition = self.add_def(
            "class",
            _TYPE_NODES[node.type],
            name,
            node,
            ctx,
            bases=[b for b in bases if b],
            visibility=_visibility(node),
            decorators=[squash(text(a)[1:]) for a in annotations],
        )
        for annotation in annotations:
            if _annotation_name(annotation) == "RequestMapping":
                self._prefix[definition.qualname] = _mapping_path(annotation) or ""
        return Ctx(scope=definition.qualname, func=ctx.func)

    def _method(self, node: TSNode, ctx: Ctx) -> Ctx:
        is_ctor = node.type == "constructor_declaration"
        params_node = node.child_by_field_name("parameters")
        signature = text(params_node)
        returns = node.child_by_field_name("type")
        if returns is not None:
            signature += f": {text(returns)}"
        parent = self._by_qualname.get(ctx.scope or "")
        owner_is_class = parent is not None and parent.kind == "class"
        visibility = _visibility(node)
        if visibility == "package" and parent is not None and parent.subkind == "interface":
            visibility = "public"
        annotations = _annotations(node)
        definition = self.add_def(
            "function",
            "constructor" if is_ctor else "method",
            CONSTRUCTOR if is_ctor else text(node.child_by_field_name("name")),
            node,
            ctx,
            signature=squash(signature),
            visibility=visibility,
            decorators=[squash(text(a)[1:]) for a in annotations],
            params=_params(params_node),
            is_method=owner_is_class,
        )
        for annotation in annotations:
            method = _MAPPINGS.get(_annotation_name(annotation))
            if method is None:
                continue
            if method == "ANY":
                method = _mapping_method(annotation)
            path = _mapping_path(annotation)
            if path is None:
                self.note("route_path_not_literal", annotation)
                continue
            full = _join(self._prefix.get(ctx.scope or "", ""), path)
            self.facts.routes.append(
                RouteFact(method, full, definition.qualname, line(annotation), end_line(annotation))
            )
        return Ctx(scope=definition.qualname, func=definition.qualname)

    def _call(self, node: TSNode, ctx: Ctx) -> None:
        name = text(node.child_by_field_name("name"))
        obj = node.child_by_field_name("object")
        argc = len(named(node.child_by_field_name("arguments")))
        receiver = dotted(obj)
        if name in _REFLECT_ALWAYS or (name == "forName" and receiver == "Class"):
            self._reflective = True
            self.add_call(ctx, "dynamic", name, node, reason="reflection")
        elif obj is None:
            self.add_call(ctx, "name", name, node, argc=argc)
        else:
            self.add_call(ctx, "attr", name, node, receiver=receiver, argc=argc)


def _params(node: TSNode | None) -> list[str]:
    out = []
    for param in named(node):
        name = param.child_by_field_name("name")
        if name is None and param.type == "spread_parameter":
            declarator = next((c for c in named(param) if c.type == "variable_declarator"), None)
            name = declarator.child_by_field_name("name") if declarator is not None else None
        if name is not None:
            out.append(text(name))
    return out


def _annotations(node: TSNode) -> list[TSNode]:
    modifiers = next((c for c in node.children if c.type == "modifiers"), None)
    return [c for c in named(modifiers) if c.type in ("annotation", "marker_annotation")]


def _annotation_name(node: TSNode) -> str:
    return text(node.child_by_field_name("name")).rpartition(".")[2]


def _mapping_path(annotation: TSNode) -> str | None:
    """Literal path of a mapping annotation; "" when omitted; None when not a literal."""
    args = named(annotation.child_by_field_name("arguments"))
    for arg in args:
        if arg.type == "string_literal":
            return string_literal(arg)
        if arg.type == "element_value_pair" and text(arg.child_by_field_name("key")) in (
            "value",
            "path",
        ):
            return string_literal(arg.child_by_field_name("value"))
    positional = [a for a in args if a.type != "element_value_pair"]
    return None if positional else ""


def _mapping_method(annotation: TSNode) -> str:
    for arg in named(annotation.child_by_field_name("arguments")):
        if arg.type == "element_value_pair" and text(arg.child_by_field_name("key")) == "method":
            value = arg.child_by_field_name("value")
            if value is not None and value.type == "field_access":
                return text(value.child_by_field_name("field"))
    return "ANY"


def _join(prefix: str, path: str) -> str:
    if not prefix:
        return path
    return prefix.rstrip("/") + "/" + path.lstrip("/") if path else prefix


def _visibility(node: TSNode) -> str:
    modifiers = next((c for c in node.children if c.type == "modifiers"), None)
    tokens = {c.type for c in modifiers.children} if modifiers is not None else set()
    return next((v for v in ("public", "protected", "private") if v in tokens), "package")
