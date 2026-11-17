"""Python extractor."""

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

_ROUTE_VERBS = {"get", "post", "put", "delete", "patch", "head", "options"}
_DYNAMIC_BUILTINS = {"eval", "exec", "__import__", "compile"}


def string_literal(node: TSNode | None) -> str | None:
    """Value of a plain string literal; None for f-strings, concatenations, non-strings."""
    if node is None or node.type != "string":
        return None
    parts = []
    for child in named(node):
        if child.type == "string_content":
            parts.append(text(child))
        elif child.type not in ("string_start", "string_end"):
            return None
    return "".join(parts)


def dotted(node: TSNode | None) -> str:
    """``a.b.c`` for identifier/attribute chains, otherwise empty."""
    if node is None:
        return ""
    if node.type == "identifier":
        return text(node)
    if node.type == "attribute":
        head = dotted(node.child_by_field_name("object"))
        return f"{head}.{text(node.child_by_field_name('attribute'))}" if head else ""
    return ""


class PythonExtractor(Extractor):
    lang = "python"
    frameworks: ClassVar[dict[str, str]] = {
        "aiohttp": "aiohttp",
        "bottle": "bottle",
        "django": "django",
        "fastapi": "fastapi",
        "flask": "flask",
        "quart": "quart",
        "sanic": "sanic",
        "starlette": "starlette",
    }

    def __init__(self) -> None:
        super().__init__()
        self._url_patterns: list[RouteFact] = []

    call_types = frozenset({"call"})
    opaque_types = frozenset({"lambda", "function_definition", "class_definition"})

    def dotted_name(self, node: TSNode) -> str:
        return dotted(node)

    def visit(self, node: TSNode, ctx: Ctx) -> Ctx | None:
        kind = node.type
        if kind == "class_definition":
            return self._class(node, ctx)
        if kind == "function_definition":
            return self._function(node, ctx)
        if kind == "import_statement":
            self._import(node)
        elif kind == "import_from_statement":
            self._import_from(node)
        elif kind == "call":
            self._call(node, ctx)
        elif kind in ("assignment", "augmented_assignment", "for_statement", "named_expression"):
            left = node.child_by_field_name("left") or node.child_by_field_name("name")
            self._locals(left, ctx)
            value = node.child_by_field_name("right") or node.child_by_field_name("value")
            also = left if kind == "augmented_assignment" else None
            self.add_flow(ctx, "assign", node, _targets(left), value, also)
        elif kind == "as_pattern":
            alias = node.child_by_field_name("alias")
            self._locals(alias, ctx)
            source = named(node)[0] if named(node) else None
            self.add_flow(ctx, "assign", node, _targets(alias), source)
        elif kind in ("return_statement", "yield"):
            self.add_flow(ctx, "return", node, [], *named(node))
        return None

    # -- definitions --------------------------------------------------------------------
    def _decorated(self, node: TSNode) -> tuple[TSNode, list[TSNode]]:
        parent = node.parent
        if parent is not None and parent.type == "decorated_definition":
            return parent, [c for c in parent.children if c.type == "decorator"]
        return node, []

    def _class(self, node: TSNode, ctx: Ctx) -> Ctx:
        span, decorators = self._decorated(node)
        name = text(node.child_by_field_name("name"))
        bases = [
            text(c)
            for c in named(node.child_by_field_name("superclasses"))
            if c.type not in ("keyword_argument", "comment")
        ]
        definition = self.add_def(
            "class",
            "class",
            name,
            node,
            ctx,
            span=span,
            bases=bases,
            visibility=_visibility(name),
            decorators=[squash(text(d)[1:]) for d in decorators],
        )
        return Ctx(scope=definition.qualname, func=ctx.func)

    def _function(self, node: TSNode, ctx: Ctx) -> Ctx:
        span, decorators = self._decorated(node)
        name = text(node.child_by_field_name("name"))
        params_node = node.child_by_field_name("parameters")
        signature = text(params_node)
        returns = node.child_by_field_name("return_type")
        if returns is not None:
            signature += f" -> {text(returns)}"
        parent = self._by_qualname.get(ctx.scope or "")
        is_method = parent is not None and parent.kind == "class"
        definition = self.add_def(
            "function",
            ("constructor" if name == "__init__" else "method") if is_method else "function",
            name,
            node,
            ctx,
            span=span,
            signature=squash(signature),
            visibility=_visibility(name),
            decorators=[squash(text(d)[1:]) for d in decorators],
            params=_params(params_node),
            is_method=is_method,
        )
        for decorator in decorators:
            self._route(decorator, definition.qualname)
        return Ctx(scope=definition.qualname, func=definition.qualname)

    def _route(self, decorator: TSNode, handler: str) -> None:
        call = next((c for c in named(decorator) if c.type == "call"), None)
        if call is None:
            return
        target = call.child_by_field_name("function")
        if target is None or target.type != "attribute":
            return
        verb = text(target.child_by_field_name("attribute"))
        if verb not in _ROUTE_VERBS | {"route", "api_route", "websocket"}:
            return
        args = named(call.child_by_field_name("arguments"))
        positional = [a for a in args if a.type != "keyword_argument"]
        path = string_literal(positional[0]) if positional else None
        if path is None:
            self.note("route_path_not_literal", decorator)
            return
        methods = [verb.upper()]
        if verb in ("route", "api_route"):
            methods = ["GET"]
            for arg in args:
                if (
                    arg.type == "keyword_argument"
                    and text(arg.child_by_field_name("name")) == "methods"
                ):
                    listed = [string_literal(v) for v in named(arg.child_by_field_name("value"))]
                    if listed and all(v is not None for v in listed):
                        methods = sorted({str(v).upper() for v in listed})
                    else:
                        methods = ["ANY"]
                        self.note("route_methods_not_literal", decorator)
        for method in methods:
            self.facts.routes.append(
                RouteFact(method, path, handler, line(decorator), end_line(decorator))
            )

    # -- imports ------------------------------------------------------------------------
    def _import(self, node: TSNode) -> None:
        for child in named(node):
            if child.type == "dotted_name":
                self.facts.imports.append(Import(text(child), None, "", line(node)))
            elif child.type == "aliased_import":
                module = text(child.child_by_field_name("name"))
                alias = text(child.child_by_field_name("alias"))
                self.facts.imports.append(Import(module, None, alias, line(node)))

    def _import_from(self, node: TSNode) -> None:
        source = node.child_by_field_name("module_name")
        module, level = text(source), 0
        if source is not None and source.type == "relative_import":
            prefix = next((c for c in named(source) if c.type == "import_prefix"), None)
            level = len(text(prefix))
            module = "".join(text(c) for c in named(source) if c.type == "dotted_name")
        for child in named(node):
            if child.id == (source.id if source else None):
                continue
            if child.type == "wildcard_import":
                self.facts.imports.append(Import(module, "*", "", line(node), level))
            elif child.type == "dotted_name":
                name = text(child)
                self.facts.imports.append(Import(module, name, name, line(node), level))
            elif child.type == "aliased_import":
                name = text(child.child_by_field_name("name"))
                alias = text(child.child_by_field_name("alias"))
                self.facts.imports.append(Import(module, name, alias, line(node), level))

    # -- calls --------------------------------------------------------------------------
    def _call(self, node: TSNode, ctx: Ctx) -> None:
        target = node.child_by_field_name("function")
        args = [
            (a.child_by_field_name("value") or a) if a.type == "keyword_argument" else a
            for a in named(node.child_by_field_name("arguments"))
            if a.type != "comment"
        ]
        argc = len(named(node.child_by_field_name("arguments")))
        if target is None:
            return
        if target.type == "identifier":
            name = text(target)
            if name in _DYNAMIC_BUILTINS:
                self.add_call(ctx, "dynamic", name, node, reason=name, arg_nodes=args)
            elif name != "super":
                self.add_call(ctx, "name", name, node, argc=argc, arg_nodes=args)
                if name in ("path", "re_path", "url") and len(args) >= 2:
                    self._url_pattern(node, args, ctx)
        elif target.type == "attribute":
            name = text(target.child_by_field_name("attribute"))
            obj = target.child_by_field_name("object")
            receiver = dotted(obj)
            is_call = obj is not None and obj.type == "call"
            if is_call and text(obj.child_by_field_name("function") if obj else None) == "super":
                receiver = "super"
            if (receiver, name) == ("importlib", "import_module"):
                self.add_call(ctx, "dynamic", name, node, reason="import_module")
            else:
                self.add_call(
                    ctx,
                    "attr",
                    name,
                    node,
                    receiver=receiver,
                    argc=argc,
                    arg_nodes=args,
                    base_node=obj,
                )
        elif target.type == "call":
            inner = text(target.child_by_field_name("function"))
            reason = "getattr" if inner == "getattr" else "call_result"
            self.add_call(ctx, "dynamic", reason, node, reason=reason)
        elif target.type == "subscript":
            self.add_call(ctx, "dynamic", "subscript", node, reason="subscript")
        else:
            self.add_call(ctx, "dynamic", "expression", node, reason="expression")

    def _url_pattern(self, node: TSNode, args: list[TSNode], ctx: Ctx) -> None:
        """Django ``path("orders/", views.orders)``; kept only if the file imports Django."""
        pattern = string_literal(args[0])
        view = args[1]
        if view.type == "call":  # Class.as_view()
            target = view.child_by_field_name("function")
            view_obj = target.child_by_field_name("object") if target is not None else None
            if (
                target is None
                or view_obj is None
                or text(target.child_by_field_name("attribute")) != "as_view"
            ):
                return
            view = view_obj
        handler = dotted(view)
        if pattern is None or not handler:
            return
        self._url_patterns.append(
            RouteFact(
                "ANY",
                "/" + pattern.lstrip("^/"),
                handler,
                line(node),
                end_line(node),
                scope=ctx.func,
            )
        )

    def finish(self) -> None:
        if any(i.module.split(".")[0] == "django" for i in self.facts.imports):
            self.facts.routes.extend(self._url_patterns)

    def _locals(self, target: TSNode | None, ctx: Ctx) -> None:
        if target is None or ctx.func is None:
            return
        if target.type == "identifier":
            self.add_local(ctx, text(target))
        elif target.type in ("pattern_list", "tuple_pattern", "list_pattern", "as_pattern_target"):
            for child in named(target):
                self._locals(child, ctx)


def _targets(node: TSNode | None) -> list[str]:
    """Names an assignment writes. ``d[k] = v`` and ``o.f = v`` write to ``d`` / ``o.f``."""
    if node is None:
        return []
    if node.type in ("identifier", "attribute"):
        name = dotted(node)
        return [name] if name else []
    if node.type == "subscript":
        return _targets(node.child_by_field_name("value"))
    return [name for child in named(node) for name in _targets(child)]


def _visibility(name: str) -> str:
    if name.startswith("__") and name.endswith("__"):
        return "public"
    return "private" if name.startswith("_") else "public"


def _params(node: TSNode | None) -> list[str]:
    out = []
    for child in named(node):
        if child.type == "identifier":
            out.append(text(child))
        elif child.type in ("default_parameter", "typed_default_parameter"):
            out.append(text(child.child_by_field_name("name")))
        elif child.type in ("typed_parameter", "list_splat_pattern", "dictionary_splat_pattern"):
            inner = next((c for c in named(child) if c.type == "identifier"), None)
            if inner is None and child.type == "typed_parameter":
                splat = next((c for c in named(child) if c.type.endswith("splat_pattern")), None)
                inner = next((c for c in named(splat) if c.type == "identifier"), None)
            out.append(text(inner))
    return [p for p in out if p]
