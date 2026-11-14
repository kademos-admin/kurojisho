"""JavaScript / TypeScript / TSX extractor (the grammars share node names)."""

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

_FUNCTION_VALUES = {"arrow_function", "function_expression", "generator_function"}
_CLASS_NODES = {"class_declaration", "abstract_class_declaration", "class", "interface_declaration"}
_ROUTE_VERBS = {"get", "post", "put", "delete", "patch", "head", "options", "all"}


def string_literal(node: TSNode | None) -> str | None:
    """Value of a quoted string or a template string without substitutions."""
    if node is None or node.type not in ("string", "template_string"):
        return None
    parts = []
    for child in named(node):
        if child.type in ("string_fragment", "escape_sequence"):
            parts.append(text(child))
        else:
            return None
    return "".join(parts)


def dotted(node: TSNode | None) -> str:
    if node is None:
        return ""
    if node.type in ("identifier", "this", "super", "type_identifier"):
        return text(node)
    if node.type == "member_expression":
        head = dotted(node.child_by_field_name("object"))
        return f"{head}.{text(node.child_by_field_name('property'))}" if head else ""
    return ""


class JavaScriptExtractor(Extractor):
    lang = "javascript"
    frameworks: ClassVar[dict[str, str]] = {
        "@koa/router": "koa",
        "@nestjs/common": "nestjs",
        "express": "express",
        "fastify": "fastify",
        "hono": "hono",
        "koa-router": "koa",
        "restify": "restify",
    }

    def __init__(self) -> None:
        super().__init__()
        # function-expression node id -> (name, span node, is_method, visibility)
        self._named: dict[int, tuple[str, TSNode, bool, str]] = {}

    def visit(self, node: TSNode, ctx: Ctx) -> Ctx | None:
        kind = node.type
        if kind in _CLASS_NODES:
            return self._class(node, ctx)
        if kind in ("function_declaration", "generator_function_declaration"):
            name = text(node.child_by_field_name("name"))
            return self._function(node, ctx, name, node, False, _export_visibility(node))
        if kind == "method_definition":
            return self._method(node, ctx)
        if kind in _FUNCTION_VALUES:
            known = self._named.pop(node.id, None)
            if known is None:
                return None  # anonymous callback: its calls belong to the enclosing function
            return self._function(node, ctx, *known)
        if kind == "variable_declarator":
            self._declarator(node, ctx)
        elif kind in ("field_definition", "public_field_definition", "pair"):
            key = (
                node.child_by_field_name("name")
                or node.child_by_field_name("property")
                or node.child_by_field_name("key")
            )
            value = node.child_by_field_name("value")
            if key is not None and value is not None and value.type in _FUNCTION_VALUES:
                self._named[value.id] = (text(key), node, True, _member_visibility(node, text(key)))
        elif kind == "assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if (
                left is not None
                and right is not None
                and left.type == "member_expression"
                and right.type in _FUNCTION_VALUES
            ):
                name = text(left.child_by_field_name("property"))
                self._named[right.id] = (name, node, False, "public")
        elif kind == "import_statement":
            self._import(node)
        elif kind == "export_statement":
            source = string_literal(node.child_by_field_name("source"))
            if source is not None:
                self.facts.imports.append(Import(source, None, "", line(node)))
        elif kind == "call_expression":
            self._call(node, ctx)
        elif kind == "new_expression":
            self._new(node, ctx)
        return None

    # -- definitions --------------------------------------------------------------------
    def _class(self, node: TSNode, ctx: Ctx) -> Ctx | None:
        name = text(node.child_by_field_name("name"))
        if not name:
            return None
        bases: list[str] = []
        for clause in node.children:
            if clause.type == "class_heritage":
                for item in named(clause):
                    if item.type == "extends_clause":
                        bases += [dotted(v) for v in item.children_by_field_name("value")]
                    elif item.type == "implements_clause":
                        bases += [_type_name(t) for t in named(item)]
                    else:
                        bases.append(dotted(item))
            elif clause.type == "extends_type_clause":
                bases += [_type_name(t) for t in named(clause)]
        subkind = "interface" if node.type == "interface_declaration" else "class"
        definition = self.add_def(
            "class",
            subkind,
            name,
            node,
            ctx,
            bases=[b for b in bases if b],
            visibility=_export_visibility(node),
            decorators=_decorators(node),
        )
        return Ctx(scope=definition.qualname, func=ctx.func)

    def _method(self, node: TSNode, ctx: Ctx) -> Ctx | None:
        key = node.child_by_field_name("name")
        if key is None or key.type == "computed_property_name":
            self.note("computed_method_name", node)
            return None
        name = text(key)
        return self._function(node, ctx, name, node, True, _member_visibility(node, name))

    def _function(
        self, node: TSNode, ctx: Ctx, name: str, span: TSNode, is_method: bool, visibility: str
    ) -> Ctx | None:
        if not name:
            return None
        params_node = node.child_by_field_name("parameters")
        single = node.child_by_field_name("parameter")
        signature = text(params_node) if params_node is not None else f"({text(single)})"
        returns = node.child_by_field_name("return_type")
        if returns is not None:
            signature += text(returns)
        params = _params(params_node)
        if single is not None:
            params.append(text(single))
        definition = self.add_def(
            "function",
            ("constructor" if name == "constructor" else "method") if is_method else "function",
            name,
            node,
            ctx,
            span=span,
            signature=squash(signature),
            visibility=visibility,
            decorators=_decorators(span),
            params=params,
            is_method=is_method,
        )
        return Ctx(scope=definition.qualname, func=definition.qualname)

    def _declarator(self, node: TSNode, ctx: Ctx) -> None:
        target, value = node.child_by_field_name("name"), node.child_by_field_name("value")
        if target is None:
            return
        if value is not None and value.type in _FUNCTION_VALUES and target.type == "identifier":
            self._named[value.id] = (text(target), node, False, _export_visibility(node))
            return
        module = _require(value)
        if module is not None:
            if target.type == "identifier":
                self.facts.imports.append(Import(module, None, text(target), line(node)))
            elif target.type == "object_pattern":
                for item in named(target):
                    if item.type == "shorthand_property_identifier_pattern":
                        self.facts.imports.append(
                            Import(module, text(item), text(item), line(node))
                        )
                    elif item.type == "pair_pattern":
                        key = text(item.child_by_field_name("key"))
                        alias = text(item.child_by_field_name("value"))
                        self.facts.imports.append(Import(module, key, alias, line(node)))
            return
        if target.type == "identifier":
            self.add_local(ctx, text(target))

    # -- imports ------------------------------------------------------------------------
    def _import(self, node: TSNode) -> None:
        module = string_literal(node.child_by_field_name("source"))
        if module is None:
            return
        clause = next((c for c in named(node) if c.type == "import_clause"), None)
        if clause is None:
            self.facts.imports.append(Import(module, None, "", line(node)))
            return
        for item in named(clause):
            if item.type == "identifier":
                self.facts.imports.append(Import(module, "default", text(item), line(node)))
            elif item.type == "namespace_import":
                alias = next((text(c) for c in named(item) if c.type == "identifier"), "")
                self.facts.imports.append(Import(module, None, alias, line(node)))
            elif item.type == "named_imports":
                for spec in named(item):
                    if spec.type != "import_specifier":
                        continue
                    name = text(spec.child_by_field_name("name"))
                    alias = text(spec.child_by_field_name("alias")) or name
                    self.facts.imports.append(Import(module, name, alias, line(node)))

    # -- calls --------------------------------------------------------------------------
    def _call(self, node: TSNode, ctx: Ctx) -> None:
        target = node.child_by_field_name("function")
        args = named(node.child_by_field_name("arguments"))
        argc = len(args)
        if target is None:
            return
        while target.type == "parenthesized_expression" and named(target):
            target = named(target)[0]
        kind = target.type
        if kind in _FUNCTION_VALUES:
            return  # immediately-invoked function: its body is walked in place
        if kind == "identifier":
            name = text(target)
            if name == "eval":
                self.add_call(ctx, "dynamic", name, node, reason="eval")
            elif name == "require":
                if not args or string_literal(args[0]) is None:
                    self.add_call(ctx, "dynamic", name, node, reason="require")
            else:
                self.add_call(ctx, "name", name, node, argc=argc)
        elif kind == "import":
            module = string_literal(args[0]) if args else None
            if module is None:
                self.add_call(ctx, "dynamic", "import", node, reason="import")
            else:
                self.facts.imports.append(Import(module, None, "", line(node)))
        elif kind == "super":
            self.add_call(ctx, "attr", "constructor", node, receiver="super", argc=argc)
        elif kind == "member_expression":
            self._member_call(node, target, ctx, args)
        elif kind == "subscript_expression":
            self.add_call(ctx, "dynamic", "computed_member", node, reason="computed_member")
        elif kind == "call_expression":
            self.add_call(ctx, "dynamic", "call_result", node, reason="call_result")
        else:
            self.add_call(ctx, "dynamic", "expression", node, reason="expression")

    def _member_call(self, node: TSNode, target: TSNode, ctx: Ctx, args: list[TSNode]) -> None:
        obj = target.child_by_field_name("object")
        name = text(target.child_by_field_name("property"))
        receiver = dotted(obj)
        if name in ("call", "apply") and receiver and receiver not in ("this", "super"):
            # fn.call(thisArg, ...) invokes fn itself.
            head, _, last = receiver.rpartition(".")
            self.add_call(ctx, "attr" if head else "name", last, node, receiver=head)
            return
        self.add_call(ctx, "attr", name, node, receiver=receiver, argc=len(args))
        if name in _ROUTE_VERBS and args:
            path = string_literal(args[0])
            if path is not None and path.startswith("/"):
                handler = (dotted(args[-1]) or None) if len(args) > 1 else None
                method = "ANY" if name == "all" else name.upper()
                self.facts.routes.append(
                    RouteFact(method, path, handler, line(node), end_line(node))
                )

    def _new(self, node: TSNode, ctx: Ctx) -> None:
        target = node.child_by_field_name("constructor")
        receiver, _, name = dotted(target).rpartition(".")
        argc = len(named(node.child_by_field_name("arguments")))
        if not name:
            self.add_call(ctx, "dynamic", "new_expression", node, reason="expression")
        elif name == "Function" and not receiver:
            self.add_call(ctx, "dynamic", "Function", node, reason="new_Function")
        else:
            self.add_call(ctx, "new", name, node, receiver=receiver, argc=argc)


def _require(value: TSNode | None) -> str | None:
    if value is None or value.type != "call_expression":
        return None
    if text(value.child_by_field_name("function")) != "require":
        return None
    args = named(value.child_by_field_name("arguments"))
    return string_literal(args[0]) if args else None


def _type_name(node: TSNode) -> str:
    if node.type == "generic_type":
        return _type_name(named(node)[0]) if named(node) else ""
    if node.type == "nested_type_identifier":
        return text(node)
    return text(node) if node.type in ("type_identifier", "identifier") else ""


def _export_visibility(node: TSNode) -> str:
    current: TSNode | None = node
    for _ in range(3):
        current = current.parent if current is not None else None
        if current is not None and current.type == "export_statement":
            return "public"
    return "module"


def _member_visibility(node: TSNode, name: str) -> str:
    if name.startswith("#"):
        return "private"
    modifier = next((text(c) for c in node.children if c.type == "accessibility_modifier"), "")
    return modifier or "public"


def _decorators(node: TSNode) -> list[str]:
    found = [c for c in node.children if c.type == "decorator"]
    sibling = node.prev_named_sibling
    while sibling is not None and sibling.type == "decorator":
        found.insert(0, sibling)
        sibling = sibling.prev_named_sibling
    return [squash(text(d)[1:]) for d in found]


def _params(node: TSNode | None) -> list[str]:
    out = []
    for child in named(node):
        target: TSNode | None = child
        if child.type in ("required_parameter", "optional_parameter"):
            target = child.child_by_field_name("pattern")
        if target is not None and target.type == "assignment_pattern":
            target = target.child_by_field_name("left")
        if target is not None and target.type == "rest_pattern":
            target = next((c for c in named(target) if c.type == "identifier"), None)
        if target is not None and target.type == "identifier":
            out.append(text(target))
    return out
