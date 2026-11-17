"""Go extractor."""

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

_ROUTE_VERBS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
_HANDLE = {"Handle", "HandleFunc"}


def string_literal(node: TSNode | None) -> str | None:
    if node is None or node.type not in ("interpreted_string_literal", "raw_string_literal"):
        return None
    return text(node)[1:-1]


def dotted(node: TSNode | None) -> str:
    if node is None:
        return ""
    if node.type in ("identifier", "package_identifier", "type_identifier"):
        return text(node)
    if node.type == "selector_expression":
        head = dotted(node.child_by_field_name("operand"))
        return f"{head}.{text(node.child_by_field_name('field'))}" if head else ""
    return ""


def _type_name(node: TSNode | None) -> str:
    """Bare type name: strips pointers, generics and package qualifiers."""
    if node is None:
        return ""
    if node.type == "type_identifier":
        return text(node)
    if node.type == "qualified_type":
        return text(node.child_by_field_name("name"))
    for child in named(node):
        found = _type_name(child)
        if found:
            return found
    return ""


class GoExtractor(Extractor):
    lang = "go"
    frameworks: ClassVar[dict[str, str]] = {
        "github.com/gin-gonic/gin": "gin",
        "github.com/go-chi/chi": "chi",
        "github.com/gofiber/fiber": "fiber",
        "github.com/gorilla/mux": "gorilla",
        "github.com/labstack/echo": "echo",
        "net/http": "net/http",
    }

    call_types = frozenset({"call_expression"})
    opaque_types = frozenset({"func_literal"})

    def dotted_name(self, node: TSNode) -> str:
        return dotted(node)

    def visit(self, node: TSNode, ctx: Ctx) -> Ctx | None:
        kind = node.type
        if kind == "package_clause":
            self.facts.package = next((text(c) for c in named(node)), "")
        elif kind == "import_spec":
            self._import(node)
        elif kind == "type_spec":
            self._type(node, ctx)
        elif kind == "function_declaration":
            name = text(node.child_by_field_name("name"))
            return self._function(node, ctx, name, None, "")
        elif kind == "method_declaration":
            receiver = node.child_by_field_name("receiver")
            decl = next((c for c in named(receiver) if c.type == "parameter_declaration"), None)
            owner = _type_name(decl.child_by_field_name("type")) if decl is not None else ""
            var = text(decl.child_by_field_name("name")) if decl is not None else ""
            name = text(node.child_by_field_name("name"))
            return self._function(node, ctx, name, owner or None, var)
        elif kind == "call_expression":
            self._call(node, ctx)
        elif kind in ("short_var_declaration", "range_clause"):
            for target in named(node.child_by_field_name("left")):
                if target.type == "identifier":
                    self.add_local(ctx, text(target))
            self._assign(node, ctx)
        elif kind == "assignment_statement":
            self._assign(node, ctx)
        elif kind == "var_spec":
            names = node.children_by_field_name("name")
            for target in names:
                self.add_local(ctx, text(target))
            self.add_flow(
                ctx, "assign", node, [text(n) for n in names], node.child_by_field_name("value")
            )
        elif kind == "return_statement":
            self.add_flow(ctx, "return", node, [], *named(node))
        return None

    def _assign(self, node: TSNode, ctx: Ctx) -> None:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        self.add_flow(ctx, "assign", node, _targets(left), right)

    def _import(self, node: TSNode) -> None:
        module = string_literal(node.child_by_field_name("path"))
        if module is None:
            return
        alias_node = node.child_by_field_name("name")
        alias = text(alias_node)
        if alias_node is not None and alias_node.type == "dot":
            self.facts.imports.append(Import(module, "*", "", line(node)))
        elif alias == "_":
            self.facts.imports.append(Import(module, None, "_", line(node)))
        else:
            self.facts.imports.append(Import(module, None, alias, line(node)))

    def _type(self, node: TSNode, ctx: Ctx) -> None:
        body = node.child_by_field_name("type")
        name = text(node.child_by_field_name("name"))
        if body is None or body.type not in ("struct_type", "interface_type") or ctx.func:
            return
        bases = []
        if body.type == "struct_type":
            for fields in named(body):
                for decl in named(fields):
                    if decl.type == "field_declaration" and not decl.children_by_field_name("name"):
                        bases.append(_type_name(decl.child_by_field_name("type")))
        else:
            for elem in named(body):
                if elem.type in ("type_elem", "constraint_elem"):
                    bases.append(_type_name(elem))
        self.add_def(
            "class",
            "struct" if body.type == "struct_type" else "interface",
            name,
            node,
            ctx,
            bases=[b for b in bases if b],
            visibility=_visibility(name),
        )

    def _function(self, node: TSNode, ctx: Ctx, name: str, owner: str | None, receiver: str) -> Ctx:
        params_node = node.child_by_field_name("parameters")
        signature = text(params_node)
        result = node.child_by_field_name("result")
        if result is not None:
            signature += f" {text(result)}"
        params = [
            text(n)
            for decl in named(params_node)
            for n in decl.children_by_field_name("name")
            if n.type == "identifier"
        ]
        definition = self.add_def(
            "function",
            "method" if owner else "function",
            name,
            node,
            ctx,
            parent=owner,
            signature=squash(signature),
            visibility=_visibility(name),
            params=params,
            receiver=receiver,
            is_method=bool(owner),
        )
        return Ctx(scope=definition.qualname, func=definition.qualname)

    def _call(self, node: TSNode, ctx: Ctx) -> None:
        target = node.child_by_field_name("function")
        args = named(node.child_by_field_name("arguments"))
        if target is None:
            return
        while target.type == "parenthesized_expression" and named(target):
            target = named(target)[0]
        kind = target.type
        if kind == "func_literal":
            return  # immediately-invoked literal: its body is walked in place
        if kind == "identifier":
            self.add_call(ctx, "name", text(target), node, argc=len(args), arg_nodes=args)
        elif kind == "selector_expression":
            name = text(target.child_by_field_name("field"))
            operand = target.child_by_field_name("operand")
            receiver = dotted(operand)
            operand_text = text(operand)
            if name == "MethodByName" or (
                name in ("Call", "CallSlice")
                and ("reflect." in operand_text or "MethodByName" in operand_text)
            ):
                self.add_call(ctx, "dynamic", name, node, reason="reflect")
                return
            self.add_call(
                ctx,
                "attr",
                name,
                node,
                receiver=receiver,
                argc=len(args),
                arg_nodes=args,
                base_node=operand,
            )
            self._route(node, name, args, ctx)
        elif kind == "index_expression":
            self.add_call(ctx, "dynamic", "index", node, reason="index")
        elif kind == "call_expression":
            self.add_call(ctx, "dynamic", "call_result", node, reason="call_result")
        elif kind not in ("generic_type", "array_type", "slice_type", "map_type", "pointer_type"):
            self.add_call(ctx, "dynamic", "expression", node, reason="expression")

    def _route(self, node: TSNode, name: str, args: list[TSNode], ctx: Ctx) -> None:
        if not args or (name not in _HANDLE and name.upper() not in _ROUTE_VERBS | {"ANY"}):
            return
        pattern = string_literal(args[0])
        if pattern is None:
            return
        method, path = "ANY", pattern
        if name in _HANDLE:
            head, _, rest = pattern.partition(" ")
            if head in _ROUTE_VERBS and rest:  # Go 1.22 "METHOD /path" patterns
                method, path = head, rest.strip()
        else:
            method = name.upper()
        if not path.startswith("/") and name not in _HANDLE:
            return
        handler, middleware = None, [_callee(a) for a in args[1:-1] if _callee(a)]
        if len(args) > 1:
            last = args[-1]
            # auth(limit(handler)): the wrappers are middleware, the innermost is the handler
            while last.type == "call_expression":
                inner = named(last.child_by_field_name("arguments"))
                wrapper = dotted(last.child_by_field_name("function"))
                if not inner:
                    break
                if wrapper:
                    middleware.append(wrapper)
                last = inner[-1]
            handler = dotted(last) or None
        self.facts.routes.append(
            RouteFact(
                method,
                path,
                handler,
                line(node),
                end_line(node),
                scope=ctx.func,
                middleware=middleware,
            )
        )


def _callee(node: TSNode) -> str:
    """Name of a middleware argument: ``auth`` or the callee of ``auth()``."""
    if node.type == "call_expression":
        return dotted(node.child_by_field_name("function"))
    return dotted(node)


def _targets(node: TSNode | None) -> list[str]:
    if node is None:
        return []
    if node.type in ("identifier", "selector_expression"):
        name = dotted(node)
        return [name] if name and name != "_" else []
    if node.type == "index_expression":
        return _targets(node.child_by_field_name("operand"))
    return [name for child in named(node) for name in _targets(child)]


def _visibility(name: str) -> str:
    return "public" if name[:1].isupper() else "package"
