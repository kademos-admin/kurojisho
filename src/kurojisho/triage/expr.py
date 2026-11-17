"""A small, safe condition language for triage rules. No ``eval``, no attribute access.

    expr    := and ("or" and)*
    and     := not ("and" not)*
    not     := "not" not | compare
    compare := operand (OP operand | "in" "[" operand ("," operand)* "]")?
    operand := "(" expr ")" | NAME

A NAME on the left of a comparison (or standing alone) must be a known fact; a NAME on the
right is a literal. Ordering comparisons work on levels such as ``E2`` or ``I1`` only.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

_TOKEN = re.compile(r"\s*(==|!=|>=|<=|>|<|\(|\)|\[|\]|,|[A-Za-z_][A-Za-z0-9_.]*)")
_LEVEL = re.compile(r"^([A-Z])(\d)$")
_ORDERED = {">=", "<=", ">", "<"}
_KEYWORDS = {"and", "or", "not", "in"}


class RuleSyntaxError(ValueError):
    """A rule condition could not be parsed. The rule file is rejected as a whole."""


@dataclass(frozen=True)
class Fact:
    name: str


@dataclass(frozen=True)
class Compare:
    fact: str
    op: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class Not:
    inner: Node


@dataclass(frozen=True)
class Bool:
    op: str  # "and" | "or"
    parts: tuple[Node, ...]


Node = Fact | Compare | Not | Bool


def _tokens(text: str) -> list[str]:
    out, position = [], 0
    while position < len(text):
        if text[position:].strip() == "":
            break
        match = _TOKEN.match(text, position)
        if match is None:
            raise RuleSyntaxError(f"unexpected character at {position}: {text[position:]!r}")
        out.append(match.group(1))
        position = match.end()
    return out


class _Parser:
    def __init__(self, text: str, facts: frozenset[str]) -> None:
        self.text = text
        self.tokens = _tokens(text)
        self.position = 0
        self.facts = facts

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self, expected: str | None = None) -> str:
        token = self.peek()
        if token is None or (expected is not None and token != expected):
            raise RuleSyntaxError(f"expected {expected or 'a term'} in {self.text!r}")
        self.position += 1
        return token

    def name(self) -> str:
        token = self.take()
        if token in _KEYWORDS or not (token[0].isalpha() or token[0] == "_"):
            raise RuleSyntaxError(f"expected a name, got {token!r} in {self.text!r}")
        return token

    def expr(self) -> Node:
        parts = [self.conjunction()]
        while self.peek() == "or":
            self.take()
            parts.append(self.conjunction())
        return parts[0] if len(parts) == 1 else Bool("or", tuple(parts))

    def conjunction(self) -> Node:
        parts = [self.negation()]
        while self.peek() == "and":
            self.take()
            parts.append(self.negation())
        return parts[0] if len(parts) == 1 else Bool("and", tuple(parts))

    def negation(self) -> Node:
        if self.peek() == "not":
            self.take()
            return Not(self.negation())
        return self.compare()

    def compare(self) -> Node:
        if self.peek() == "(":
            self.take()
            inner = self.expr()
            self.take(")")
            return inner
        fact = self.name()
        if fact not in self.facts:
            raise RuleSyntaxError(f"unknown fact {fact!r} in {self.text!r}")
        op = self.peek()
        if op == "in":
            self.take()
            self.take("[")
            values = [self.name()]
            while self.peek() == ",":
                self.take()
                values.append(self.name())
            self.take("]")
            return Compare(fact, "in", tuple(values))
        if op in ("==", "!=", *_ORDERED):
            self.take()
            value = self.name()
            if op in _ORDERED and _LEVEL.match(value) is None:
                raise RuleSyntaxError(f"{op} needs a level such as E2, got {value!r}")
            return Compare(fact, op, (value,))
        return Fact(fact)


def parse(text: str, facts: frozenset[str]) -> Node:
    parser = _Parser(text, facts)
    node = parser.expr()
    if parser.peek() is not None:
        raise RuleSyntaxError(f"unexpected {parser.peek()!r} in {text!r}")
    return node


def _text(value: object) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown" if value is None else str(value)


def evaluate(node: Node, facts: Mapping[str, object]) -> bool:
    if isinstance(node, Bool):
        results = (evaluate(part, facts) for part in node.parts)
        return all(results) if node.op == "and" else any(results)
    if isinstance(node, Not):
        return not evaluate(node.inner, facts)
    if isinstance(node, Fact):
        return facts[node.name] is True  # unknown is not true
    actual = _text(facts[node.fact])
    if node.op == "in":
        return actual in node.values
    wanted = node.values[0]
    if node.op == "==":
        return actual == wanted
    if node.op == "!=":
        return actual != wanted
    left, right = _LEVEL.match(actual), _LEVEL.match(wanted)
    if left is None or right is None or left.group(1) != right.group(1):
        return False  # an unknown level satisfies no ordering
    a, b = int(left.group(2)), int(right.group(2))
    return {">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b}[node.op]
