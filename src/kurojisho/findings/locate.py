"""Map a file and line to the innermost function that contains it."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from kurojisho.model import Node, NodeType


class FunctionIndex:
    def __init__(self, nodes: Iterable[Node]) -> None:
        self._spans: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
        for node in nodes:
            span = node.props.get("span")
            if node.type is NodeType.FUNCTION and span and not node.props.get("synthetic"):
                self._spans[node.props["path"]].append((span[0], span[1], node.id))

    def innermost(self, path: str | None, line: int | None) -> str | None:
        if path is None or line is None:
            return None
        hits = [
            (end - start, start, nid)
            for start, end, nid in self._spans.get(path, [])
            if start <= line <= end
        ]
        return min(hits)[2] if hits else None
