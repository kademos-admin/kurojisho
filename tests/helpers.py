"""Shared builders for tests."""

from __future__ import annotations

from typing import Any

from kurojisho.model import Edge, EdgeType, Evidence, Node, NodeType, Provenance, node_key

EV = Evidence(path="a.py", source="test", start_line=1, end_line=1)


def fn(name: str, owner: str = "a.py", **props: Any) -> Node:
    return Node(
        type=NodeType.FUNCTION,
        key=node_key(NodeType.FUNCTION, owner, name),
        name=name,
        owner_file=owner,
        props=props,
        provenance=Provenance.EXTRACTED,
        confidence=1.0,
        evidence=(EV,),
    )


def call(src: Node, dst: Node, resolution: str = "exact", confidence: float = 0.9) -> Edge:
    return Edge(
        type=EdgeType.CALLS,
        src=src.id,
        dst=dst.id,
        owner_file=src.owner_file,
        props={"resolution": resolution},
        provenance=Provenance.INFERRED,
        confidence=confidence,
        evidence=(EV,),
    )
