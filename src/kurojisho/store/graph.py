"""In-memory views of the live graph: NetworkX loader and canonical export."""

from __future__ import annotations

import json
from typing import Any

import networkx as nx

from kurojisho.model import canonical_json
from kurojisho.store.db import Store

_NODE_SQL = (
    "SELECT id, type, key, name, owner_file, props, provenance, confidence, evidence "
    "FROM nodes WHERE retired = 0 ORDER BY id"
)
_EDGE_SQL = (
    "SELECT id, type, src, dst, owner_file, props, provenance, confidence, evidence "
    "FROM edges WHERE retired = 0 ORDER BY id"
)


def _rows(store: Store, sql: str) -> list[dict[str, Any]]:
    out = []
    for row in store.conn.execute(sql):
        data = dict(row)
        data["props"] = json.loads(data["props"])
        data["evidence"] = json.loads(data["evidence"])
        out.append(data)
    return out


def to_networkx(store: Store) -> nx.MultiDiGraph[str]:
    """Load the live graph. Edge keys are edge ids, so parallel edges are preserved."""
    graph: nx.MultiDiGraph[str] = nx.MultiDiGraph()
    for node in _rows(store, _NODE_SQL):
        graph.add_node(node.pop("id"), **node)
    for edge in _rows(store, _EDGE_SQL):
        graph.add_edge(edge.pop("src"), edge.pop("dst"), key=edge.pop("id"), **edge)
    return graph


def canonical_export(store: Store) -> str:
    """Deterministic JSON of the live graph.

    Scan bookkeeping (first/last seen, timestamps) is excluded on purpose: it describes
    *when* a fact was observed, not the fact, and must not make two scans of the same tree
    differ.
    """
    body = {"nodes": _rows(store, _NODE_SQL), "edges": _rows(store, _EDGE_SQL)}
    lines = ['{"edges":[']
    lines.append(",\n".join(canonical_json(e) for e in body["edges"]))
    lines.append('],"nodes":[')
    lines.append(",\n".join(canonical_json(n) for n in body["nodes"]))
    lines.append("]}")
    return "\n".join(lines) + "\n"
