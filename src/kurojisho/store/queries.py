"""Named graph queries. Path queries use recursive CTEs over live edges."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Literal

from kurojisho.model import EdgeType
from kurojisho.store.db import Store

Direction = Literal["out", "in"]

DEFAULT_MAX_DEPTH = 32

# Breadth-first distances from a start node. UNION (not UNION ALL) plus the depth bound
# guarantees termination on cyclic graphs.
_DISTANCES = """
WITH RECURSIVE walk(id, depth) AS (
    SELECT :start, 0
    UNION
    SELECT e.{far}, w.depth + 1
    FROM walk w
    JOIN edges e ON e.{near} = w.id
    WHERE e.retired = 0
      AND w.depth < :max_depth
      AND e.type IN (SELECT value FROM json_each(:types))
)
SELECT id, MIN(depth) AS depth FROM walk GROUP BY id ORDER BY depth, id
"""


@dataclass(frozen=True)
class PathStep:
    edge_id: str
    edge_type: str
    src: str
    dst: str
    confidence: float
    provenance: str
    props: dict[str, Any]


def _types(edge_types: list[EdgeType] | None) -> str:
    return json.dumps(sorted(t.value for t in (edge_types or list(EdgeType))))


def distances(
    store: Store,
    start: str,
    *,
    edge_types: list[EdgeType] | None = None,
    direction: Direction = "out",
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> dict[str, int]:
    """Node id -> hop count for everything reachable from ``start`` (inclusive)."""
    near, far = ("src", "dst") if direction == "out" else ("dst", "src")
    sql = _DISTANCES.format(near=near, far=far)
    rows = store.conn.execute(
        sql, {"start": start, "max_depth": max_depth, "types": _types(edge_types)}
    )
    return {r["id"]: int(r["depth"]) for r in rows}


def shortest_path(
    store: Store,
    src: str,
    dst: str,
    *,
    edge_types: list[EdgeType] | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> list[PathStep] | None:
    """One shortest path from ``src`` to ``dst``; ties are broken by smallest edge id."""
    dist = distances(store, src, edge_types=edge_types, max_depth=max_depth)
    if dst not in dist:
        return None
    types = _types(edge_types)
    steps: list[PathStep] = []
    current = dst
    while current != src:
        rows = store.conn.execute(
            "SELECT id, type, src, dst, confidence, provenance, props FROM edges "
            "WHERE dst = ? AND retired = 0 AND type IN (SELECT value FROM json_each(?)) "
            "ORDER BY id",
            (current, types),
        ).fetchall()
        step = next(r for r in rows if dist.get(r["src"]) == dist[current] - 1)
        steps.append(_step(step))
        current = step["src"]
    steps.reverse()
    return steps


def neighbours(
    store: Store, node: str, edge_type: EdgeType, direction: Direction = "out"
) -> list[PathStep]:
    near = "src" if direction == "out" else "dst"
    rows = store.conn.execute(
        "SELECT id, type, src, dst, confidence, provenance, props FROM edges "  # noqa: S608
        f"WHERE {near} = ? AND type = ? AND retired = 0 ORDER BY id",
        (node, edge_type.value),
    )
    return [_step(r) for r in rows]


def find_nodes(
    store: Store, *, node_type: str | None = None, name: str | None = None, limit: int = 0
) -> list[dict[str, Any]]:
    sql = "SELECT * FROM nodes_seen WHERE retired = 0"
    params: list[Any] = []
    if node_type:
        sql += " AND type = ?"
        params.append(node_type)
    if name:
        sql += " AND name = ?"
        params.append(name)
    sql += " ORDER BY key"
    if limit > 0:
        sql += " LIMIT ?"
        params.append(limit)
    return [node_row(r) for r in store.conn.execute(sql, params)]


def get_node(store: Store, node: str) -> dict[str, Any] | None:
    row = store.conn.execute("SELECT * FROM nodes_seen WHERE id = ?", (node,)).fetchone()
    return None if row is None else node_row(row)


def resolve_ref(store: Store, ref: str) -> list[dict[str, Any]]:
    """Resolve a user-supplied reference: node id, full key, key suffix, or bare name."""
    for sql, param in (
        ("id = ?", ref),
        ("key = ?", ref),
        ("key LIKE ? ESCAPE '\\'", "%:" + _like(ref)),
        ("key LIKE ? ESCAPE '\\'", "%::" + _like(ref)),
        ("name = ?", ref),
    ):
        rows = store.conn.execute(
            f"SELECT * FROM nodes_seen WHERE retired = 0 AND {sql} ORDER BY key",  # noqa: S608
            (param,),
        ).fetchall()
        if rows:
            return [node_row(r) for r in rows]
    return []


def stats(store: Store) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {"nodes": {}, "edges": {}, "call_resolution": {}}
    for table in ("nodes", "edges"):
        for r in store.conn.execute(
            f"SELECT type, COUNT(*) AS n FROM {table} WHERE retired = 0 "  # noqa: S608
            "GROUP BY type ORDER BY type"
        ):
            out[table][r["type"]] = int(r["n"])
    for r in store.conn.execute(
        "SELECT json_extract(props, '$.resolution') AS res, COUNT(*) AS n FROM edges "
        "WHERE retired = 0 AND type = 'CALLS' GROUP BY res ORDER BY res"
    ):
        out["call_resolution"][str(r["res"])] = int(r["n"])
    return out


def node_row(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["props"] = json.loads(data["props"])
    data["evidence"] = json.loads(data["evidence"])
    data.pop("row_hash", None)
    data["retired"] = bool(data["retired"])
    return data


def _step(row: sqlite3.Row) -> PathStep:
    return PathStep(
        edge_id=row["id"],
        edge_type=row["type"],
        src=row["src"],
        dst=row["dst"],
        confidence=float(row["confidence"]),
        provenance=row["provenance"],
        props=json.loads(row["props"]),
    )


def _like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
