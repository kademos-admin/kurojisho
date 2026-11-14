"""M1-AC2 / M1-AC4 / M1-AC8: store writes, provenance columns, CTE queries, NetworkX."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from kurojisho.model import EdgeType
from kurojisho.store import Store, StoreError
from kurojisho.store import queries as q
from kurojisho.store.graph import canonical_export, to_networkx
from tests.helpers import call, fn


def scan(store: Store, nodes: list, edges: list, commit: str | None = None):  # type: ignore[no-untyped-def]
    with store.transaction():
        sid = store.begin_scan(
            commit_sha=commit, tree_hash="t", started_at="2024-01-01T00:00:00Z", tool_version="x"
        )
        return store.apply(nodes, edges, sid)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "g.db")


def test_insert_then_identical_apply_writes_nothing(store: Store) -> None:
    a, b = fn("a"), fn("b")
    first = scan(store, [a, b], [call(a, b)])
    assert (first.nodes_inserted, first.edges_inserted) == (2, 1)
    before = store.conn.total_changes
    again = scan(store, [b, a], [call(a, b)])
    assert again.total == 0
    assert store.conn.total_changes - before == 1  # only the scans row


def test_update_retire_and_revive_keep_first_seen(store: Store) -> None:
    a, b = fn("a"), fn("b")
    scan(store, [a, b], [call(a, b)], commit="c1")
    changed = scan(store, [fn("a", signature="(x)")], [], commit="c2")
    assert (changed.nodes_updated, changed.nodes_retired, changed.edges_retired) == (1, 1, 1)
    row = store.conn.execute("SELECT * FROM nodes_seen WHERE id = ?", (b.id,)).fetchone()
    assert (row["retired"], row["first_seen_commit"], row["last_seen_commit"]) == (1, "c1", "c1")
    live = store.conn.execute("SELECT * FROM nodes_seen WHERE id = ?", (a.id,)).fetchone()
    assert (live["first_seen_commit"], live["last_seen_commit"]) == ("c1", "c2")
    revived = scan(store, [a, b], [call(a, b)], commit="c3")
    assert (revived.nodes_updated, revived.edges_updated) == (2, 1)
    row = store.conn.execute("SELECT * FROM nodes_seen WHERE id = ?", (b.id,)).fetchone()
    assert (row["retired"], row["first_seen_commit"], row["last_seen_commit"]) == (0, "c1", "c3")


def test_apply_rejects_inconsistent_graphs_and_rolls_back(store: Store) -> None:
    a, b = fn("a"), fn("b")
    with pytest.raises(StoreError, match="no endpoint"):
        scan(store, [a], [call(a, b)])
    with pytest.raises(StoreError, match="duplicate node"):
        scan(store, [a, a], [])
    with pytest.raises(StoreError, match="duplicate edge"):
        scan(store, [a, b], [call(a, b), call(a, b)])
    assert store.last_scan_id() is None  # failed scans leave no trace


def test_schema_rejects_rows_without_provenance(store: Store) -> None:
    scan(store, [fn("a")], [])
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("UPDATE nodes SET evidence = '[]'")
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("UPDATE nodes SET confidence = 1.5")
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("UPDATE nodes SET provenance = 'GUESS'")


def test_newer_schema_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "g.db"
    Store(path).conn.execute("PRAGMA user_version=99")
    with pytest.raises(StoreError, match="newer"):
        Store(path)


def test_meta_and_file_cache(store: Store) -> None:
    assert store.get_meta("k") is None
    store.set_meta("k", "v")
    store.set_meta("k", "v2")
    assert store.get_meta("k") == "v2"
    store.put_file("a.py", "h1", "{}")
    store.put_file("a.py", "h2", "{}")
    assert store.cached_files() == {"a.py": ("h2", "{}")}
    store.delete_file("a.py")
    assert store.cached_files() == {}


def _chain(store: Store) -> list:  # type: ignore[type-arg]
    # a -> b -> c -> a (cycle), a -> d, c -> d, e isolated
    n = {k: fn(k) for k in "abcde"}
    edges = [call(n[s], n[d]) for s, d in ("ab", "bc", "ca", "ad", "cd")]
    scan(store, list(n.values()), edges)
    return [n[k] for k in "abcde"]


def test_cte_distances_terminate_on_cycles(store: Store) -> None:
    a, b, c, d, e = _chain(store)
    out = q.distances(store, a.id, edge_types=[EdgeType.CALLS])
    assert out == {a.id: 0, b.id: 1, d.id: 1, c.id: 2}
    assert e.id not in out
    assert q.distances(store, d.id, direction="in") == {d.id: 0, a.id: 1, c.id: 1, b.id: 2}
    assert q.distances(store, a.id, max_depth=1) == {a.id: 0, b.id: 1, d.id: 1}
    assert q.distances(store, a.id, edge_types=[EdgeType.IMPORTS]) == {a.id: 0}


def test_shortest_path_and_neighbours(store: Store) -> None:
    a, b, c, d, e = _chain(store)
    path = q.shortest_path(store, b.id, d.id)
    assert path is not None
    assert [(s.src, s.dst) for s in path] == [(b.id, c.id), (c.id, d.id)]
    assert path[0].props == {"resolution": "exact"}
    assert q.shortest_path(store, a.id, e.id) is None
    assert q.shortest_path(store, a.id, a.id) == []
    assert q.shortest_path(store, b.id, d.id, max_depth=1) is None
    assert {s.dst for s in q.neighbours(store, a.id, EdgeType.CALLS)} == {b.id, d.id}
    assert {s.src for s in q.neighbours(store, d.id, EdgeType.CALLS, "in")} == {a.id, c.id}


def test_retired_edges_are_invisible_to_queries(store: Store) -> None:
    a, b = fn("a"), fn("b")
    scan(store, [a, b], [call(a, b)])
    scan(store, [a, b], [])
    assert q.distances(store, a.id) == {a.id: 0}
    assert to_networkx(store).number_of_edges() == 0
    assert q.stats(store)["edges"] == {}


def test_lookup_helpers(store: Store) -> None:
    a, *_ = _chain(store)
    assert [n["id"] for n in q.resolve_ref(store, a.id)] == [a.id]
    assert [n["id"] for n in q.resolve_ref(store, a.key)] == [a.id]
    assert [n["id"] for n in q.resolve_ref(store, "a.py::a")] == [a.id]
    assert [n["id"] for n in q.resolve_ref(store, "a")] == [a.id]
    assert q.resolve_ref(store, "%") == []
    assert len(q.find_nodes(store, node_type="Function")) == 5
    assert len(q.find_nodes(store, node_type="Function", limit=2)) == 2
    assert q.find_nodes(store, name="zzz") == []
    node = q.get_node(store, a.id)
    assert node is not None and node["first_seen_at"] == "2024-01-01T00:00:00Z"
    assert q.get_node(store, "nope") is None
    assert q.stats(store)["call_resolution"] == {"exact": 5}


def test_networkx_matches_db_and_export_is_order_independent(tmp_path: Path) -> None:
    one, two = Store(tmp_path / "1.db"), Store(tmp_path / "2.db")
    nodes = _chain(one)
    n = {x.name: x for x in nodes}
    edges = [call(n[s], n[d]) for s, d in ("cd", "ad", "ca", "bc", "ab")]
    scan(two, list(reversed(nodes)), edges)
    assert canonical_export(one) == canonical_export(two)
    graph = to_networkx(one)
    assert graph.number_of_nodes() == 5 and graph.number_of_edges() == 5
    assert graph.nodes[n["a"].id]["provenance"] == "EXTRACTED"
    _, _, data = next(iter(graph.out_edges(n["b"].id, data=True)))
    assert data["props"] == {"resolution": "exact"} and data["evidence"]
