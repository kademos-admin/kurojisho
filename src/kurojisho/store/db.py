"""SQLite-backed graph store with diff-based writes."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from kurojisho.model import Edge, Node, canonical_json

SCHEMA_VERSION = 2


class StoreError(RuntimeError):
    """Raised when the store is unusable or the graph handed to it is inconsistent."""


@dataclass
class WriteStats:
    nodes_inserted: int = 0
    nodes_updated: int = 0
    nodes_retired: int = 0
    edges_inserted: int = 0
    edges_updated: int = 0
    edges_retired: int = 0

    @property
    def total(self) -> int:
        return sum(asdict(self).values())


_SHARED_COLUMNS = "owner_file, props, provenance, confidence, evidence, row_hash"
_LABEL_COLUMN = {"nodes": "name", "edges": "discriminator"}


class Store:
    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def _migrate(self) -> None:
        version = int(self.conn.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise StoreError(
                f"database schema v{version} is newer than this build (v{SCHEMA_VERSION})"
            )
        if version < SCHEMA_VERSION:
            schema = resources.files("kurojisho.store").joinpath("schema.sql").read_text("utf-8")
            self.conn.executescript(schema)
            self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    # -- meta ---------------------------------------------------------------------------
    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row[0])

    def set_meta(self, key: str, value: str) -> None:
        if self.get_meta(key) != value:
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    # -- scans --------------------------------------------------------------------------
    def last_scan_id(self) -> int | None:
        row = self.conn.execute("SELECT MAX(id) FROM scans").fetchone()
        return None if row[0] is None else int(row[0])

    def begin_scan(
        self, *, commit_sha: str | None, tree_hash: str, started_at: str, tool_version: str
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans(commit_sha, tree_hash, started_at, tool_version) VALUES(?,?,?,?)",
            (commit_sha, tree_hash, started_at, tool_version),
        )
        if cur.lastrowid is None:  # pragma: no cover - sqlite always sets it on INSERT
            raise StoreError("scan row was not created")
        return cur.lastrowid

    def finish_scan(self, scan_id: int, stats: dict[str, Any]) -> None:
        self.conn.execute(
            "UPDATE scans SET stats = ? WHERE id = ?", (canonical_json(stats), scan_id)
        )

    # -- per-file extraction cache ------------------------------------------------------
    def cached_files(self) -> dict[str, tuple[str, str]]:
        rows = self.conn.execute("SELECT path, content_hash, facts FROM files")
        return {r["path"]: (r["content_hash"], r["facts"]) for r in rows}

    def put_file(self, path: str, content_hash: str, facts: str) -> None:
        self.conn.execute(
            "INSERT INTO files(path, content_hash, facts) VALUES(?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET content_hash = excluded.content_hash, "
            "facts = excluded.facts",
            (path, content_hash, facts),
        )

    def delete_file(self, path: str) -> None:
        self.conn.execute("DELETE FROM files WHERE path = ?", (path,))

    # -- graph writes -------------------------------------------------------------------
    def apply(self, nodes: Iterable[Node], edges: Iterable[Edge], scan_id: int) -> WriteStats:
        """Make the live graph equal to ``nodes`` + ``edges``, writing only rows that differ.

        Rows that vanished are retired (kept, with ``last_seen`` pinned to the previous scan)
        rather than deleted. Must be called inside :meth:`transaction`.
        """
        desired_nodes: dict[str, Node] = {}
        for node in nodes:
            if node.id in desired_nodes:
                raise StoreError(f"duplicate node key: {node.key}")
            desired_nodes[node.id] = node
        desired_edges: dict[str, Edge] = {}
        for edge in edges:
            if edge.src not in desired_nodes or edge.dst not in desired_nodes:
                raise StoreError(f"edge {edge.type.value} {edge.src}->{edge.dst} has no endpoint")
            if edge.id in desired_edges:
                raise StoreError(f"duplicate edge: {edge.type.value} {edge.src}->{edge.dst}")
            desired_edges[edge.id] = edge

        previous = scan_id - 1 if scan_id > 1 else scan_id
        stats = WriteStats()
        # Edges are retired before nodes and inserted after them, so references stay valid.
        e_ins, e_upd, e_ret = self._diff("edges", desired_edges)
        n_ins, n_upd, n_ret = self._diff("nodes", desired_nodes)
        self._retire("edges", e_ret, previous)
        self._retire("nodes", n_ret, previous)
        for nid in n_ins:
            n = desired_nodes[nid]
            self.conn.execute(
                f"INSERT INTO nodes(id, type, key, name, {_SHARED_COLUMNS}, first_seen_scan) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (n.id, n.type.value, n.key, *_content(n), scan_id),
            )
        for nid in n_upd:
            self._update("nodes", nid, _content(desired_nodes[nid]))
        for eid in e_ins:
            e = desired_edges[eid]
            self.conn.execute(
                "INSERT INTO edges(id, type, src, dst, discriminator, "
                f"{_SHARED_COLUMNS}, first_seen_scan) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (e.id, e.type.value, e.src, e.dst, *_content(e), scan_id),
            )
        for eid in e_upd:
            self._update("edges", eid, _content(desired_edges[eid]))
        stats.nodes_inserted, stats.nodes_updated, stats.nodes_retired = (
            len(n_ins),
            len(n_upd),
            len(n_ret),
        )
        stats.edges_inserted, stats.edges_updated, stats.edges_retired = (
            len(e_ins),
            len(e_upd),
            len(e_ret),
        )
        return stats

    def _diff(
        self, table: str, desired: dict[str, Node] | dict[str, Edge]
    ) -> tuple[list[str], list[str], list[str]]:
        existing = {
            r["id"]: (r["row_hash"], bool(r["retired"]))
            for r in self.conn.execute(f"SELECT id, row_hash, retired FROM {table}")  # noqa: S608
        }
        insert, update = [], []
        for rid in sorted(desired):
            if rid not in existing:
                insert.append(rid)
            else:
                row_hash, retired = existing[rid]
                if retired or row_hash != desired[rid].row_hash():
                    update.append(rid)
        retire = sorted(
            r for r, (_, retired) in existing.items() if not retired and r not in desired
        )
        return insert, update, retire

    def _update(self, table: str, rid: str, content: tuple[Any, ...]) -> None:
        self.conn.execute(
            f"UPDATE {table} SET {_LABEL_COLUMN[table]}=?, owner_file=?, props=?, "  # noqa: S608
            "provenance=?, confidence=?, evidence=?, row_hash=?, retired=0, last_seen_scan=NULL "
            "WHERE id=?",
            (*content, rid),
        )

    def _retire(self, table: str, ids: list[str], last_seen: int) -> None:
        self.conn.executemany(
            f"UPDATE {table} SET retired=1, last_seen_scan=? WHERE id=?",  # noqa: S608
            [(last_seen, rid) for rid in ids],
        )


def _content(item: Node | Edge) -> tuple[Any, ...]:
    name = item.name if isinstance(item, Node) else item.discriminator
    return (
        name,
        item.owner_file,
        canonical_json(item.props),
        item.provenance.value,
        item.confidence,
        canonical_json([e.as_json() for e in item.evidence]),
        item.row_hash(),
    )
