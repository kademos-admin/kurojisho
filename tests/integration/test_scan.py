"""M1-AC1..AC4, AC9: determinism, no-op re-scan, incremental scope, provenance, safety."""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import socket
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from kurojisho.config.context import ContextError
from kurojisho.ingest import pipeline, walker
from kurojisho.ingest.pipeline import ScanError, scan
from kurojisho.store import Store
from kurojisho.store import queries as q
from kurojisho.store.graph import canonical_export
from tests.conftest import CLOCK, FIXTURE_NAMES, Scanned, copy_fixture


def rows(store: Store, table: str) -> dict[str, tuple[Any, ...]]:
    return {r["id"]: tuple(r) for r in store.conn.execute(f"SELECT * FROM {table}")}


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode())
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def fresh_export(root: Path, tmp_path: Path, tag: str) -> str:
    store = Store(tmp_path / f"fresh-{tag}.db")
    scan(root, store, CLOCK)
    return canonical_export(store)


# -- AC1: determinism -----------------------------------------------------------------
@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_two_fresh_scans_are_byte_identical(
    name: str, scan_fixture: Callable[..., Scanned], monkeypatch: pytest.MonkeyPatch
) -> None:
    first = canonical_export(scan_fixture(name).store)
    real_walk = os.walk

    def shuffled(*args: Any, **kwargs: Any) -> Iterator[tuple[str, list[str], list[str]]]:
        for current, dirs, files in real_walk(*args, **kwargs):
            random.Random(7).shuffle(dirs)
            random.Random(7).shuffle(files)
            yield current, dirs, files

    monkeypatch.setattr(walker.os, "walk", shuffled)  # filesystem order must not matter
    second = canonical_export(scan_fixture(name).store)
    assert first == second
    assert first.endswith("\n") and "first_seen" not in first and "2024-01-01" not in first


def test_full_rescan_equals_incremental(scan_fixture: Callable[..., Scanned]) -> None:
    scanned = scan_fixture("py_flask_app")
    before = canonical_export(scanned.store)
    result = scanned.rescan(full=True)
    assert len(result.files_parsed) == 6 and result.writes.total == 0
    assert canonical_export(scanned.store) == before


# -- AC2: no-op re-scan ----------------------------------------------------------------
@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_rescan_without_changes_writes_no_graph_rows(
    name: str, scan_fixture: Callable[..., Scanned]
) -> None:
    scanned = scan_fixture(name)
    nodes, edges = rows(scanned.store, "nodes"), rows(scanned.store, "edges")
    cache = scanned.store.cached_files()
    changes = scanned.store.conn.total_changes
    result = scanned.rescan()
    assert result.writes.total == 0 and result.files_parsed == []
    assert result.files_from_cache == len(cache)
    assert rows(scanned.store, "nodes") == nodes and rows(scanned.store, "edges") == edges
    assert scanned.store.cached_files() == cache
    # the only writes are the scan log row and its stats
    assert scanned.store.conn.total_changes - changes == 2
    assert scanned.store.last_scan_id() == 2


# -- AC3: a single-file change only touches that file's subgraph -------------------------
def changed(before: dict[str, tuple[Any, ...]], after: dict[str, tuple[Any, ...]]) -> set[str]:
    return {k for k in before.keys() | after.keys() if before.get(k) != after.get(k)}


def test_single_file_edit_only_touches_that_files_rows(
    scan_fixture: Callable[..., Scanned], tmp_path: Path
) -> None:
    scanned = scan_fixture("py_flask_app")
    store = scanned.store
    nodes, edges = rows(store, "nodes"), rows(store, "edges")
    target = scanned.root / "shop" / "db.py"
    target.write_text(
        target.read_text()
        + "\n\ndef vacuum(db):\n    log_query('VACUUM')\n    return db.query('VACUUM')\n"
    )
    result = scanned.rescan()
    assert result.files_parsed == ["shop/db.py"]
    assert result.files_from_cache == 5
    after_nodes, after_edges = rows(store, "nodes"), rows(store, "edges")
    owner = {"nodes": 4, "edges": 5}  # column index of owner_file
    touched_nodes = changed(nodes, after_nodes)
    touched_edges = changed(edges, after_edges)
    assert touched_nodes and touched_edges
    for nid in touched_nodes:
        assert after_nodes[nid][owner["nodes"]] == "shop/db.py", after_nodes[nid][2]
    for eid in touched_edges:
        assert after_edges[eid][owner["edges"]] == "shop/db.py"
    assert result.writes.nodes_inserted == 1  # vacuum
    # evidence carries the file's content hash, so every row of db.py is refreshed
    owned = sum(1 for row in nodes.values() if row[owner["nodes"]] == "shop/db.py")
    assert result.writes.nodes_updated == owned
    assert result.writes.nodes_retired == 0
    assert canonical_export(store) == fresh_export(scanned.root, tmp_path, "edit")


def test_removing_a_definition_re_resolves_inbound_edges_only(
    scan_fixture: Callable[..., Scanned], tmp_path: Path
) -> None:
    scanned = scan_fixture("py_flask_app")
    store = scanned.store
    nodes = rows(store, "nodes")
    edges = rows(store, "edges")
    target = scanned.root / "shop" / "services.py"
    target.write_text(target.read_text().replace("def make_service(path):", "def build(path):"))
    result = scanned.rescan()
    assert result.files_parsed == ["shop/services.py"]
    after_nodes, after_edges = rows(store, "nodes"), rows(store, "edges")
    owners = {after_nodes[n][4] for n in changed(nodes, after_nodes)}
    # app.py imported and called make_service: its rows are re-resolved, nothing else moves
    assert owners == {"shop/services.py", "shop/app.py"}
    assert {after_edges[e][5] for e in changed(edges, after_edges)} <= owners
    gone = q.resolve_ref(store, "shop/services.py::make_service")
    assert gone == []
    retired = store.conn.execute(
        "SELECT retired, last_seen_scan FROM nodes WHERE key LIKE '%::make_service'"
    ).fetchone()
    assert tuple(retired) == (1, 1)  # kept as a tombstone, last seen in scan 1
    app_file = q.resolve_ref(store, "File:shop/app.py")[0]
    assert "make_service" in app_file["props"]["calls_unresolved"]
    assert canonical_export(store) == fresh_export(scanned.root, tmp_path, "rm")


def test_add_delete_and_rename_match_a_fresh_scan(
    scan_fixture: Callable[..., Scanned], tmp_path: Path
) -> None:
    scanned = scan_fixture("js_express_app")
    root, store = scanned.root, scanned.store
    (root / "src" / "extra.ts").write_text("export function extra() { return 1; }\n")
    assert scanned.rescan().files_parsed == ["src/extra.ts"]
    assert canonical_export(store) == fresh_export(root, tmp_path, "add")

    (root / "src" / "routes" / "render.ts").rename(root / "src" / "routes" / "view.ts")
    assert scanned.rescan().files_parsed == ["src/routes/view.ts"]
    assert "src/routes/render.ts" not in store.cached_files()
    assert canonical_export(store) == fresh_export(root, tmp_path, "rename")

    (root / "src" / "extra.ts").unlink()
    result = scanned.rescan()
    assert result.files_parsed == [] and result.writes.nodes_retired == 2
    assert canonical_export(store) == fresh_export(root, tmp_path, "delete")

    # restoring the file revives the same rows; first_seen is preserved
    (root / "src" / "extra.ts").write_text("export function extra() { return 1; }\n")
    scanned.rescan()
    row = store.conn.execute(
        "SELECT retired, first_seen_scan, last_seen_scan FROM nodes WHERE key = ?",
        ("Function:src/extra.ts::extra",),
    ).fetchone()
    assert tuple(row) == (0, 2, None)


def test_extractor_version_change_invalidates_the_cache(
    scan_fixture: Callable[..., Scanned], monkeypatch: pytest.MonkeyPatch
) -> None:
    scanned = scan_fixture("go_http_app")
    monkeypatch.setattr(pipeline, "EXTRACTOR_VERSION", "next")
    result = scanned.rescan()
    assert len(result.files_parsed) == 3 and result.writes.total == 0
    assert scanned.store.get_meta("extractor_version") == "next"


# -- AC4: provenance on every row --------------------------------------------------------
@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_every_node_and_edge_carries_provenance_and_evidence(
    name: str, scan_fixture: Callable[..., Scanned]
) -> None:
    scanned = scan_fixture(name)
    valid = {"EXTRACTED", "INFERRED", "ASSERTED"}  # the only sources M1 can produce
    total = 0
    for view in ("nodes_seen", "edges_seen"):
        for row in scanned.store.conn.execute(f"SELECT * FROM {view}"):
            total += 1
            assert row["provenance"] in valid
            assert 0.0 <= row["confidence"] <= 1.0
            assert row["first_seen_at"] == "2024-01-01T00:00:00Z" == row["last_seen_at"]
            evidence = json.loads(row["evidence"])
            assert evidence
            for item in evidence:
                assert item["source"]
                target = scanned.root / item["path"]
                assert target.exists(), item
                if "start_line" in item:
                    lines = target.read_bytes().count(b"\n") + 1
                    assert 1 <= item["start_line"] <= item.get("end_line", lines) <= lines
                if target.is_file():
                    assert item["content_hash"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert total > 50
    inferred = scanned.store.conn.execute(
        "SELECT DISTINCT type FROM edges WHERE provenance = 'INFERRED'"
    ).fetchall()
    assert {r[0] for r in inferred} <= {"CALLS", "INHERITS", "DEFINES"}
    low = scanned.store.conn.execute(
        "SELECT COUNT(*) FROM edges WHERE type = 'CALLS' AND confidence NOT IN (0.9, 0.5, 0.1)"
    ).fetchone()
    assert low[0] == 0


def test_commit_sha_is_recorded_on_first_and_last_seen(tmp_path: Path) -> None:
    root = copy_fixture("go_http_app", tmp_path)
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("1" * 40)
    store = Store(tmp_path / "g.db")
    assert scan(root, store, CLOCK).commit_sha == "1" * 40
    (root / ".git" / "HEAD").write_text("2" * 40)
    (root / "main.go").write_text((root / "main.go").read_text() + "\nfunc added() {}\n")
    scan(root, store, CLOCK)
    old = q.resolve_ref(store, "main.go::main")[0]
    new = q.resolve_ref(store, "main.go::added")[0]
    assert (old["first_seen_commit"], old["last_seen_commit"]) == ("1" * 40, "2" * 40)
    assert (new["first_seen_commit"], new["last_seen_commit"]) == ("2" * 40, "2" * 40)
    assert ".git" in q.find_nodes(store, node_type="Repo")[0]["props"]["skipped_dirs"]


# -- AC9: the target is read, never executed or modified -----------------------------------
@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_scan_executes_nothing_uses_no_network_and_leaves_target_untouched(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = copy_fixture(name, tmp_path)
    before = tree_digest(root)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("scan tried to start a process or open a socket")

    for module, attr in (
        (subprocess, "Popen"),
        (subprocess, "run"),
        (os, "system"),
        (os, "execv"),
        (os, "posix_spawn"),
        (socket, "socket"),
        (socket, "create_connection"),
    ):
        monkeypatch.setattr(module, attr, forbidden)
    store = Store(tmp_path / "g.db")
    scan(root, store, CLOCK)
    assert tree_digest(root) == before
    assert not list(tmp_path.rglob("PWNED*"))
    assert q.stats(store)["nodes"]["File"] > 0


# -- gaps are recorded, not hidden ---------------------------------------------------------
def test_syntax_errors_oversized_and_unreadable_sources_are_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "ok.py").write_text("def fine():\n    pass\n")
    (root / "broken.py").write_text("def ok():\n    pass\n\ndef broken(:\n")
    (root / "huge.py").write_text("x = 1\n" * 50)
    (root / "data.bin").write_bytes(b"\x00\x01")
    (root / "yarn.lock").write_text("")
    monkeypatch.setattr(pipeline, "MAX_SOURCE_BYTES", 100)
    store = Store(tmp_path / "g.db")
    result = scan(root, store, CLOCK)
    assert result.files_with_parse_errors == ["broken.py"]
    files = {n["name"]: n["props"] for n in q.find_nodes(store, node_type="File")}
    assert files["ok.py"]["parse_status"] == "ok"
    assert files["broken.py"]["parse_status"] == "partial"
    assert files["broken.py"]["parse_error_lines"]
    assert q.resolve_ref(store, "broken.py::ok")  # what could be parsed is kept
    assert files["huge.py"]["parse_status"] == "skipped"
    assert files["huge.py"]["parse_skip_reason"] == "too_large"
    assert files["data.bin"]["lang"] is None and "parse_status" not in files["data.bin"]
    assert files["yarn.lock"]["manifest"] == "unsupported"
    assert files["yarn.lock"]["manifest_notes"] == ["manifest_format_not_supported"]


def test_bad_context_or_target_stops_the_scan_before_any_write(tmp_path: Path) -> None:
    root = copy_fixture("py_flask_app", tmp_path)
    (root / "kurojisho.context.yaml").write_text("assets: [{id: a, paths: ['x'], tier: 9}]")
    store = Store(tmp_path / "g.db")
    with pytest.raises(ContextError, match="tier"):
        scan(root, store, CLOCK)
    with pytest.raises(ScanError, match="not a directory"):
        scan(root / "missing", store, CLOCK)
    with pytest.raises(ScanError, match="cannot read context"):
        scan(root, store, CLOCK, context_path=tmp_path / "nope.yaml")
    assert store.last_scan_id() is None and rows(store, "nodes") == {}


def test_external_context_file_and_context_edits(tmp_path: Path) -> None:
    root = copy_fixture("go_http_app", tmp_path)
    context = tmp_path / "ctx.yaml"
    context.write_text("assets:\n  - id: inv\n    paths: ['internal/**']\n    tier: 2\n")
    store = Store(tmp_path / "g.db")
    scan(root, store, CLOCK, context_path=context)
    asset = q.find_nodes(store, node_type="Asset")[0]
    assert asset["evidence"][0]["path"] == "<external>/ctx.yaml"
    assert asset["props"]["tier"] == 2
    context.write_text("assets:\n  - id: inv\n    paths: ['internal/**']\n    tier: 1\n")
    result = scan(root, store, CLOCK, context_path=context)
    assert result.files_parsed == []  # business context changes never force a re-parse
    assert q.find_nodes(store, node_type="Asset")[0]["props"]["tier"] == 1


def test_fixture_copy_helper_leaves_ground_truth_behind(tmp_path: Path) -> None:
    root = copy_fixture("go_http_app", tmp_path)
    assert not (root / "expected.yaml").exists()
    shutil.rmtree(root)
