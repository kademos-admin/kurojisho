"""M1-AC5 / M1-AC6 / M1-AC7: each fixture repo against its hand-labelled expected.yaml."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable
from typing import Any

import pytest
from ruamel.yaml import YAML

from kurojisho.store import Store
from kurojisho.store import queries as q
from tests.conftest import FIXTURE_NAMES, FIXTURES, Scanned


def expected(name: str) -> dict[str, Any]:
    return YAML(typ="safe").load((FIXTURES / name / "expected.yaml").read_text())  # type: ignore[no-any-return]


def edges(store: Store, kind: str) -> list[tuple[str, str, dict[str, Any]]]:
    rows = store.conn.execute(
        "SELECT s.key AS src, d.key AS dst, e.props FROM edges e "
        "JOIN nodes s ON s.id = e.src JOIN nodes d ON d.id = e.dst "
        "WHERE e.retired = 0 AND e.type = ? ORDER BY 1, 2",
        (kind,),
    )
    return [
        (r["src"].split(":", 1)[1], r["dst"].split(":", 1)[1], json.loads(r["props"])) for r in rows
    ]


def call_metrics(store: Store, truth: set[tuple[str, str]]) -> tuple[float, float]:
    """Precision and recall of resolved (non-dynamic) CALLS edges against ground truth."""
    found = {(s, d) for s, d, p in edges(store, "CALLS") if p["resolution"] != "dynamic_unknown"}
    hits = len(found & truth)
    return hits / len(found), hits / len(truth)


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_matches_ground_truth(name: str, scan_fixture: Callable[..., Scanned]) -> None:
    want = expected(name)
    store = scan_fixture(name).store
    assert q.stats(store)["nodes"] == want["nodes"]

    calls = edges(store, "CALLS")
    resolution = {(s, d): p["resolution"] for s, d, p in calls}
    truth = {(s, d) for s, d, _ in want["calls"]}
    for src, dst, how in want["calls"]:
        assert resolution.get((src, dst)) == how, f"{src} -> {dst}"
    # An "exact" edge is a claim of certainty: every one must be a real call.
    exact = {pair for pair, how in resolution.items() if how == "exact"}
    assert exact <= truth, sorted(exact - truth)
    dynamic = {s for (s, _), how in resolution.items() if how == "dynamic_unknown"}
    assert dynamic == set(want["dynamic_callers"])
    precision, recall = call_metrics(store, truth)
    assert recall == 1.0
    assert precision >= want["min_call_precision"]

    routes = [
        (n["props"]["method"], n["props"]["path_pattern"], n["props"]["handler"])
        for n in q.find_nodes(store, node_type="Route")
    ]
    assert sorted(routes, key=str) == sorted((tuple(r) for r in want["routes"]), key=str)
    assert {(s, d) for s, d, _ in edges(store, "INHERITS")} == {tuple(i) for i in want["inherits"]}
    assert {(s, d) for s, d, _ in edges(store, "IMPORTS")} == {tuple(i) for i in want["imports"]}

    packages = {(d, p["direct"], p["scope"]) for s, d, p in edges(store, "DEPENDS_ON") if s == "."}
    assert packages == {tuple(p) for p in want["packages"]}
    for node in q.find_nodes(store, node_type="Package"):
        assert node["props"]["license"] is None and node["props"]["version"]

    owned: dict[str, list[str]] = defaultdict(list)
    for src, dst, _ in edges(store, "BELONGS_TO"):
        owned[dst].append(src)
    assert dict(owned) == want["belongs_to"]


def test_asset_nodes_are_asserted_with_defaults_marked(
    scan_fixture: Callable[..., Scanned],
) -> None:
    store = scan_fixture("py_flask_app").store
    assets = {n["name"]: n for n in q.find_nodes(store, node_type="Asset")}
    api, tests = assets["shop-api"], assets["test-suite"]
    assert api["provenance"] == "ASSERTED" and api["confidence"] == 1.0
    assert api["props"]["tier"] == 1 and api["props"]["asvs_level"] == 3
    assert api["props"]["exposure"] == "internet" and api["props"]["defaulted"] == []
    assert api["evidence"][0]["path"] == "kurojisho.context.yaml"
    assert api["evidence"][0]["start_line"] == 2
    # defaults fill tier/asvs_level and are flagged; exposure stays unknown, never "none"
    assert (tests["props"]["tier"], tests["props"]["asvs_level"]) == (3, 2)
    assert tests["props"]["defaulted"] == ["asvs_level", "tier"]
    assert tests["props"]["exposure"] is None
    row = store.conn.execute(
        "SELECT provenance, confidence FROM edges WHERE type = 'BELONGS_TO' LIMIT 1"
    ).fetchone()
    assert tuple(row) == ("ASSERTED", 1.0)


def test_languages_do_not_bleed_into_each_other(tmp_path: Any) -> None:
    """A polyglot tree: name matching must stay within one language family."""
    from kurojisho.ingest.pipeline import scan
    from tests.conftest import CLOCK, copy_fixture

    root = tmp_path / "polyglot"
    for name in FIXTURE_NAMES:
        copy_fixture(name, root)
    (root / "py_flask_app" / "kurojisho.context.yaml").unlink()
    store = Store(tmp_path / "g.db")
    scan(root, store, CLOCK)
    for src, dst, _ in edges(store, "CALLS") + edges(store, "INHERITS") + edges(store, "IMPORTS"):
        assert src.split("/", 1)[0] == dst.split("/", 1)[0], (src, dst)
    assert set(q.find_nodes(store, node_type="Repo")[0]["props"]["languages"]) == {
        "go",
        "java",
        "javascript",
        "python",
        "typescript",
    }
    # each manifest hangs off the directory that holds it
    owners = {s for s, _, _ in edges(store, "DEPENDS_ON")}
    assert owners == set(FIXTURE_NAMES)
