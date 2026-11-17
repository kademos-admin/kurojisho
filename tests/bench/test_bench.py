"""M3-AC3: precision and recall on deliberately vulnerable applications.

Opt-in. The applications are third-party code: they are not vendored, not downloaded by
the tests and never executed. Point an environment variable at a checkout to run:

    KUROJISHO_BENCH_NODEGOAT   labelled baseline (needs the pinned scanners; offline)
    KUROJISHO_BENCH_SMOKE      colon-separated checkouts (e.g. Juice Shop, WebGoat) that
                               must scan without error; graph only, no labels
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from kurojisho.ingest.walker import read_git_head
from kurojisho.scanner import scan_with_tools
from kurojisho.store import Store
from kurojisho.tools.runners import ScanOptions
from kurojisho.tools.runtime import detect_runtime
from tests.conftest import CLOCK

pytestmark = [pytest.mark.bench, pytest.mark.slow]
LABELS = YAML(typ="safe").load((Path(__file__).parent / "nodegoat.yaml").read_text())
NODEGOAT = os.environ.get("KUROJISHO_BENCH_NODEGOAT")
SMOKE = [p for p in os.environ.get("KUROJISHO_BENCH_SMOKE", "").split(":") if p]


@pytest.fixture
def real_user_dirs(monkeypatch: pytest.MonkeyPatch) -> None:
    """The benchmark needs the real intel cache and built tools, unlike every other test."""
    monkeypatch.delenv("KUROJISHO_CACHE_DIR", raising=False)
    monkeypatch.delenv("KUROJISHO_CONFIG_DIR", raising=False)


@pytest.mark.needs_tools
@pytest.mark.skipif(not NODEGOAT, reason="set KUROJISHO_BENCH_NODEGOAT to a NodeGoat checkout")
def test_nodegoat_against_labelled_baseline(tmp_path: Path, real_user_dirs: None) -> None:
    root = Path(str(NODEGOAT))
    assert read_git_head(root) == LABELS["commit"], "check out the pinned commit"
    store = Store(tmp_path / "graph.db")
    _, outcomes = scan_with_tools(
        root, store, CLOCK, runtime=detect_runtime(None),
        options=ScanOptions(only=frozenset({"semgrep"}), offline=True),
    )  # fmt: skip
    assert {o.tool: o.status for o in outcomes}["semgrep"] == "ok"
    truth = {(path, line): cwe for path, line, cwe, _, _ in LABELS["weaknesses"]}
    found: dict[tuple[str, int], dict[str, object]] = {}
    for row in store.conn.execute("SELECT props FROM nodes WHERE type = 'Finding' AND retired = 0"):
        props = json.loads(row[0])
        if props["category"] == "sast" and props["triage_state"] != "duplicate":
            found[(props["path"], props["span"][0])] = props
    hits = set(found) & set(truth)
    expected = LABELS["expected"]
    assert len(hits) == expected["findings_true_positives"]
    assert len(set(found) - set(truth)) == expected["findings_false_positives"]
    assert round(len(hits) / len(truth), 2) == expected["findings_recall"]
    for key in hits:
        props = found[key]
        assert props["reach"]["value"] == "R4" and props["final_severity"] == "Critical"  # type: ignore[index]
        assert props["entry_points"] == ["app/routes/index.js::http POST /contributions"]
    sinks = {
        (json.loads(r[0])["path"], json.loads(r[0])["line"])
        for r in store.conn.execute(
            "SELECT n.props FROM edges e JOIN nodes n ON n.id = e.dst WHERE e.type = 'FLOWS_TO'"
        )
    }
    traced = sinks & set(truth)
    assert len(traced) == expected["flows_found"]
    assert round(len(traced) / len(truth), 2) == expected["flows_recall"]


@pytest.mark.skipif(not SMOKE, reason="set KUROJISHO_BENCH_SMOKE to one or more checkouts")
@pytest.mark.parametrize("checkout", SMOKE or ["-"])
def test_large_vulnerable_apps_scan_without_error(checkout: str, tmp_path: Path) -> None:
    store = Store(tmp_path / "graph.db")
    result, _ = scan_with_tools(
        Path(checkout), store, CLOCK, runtime=None, options=ScanOptions(tools=False)
    )
    counts = dict(
        store.conn.execute(
            "SELECT type, COUNT(*) FROM nodes WHERE retired = 0 GROUP BY 1"
        ).fetchall()
    )
    assert result.files_total > 100 and counts.get("EntryPoint", 0) > 50
    assert counts.get("Sink", 0) > 10
    rows = store.conn.execute("SELECT evidence FROM edges WHERE type = 'FLOWS_TO'").fetchall()
    assert rows and all(r[0] != "[]" for r in rows)
