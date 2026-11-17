"""M1-AC8: the command line end to end (init, scan, query)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kurojisho import __version__
from kurojisho.cli import app
from tests.conftest import copy_fixture

runner = CliRunner()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    monkeypatch.setenv("COLUMNS", "200")
    root = copy_fixture("py_flask_app", tmp_path)
    monkeypatch.chdir(root)
    return root


def run(*args: str, code: int = 0) -> str:
    result = runner.invoke(app, list(args))
    assert result.exit_code == code, result.output
    return result.output


def test_version_and_help() -> None:
    assert run("--version").strip() == __version__
    assert "scan" in run("--help") and "query" in run("--help")
    assert "Usage" in runner.invoke(app, []).output


def test_init_creates_state_and_keeps_existing_context(tmp_path: Path) -> None:
    out = run("init", str(tmp_path))
    assert (tmp_path / ".kurojisho" / "graph.db").is_file()
    context = tmp_path / "kurojisho.context.yaml"
    assert "context file created" in out and context.read_text().startswith("# Business context")
    context.write_text("assets: []\n")
    assert "context file kept" in run("init", str(tmp_path))
    assert context.read_text() == "assets: []\n"
    run("scan", "--no-tools", str(tmp_path))  # the starter template is a valid, empty context
    assert "not a directory" in run("init", str(tmp_path / "missing"), code=2)


def test_scan_then_query_round_trip(repo: Path) -> None:
    first = json.loads(run("scan", "--no-tools", ".", "--json"))
    assert first["scan_id"] == 1 and first["files_parsed"] == 6 and first["nodes_inserted"] == 50
    again = json.loads(run("scan", "--no-tools", str(repo), "--json"))
    assert again["scan_id"] == 2 and again["files_parsed"] == 0 and again["nodes_inserted"] == 0
    assert "scan #3" in run("scan", "--no-tools", ".", "--full")

    stats = json.loads(run("query", "stats", "--json"))
    assert stats["nodes"]["Function"] == 18 and stats["call_resolution"]["exact"] >= 5
    assert "CALLS" in run("query", "stats")

    listed = json.loads(run("query", "nodes", "--type", "Route", "--json"))
    assert [n["name"] for n in listed] == [
        "GET /orders/<int:order_id>",
        "GET /orders/search",
        "POST /orders/search",
        "POST /plugins/<name>",
    ]
    assert "Package:pkg:pypi/flask@3.0.3" in run("query", "nodes", "--type", "Package")
    assert len(json.loads(run("query", "nodes", "--limit", "3", "--json"))) == 3

    node = json.loads(run("query", "show", "shop/db.py::log_query"))
    assert node["provenance"] == "EXTRACTED" and node["evidence"][0]["start_line"] == 18
    assert node["first_seen_at"] == "2023-11-14T22:13:20Z"

    callers = json.loads(run("query", "callers", "log_query", "--json"))
    assert callers == [
        {
            "confidence": 0.9,
            "function": "Function:shop/db.py::AuditedDatabase.query",
            "resolution": "exact",
        }
    ]
    assert "OrderService.__init__" in run("query", "callees", "make_service")

    path = json.loads(run("query", "path", "get_order", "log_query", "--json"))
    assert [step["dst"].split("::")[1] for step in path] == [
        "OrderService.find",
        "AuditedDatabase.query",
        "log_query",
    ]
    assert [step["props"]["resolution"] for step in path] == ["name_match", "name_match", "exact"]
    assert "name_match" in run("query", "path", "get_order", "log_query")
    contains = run(
        "query", "path", "Repo:.", "log_query", "--edge", "CONTAINS", "--edge", "DEFINES"
    )
    assert "DEFINES" in contains
    assert "no path" in run("query", "path", "log_query", "get_order", code=1)
    assert "no path" in run("query", "path", "get_order", "log_query", "--max-depth", "1", code=1)


def test_export_is_stable_and_can_be_written_to_a_file(repo: Path, tmp_path: Path) -> None:
    run("scan", "--no-tools", ".")
    printed = run("query", "export")
    target = tmp_path / "graph.json"
    run("query", "export", "-o", str(target), "--repo", str(repo))
    assert target.read_text() == printed
    data = json.loads(printed)
    assert len(data["nodes"]) == 50 and len(data["edges"]) == 73
    run("scan", "--no-tools", ".")
    assert run("query", "export") == printed


def test_errors_are_reported_with_exit_code_2(repo: Path, tmp_path: Path) -> None:
    assert "no graph" in run("query", "stats", code=2)
    assert "not a directory" in run("scan", "--no-tools", str(tmp_path / "nope"), code=2)
    run("scan", "--no-tools", ".")
    assert "no node matches" in run("query", "show", "does-not-exist", code=2)
    assert "ambiguous" in run("query", "callers", "query", code=2)
    (repo / "kurojisho.context.yaml").write_text("assets: [{id: a}]")
    assert "paths" in run("scan", "--no-tools", ".", code=2)
    (repo / "kurojisho.context.yaml").unlink()
    missing = str(tmp_path / "c.yaml")
    assert "cannot read context" in run("scan", "--no-tools", ".", "--context", missing, code=2)


def test_explicit_db_and_parse_error_warning(tmp_path: Path) -> None:
    root = tmp_path / "r"
    root.mkdir()
    (root / "bad.py").write_text("def broken(:\n")
    db = tmp_path / "custom.db"
    result = runner.invoke(app, ["scan", "--no-tools", str(root), "--db", str(db)])
    assert result.exit_code == 0 and db.is_file()
    assert "syntax" in result.output
    assert not (root / ".kurojisho").exists()
    assert "File" in run("query", "stats", "--db", str(db))
