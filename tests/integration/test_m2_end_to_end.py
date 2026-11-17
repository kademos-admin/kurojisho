"""M2 fixture end-to-end: every adapter on vuln_app (replayed real output), selection,
determinism (AC11), the intel CLI (AC8) and the golden export."""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import pytest
from syrupy.assertion import SnapshotAssertion
from typer.testing import CliRunner

from kurojisho.cli import app
from kurojisho.intel import refresh as r
from kurojisho.scanner import scan_with_tools, select
from kurojisho.store import Store
from kurojisho.store import queries as q
from kurojisho.store.graph import canonical_export
from kurojisho.tools.runners import RUNNERS, RepoProfile, ScanOptions
from tests.conftest import CLOCK, copy_fixture
from tests.helpers import FakeFetcher, FakeRuntime, all_handlers, make_intel, tool_gaps

runner = CliRunner()
#: Everything that runs by default and needs no install-time build.
DEFAULT = {n: x for n, x in RUNNERS.items() if n not in ("codeql", "govulncheck")}


@pytest.fixture(autouse=True)
def fixed_salt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUROJISHO_SECRET_SALT", "test-salt")


def full_scan(tmp_path: Path) -> tuple[Store, dict[str, str], Any]:
    root = copy_fixture("vuln_app", tmp_path)
    store = Store(tmp_path / "state" / "graph.db")
    result, outcomes = scan_with_tools(
        root, store, CLOCK, runtime=FakeRuntime(all_handlers()), runners=DEFAULT,
        intel=make_intel(tmp_path / "intel", CLOCK),
    )  # fmt: skip
    return store, {o.tool: o.status for o in outcomes}, result


def test_selection_covers_languages_manifests_and_iac() -> None:
    def names(langs: set[str], files: set[str], **options: Any) -> set[str]:
        profile = RepoProfile(frozenset(langs), frozenset(files))
        return {x.name for x in select(profile, ScanOptions(**options), RUNNERS)[0]}

    always = {"gitleaks", "trufflehog", "syft"}
    sca = {"osv-scanner", "trivy", "grype"}
    assert names({"python"}, {"a.py", "requirements.txt"}) == always | sca | {"semgrep", "bandit"}
    assert names({"go"}, {"go.mod", "main.go"}) == always | sca | {
        "semgrep",
        "gosec",
        "govulncheck",
    }
    assert names({"javascript"}, {"x.js", "yarn.lock"}) == always | sca | {"semgrep"}
    assert names(set(), {"deploy/app.tf"}) == always | {"checkov", "trivy-config"}
    assert "codeql" not in names({"python"}, {"a.py"})
    assert "codeql" in names({"python"}, {"a.py"}, enable=frozenset({"codeql"}))
    assert "codeql" not in names({"go"}, {"go.mod", "m.go"}, enable=frozenset({"codeql"}))


def test_every_default_tool_reports_on_the_fixture(tmp_path: Path) -> None:
    store, statuses, _ = full_scan(tmp_path)
    assert set(statuses) == set(DEFAULT) and set(statuses.values()) == {"ok"}
    counts = dict(
        store.conn.execute(
            "SELECT json_extract(props, '$.tool'), COUNT(*) FROM nodes "
            "WHERE type = 'Finding' AND retired = 0 GROUP BY 1"
        ).fetchall()
    )
    assert counts == {
        "semgrep": 19, "bandit": 10, "gosec": 9, "checkov": 37, "trivy-config": 37,
        "osv-scanner": 44, "trivy": 45, "grype": 44,
    }  # fmt: skip
    stats = q.stats(store)
    assert stats["nodes"]["Advisory"] == 45 and stats["edges"]["AFFECTED_BY"] == 45
    assert stats["edges"]["DUPLICATE_OF"] == 95 and tool_gaps(store) == []
    # every finding points at a file that exists in the graph
    located = store.conn.execute(
        "SELECT COUNT(DISTINCT e.src) FROM edges e JOIN nodes f ON f.id = e.dst "
        "WHERE e.type = 'LOCATED_IN' AND f.type = 'File' AND e.retired = 0"
    ).fetchone()[0]
    assert located == sum(counts.values())
    for view in ("nodes_seen", "edges_seen"):
        for row in store.conn.execute(f"SELECT provenance, confidence, evidence FROM {view}"):
            assert row["provenance"] in {"EXTRACTED", "INFERRED", "TOOL", "INTEL"}
            assert 0 <= row["confidence"] <= 1 and json.loads(row["evidence"])


def test_full_scan_is_deterministic_and_idempotent(tmp_path: Path) -> None:
    first, _, _ = full_scan(tmp_path / "a")
    second, _, _ = full_scan(tmp_path / "b")
    export = canonical_export(first)
    assert export == canonical_export(second)
    root = tmp_path / "a" / "vuln_app"
    again, outcomes = scan_with_tools(
        root, first, CLOCK, runtime=FakeRuntime(all_handlers()), runners=DEFAULT,
        intel=make_intel(tmp_path / "a" / "intel", CLOCK),
    )  # fmt: skip
    assert again.writes.total == 0 and canonical_export(first) == export
    cached = {o.tool for o in outcomes if o.status == "cached"}
    assert cached == set(DEFAULT) - {"gitleaks", "trufflehog"}


def test_vuln_app_golden(tmp_path: Path, snapshot: SnapshotAssertion) -> None:
    store, _, _ = full_scan(tmp_path)
    assert canonical_export(store) == snapshot


def test_intel_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    kev = json.dumps({"vulnerabilities": []}).encode()
    epss = gzip.compress(b"cve,epss,percentile\n")
    fetcher = FakeFetcher({r.KEV_URL: kev, r.EPSS_URL: epss})
    monkeypatch.setattr("kurojisho.cli.make_fetcher", lambda: fetcher)
    monkeypatch.setattr("kurojisho.cli.detect_runtime", lambda _p=None: None)
    empty = json.loads(runner.invoke(app, ["intel", "status", "--json"]).stdout)
    assert empty["sources"] == []
    result = runner.invoke(app, ["intel", "refresh"])
    assert result.exit_code == 1  # some sources were unreachable, and that is reported
    assert "updated  kev" in result.output and "updated  epss" in result.output
    assert "failed   trivy-db" in result.output and "failed   grype-db" in result.output
    status = json.loads(runner.invoke(app, ["intel", "status", "--json"]).stdout)
    assert [s["source"] for s in status["sources"]] == ["epss", "kev"]
    assert all(not s["stale"] and s["age_hours"] == 0.0 for s in status["sources"])
    assert len(status["snapshot"]) == 64 and status["cache"].endswith("intel")
    assert "kev" in runner.invoke(app, ["intel", "status"]).output
    fetcher.requested.clear()
    runner.invoke(app, ["intel", "refresh"])
    assert r.KEV_URL not in fetcher.requested  # under a day old: left alone
    runner.invoke(
        app, ["intel", "refresh", "--force", "--nvd", "5", "--db", str(tmp_path / "none.db")]
    )
    assert r.KEV_URL in fetcher.requested
