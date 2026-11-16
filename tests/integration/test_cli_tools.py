"""M2-AC1 / M2-AC9: scanner-related commands of the CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kurojisho.cli import app
from kurojisho.tools.runners import RUNNERS
from tests.conftest import copy_fixture
from tests.helpers import PINS, TOOL_OUTPUTS, FakeRuntime, writes

runner = CliRunner()
SEMGREP = (TOOL_OUTPUTS / "semgrep" / "vuln_app.sarif").read_bytes()


def fake(installed: bool = True) -> FakeRuntime:
    return FakeRuntime(
        {
            "semgrep": writes({"semgrep.sarif": SEMGREP}),
            "gitleaks": writes({"dir.json": "[]", "git.json": "[]"}),
        },
        installed=installed,
    )


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("COLUMNS", "220")
    monkeypatch.setenv("KUROJISHO_SECRET_SALT", "salt")
    return copy_fixture("vuln_app", tmp_path)


def use(monkeypatch: pytest.MonkeyPatch, runtime: FakeRuntime | None) -> None:
    monkeypatch.setattr("kurojisho.cli.detect_runtime", lambda _preferred=None: runtime)
    two = {name: RUNNERS[name] for name in ("semgrep", "gitleaks")}
    monkeypatch.setattr("kurojisho.scanner.RUNNERS", two)


def run(*args: str, code: int = 0) -> str:
    """Everything printed (stdout and stderr together)."""
    result = runner.invoke(app, list(args))
    assert result.exit_code == code, result.output
    return result.output


def stdout(*args: str) -> str:
    """Standard output only: warnings go to stderr and must not corrupt --json."""
    result = runner.invoke(app, list(args))
    assert result.exit_code == 0, result.output
    return result.stdout


def test_scan_runs_tools_and_reports_them(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    use(monkeypatch, fake())
    summary = json.loads(stdout("scan", str(repo), "--json"))
    assert summary["tools"] == {
        "gitleaks": {"status": "ok", "findings": 0},
        "semgrep": {"status": "ok", "findings": 19},
    }
    stats = json.loads(stdout("query", "stats", "--repo", str(repo), "--json"))
    assert stats["nodes"]["Finding"] == 19
    text = run("scan", str(repo))
    assert "tool: semgrep" in text and "cached (19 findings)" in text
    listed = json.loads(
        stdout("query", "nodes", "--type", "Finding", "--repo", str(repo), "--json")
    )
    assert listed[0]["props"]["raw_severity"] in {"High", "Medium"}


def test_first_scan_installs_missing_tools_and_says_so(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = fake(installed=False)
    use(monkeypatch, runtime)
    output = run("scan", str(repo))
    assert f"installing semgrep {PINS['semgrep'].version} (network" in output
    assert len(runtime.pulled) == 2


def test_offline_and_missing_runtime_warn_about_gaps(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = fake(installed=False)
    use(monkeypatch, runtime)
    output = run("scan", str(repo), "--offline")
    assert "coverage gaps: gitleaks, semgrep" in output and runtime.pulled == []
    use(monkeypatch, None)
    output = run("scan", str(repo), "--db", str(repo.parent / "other.db"))
    assert "no container runtime found" in output and "sandbox_unavailable" in output


def test_tool_selection_flags(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    use(monkeypatch, fake())
    only = json.loads(stdout("scan", str(repo), "--tools", "semgrep", "--json"))
    assert only["tools"]["gitleaks"]["status"] == "skipped_by_user"
    skipped = json.loads(stdout("scan", str(repo), "--skip", "semgrep, gitleaks", "--json"))
    assert {t["status"] for t in skipped["tools"].values()} == {"skipped_by_user"}
    assert "unknown tool(s): nessus" in run("scan", str(repo), "--tools", "nessus", code=2)
    assert json.loads(stdout("scan", str(repo), "--no-tools", "--json"))["tools"] == {}


def test_tools_list_install_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "220")
    runtime = fake(installed=False)
    use(monkeypatch, runtime)
    listed = json.loads(stdout("tools", "list", "--json"))
    assert {t["name"] for t in listed} == set(PINS)
    assert all(not t["installed"] and "@sha256:" in t["image"] and t["licence"] for t in listed)
    assert "MISSING semgrep" in run("tools", "verify", code=1)
    assert "installed: gitleaks" in run("tools", "install", "gitleaks")
    assert runtime.pulled == [PINS["gitleaks"].ref]
    assert "unknown tool(s): nope" in run("tools", "install", "nope", code=2)
    # govulncheck is built at install time; here the build fails, the rest still install
    output = run("tools", "install", code=1)
    assert "failed: govulncheck" in output and "installed: bandit" in output
    assert len(runtime.pulled) == len(PINS)
    assert "nothing to do" in run("tools", "install", "semgrep")
    verified = run("tools", "verify", code=1)
    assert "MISSING govulncheck" in verified and "ok      semgrep" in verified
    assert "AGPL-3.0-only" in run("tools", "list")
    use(monkeypatch, None)
    assert "no container runtime" in run("tools", "install", code=2)
    assert "MISSING" in run("tools", "verify", code=1)
