"""M2-AC2..AC6, AC9, AC11: orchestrated scans against a fake runtime replaying tool output."""

from __future__ import annotations

import json
import random
import string
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

from kurojisho.scanner import GAP_DETAIL, SelectionError, ToolOutcome, scan_with_tools, select
from kurojisho.store import Store
from kurojisho.store import queries as q
from kurojisho.store.graph import canonical_export
from kurojisho.tools.runners import RUNNERS, RepoProfile, ScanOptions
from kurojisho.tools.runtime import RunResult
from tests.conftest import CLOCK, FIXTURES, copy_fixture
from tests.helpers import PINS, TOOL_OUTPUTS, FakeRuntime, gitleaks_report, tool_gaps, writes

SEMGREP = (TOOL_OUTPUTS / "semgrep" / "vuln_app.sarif").read_bytes()
#: These tests exercise the orchestrator itself, so they run a fixed pair of scanners.
TWO = {name: RUNNERS[name] for name in ("semgrep", "gitleaks")}


def token(seed: int, prefix: str = "ghp_", length: int = 36) -> str:
    """A secret-shaped value generated at test time; nothing secret-like is committed."""
    return prefix + "".join(
        random.Random(seed).choices(string.ascii_letters + string.digits, k=length)
    )


def handlers(**override: Any) -> dict[str, Any]:
    base = {
        "semgrep": writes({"semgrep.sarif": SEMGREP}),
        "gitleaks": writes({"dir.json": "[]", "git.json": "[]"}),
    }
    return {**base, **override}


class Scan:
    def __init__(self, tmp_path: Path, runtime: FakeRuntime | None, name: str = "vuln_app") -> None:
        self.root = copy_fixture(name, tmp_path)
        self.state = tmp_path / "state"
        self.store = Store(self.state / "graph.db")
        self.runtime = runtime
        self.runners = TWO
        self.outcomes: dict[str, ToolOutcome] = {}

    def run(self, **options: Any):  # type: ignore[no-untyped-def]
        result, outcomes = scan_with_tools(
            self.root, self.store, CLOCK, runtime=self.runtime, options=ScanOptions(**options),
            runners=self.runners,
        )  # fmt: skip
        self.outcomes = {o.tool: o for o in outcomes}
        return result

    def nodes(self, kind: str) -> list[dict[str, Any]]:
        return q.find_nodes(self.store, node_type=kind)

    def state_bytes(self) -> bytes:
        self.store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return b"".join(p.read_bytes() for p in sorted(self.state.rglob("*")) if p.is_file())


@pytest.fixture(autouse=True)
def fixed_salt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUROJISHO_SECRET_SALT", "test-salt")


# -- AC4: findings ---------------------------------------------------------------------
def test_semgrep_findings_match_planted_ground_truth(tmp_path: Path) -> None:
    scan = Scan(tmp_path, FakeRuntime(handlers()))
    scan.run()
    want = YAML(typ="safe").load((FIXTURES / "vuln_app" / "expected.yaml").read_text())
    functions = dict(
        scan.store.conn.execute(
            "SELECT e.src, n.name FROM edges e JOIN nodes n ON n.id = e.dst "
            "WHERE e.type = 'LOCATED_IN' AND n.type = 'Function' AND e.retired = 0"
        ).fetchall()
    )
    got = sorted(
        [n["name"], n["props"]["path"], n["props"]["span"][0], n["props"]["raw_severity"],
         n["props"]["cwe"][0], functions.get(n["id"])]
        for n in scan.nodes("Finding")
    )  # fmt: skip
    assert got == sorted(want["semgrep"])  # precision and recall both 1.0 on planted issues
    reported = {(n["props"]["path"], n["props"]["span"][0]) for n in scan.nodes("Finding")}
    assert not reported & {tuple(c) for c in want["clean_lines"]}
    for node in scan.nodes("Finding"):
        assert (
            node["provenance"] == "TOOL"
            and node["props"]["tool_version"] == PINS["semgrep"].version
        )
        assert node["props"]["final_severity"] is not None and node["props"]["reasons"]
        assert node["evidence"][0]["source"] == f"semgrep@{PINS['semgrep'].version}"
        assert node["evidence"][0]["content_hash"] and node["owner_file"] == node["props"]["path"]
    files = scan.store.conn.execute(
        "SELECT COUNT(*) FROM edges e JOIN nodes n ON n.id = e.dst "
        "WHERE e.type = 'LOCATED_IN' AND n.type = 'File' AND e.provenance = 'TOOL'"
    ).fetchone()[0]
    assert files == 19
    assert scan.outcomes["semgrep"].status == "ok" and scan.outcomes["semgrep"].findings == 19
    assert tool_gaps(scan.store) == []
    runs = scan.store.conn.execute("SELECT tool, status, findings FROM tool_runs ORDER BY tool")
    assert [tuple(r) for r in runs] == [("gitleaks", "ok", 0), ("semgrep", "ok", 19)]


# -- AC2: every run goes through the sandbox --------------------------------------------
def test_every_tool_run_is_sandboxed_and_offline(tmp_path: Path) -> None:
    runtime = FakeRuntime(handlers())
    scan = Scan(tmp_path, runtime)
    (scan.root / ".git").mkdir()
    scan.run(verify_secrets=True)  # opting in must not give network to tools that may not have it
    assert [tool for tool, _, _ in runtime.runs] == ["gitleaks", "gitleaks", "semgrep"]
    for command in runtime.commands:
        assert "--network=none" in command and "--read-only" in command
        assert "--cap-drop=ALL" in command and "--pull=never" in command
        assert f"--mount=type=bind,source={scan.root},target=/src,readonly" in command
        assert any("@sha256:" in part for part in command)
    assert not any(allow for _, _, allow in runtime.runs)
    # each tool gets its own private output directory, removed afterwards
    assert len(set(runtime.out_dirs)) == 2
    assert not any(d.exists() for d in runtime.out_dirs)
    assert list((scan.state / "work").iterdir()) == []
    assert oct((scan.state / "work").stat().st_mode & 0o777) == "0o700"


# -- AC6: no raw secret anywhere --------------------------------------------------------
def test_raw_secrets_never_reach_db_logs_cache_or_export(tmp_path: Path) -> None:
    pat, slack, old = token(1), token(2, "xoxb-", 50), token(3, "AKIA", 16)
    seen_on_disk: list[bytes] = []

    def leaky_gitleaks(spec: Any, out: Path) -> RunResult:
        done = writes(
            {
                "dir.json": gitleaks_report(
                    ("github-pat", "api/settings.py", 1, pat),
                    ("slack-bot-token", "web/hook.js", 2, slack),
                ),
                "git.json": gitleaks_report(
                    ("github-pat", "api/settings.py", 1, pat),
                    ("aws-access-token", "deleted.env", 3, old),
                    commit="c" * 40,
                ),
            },
            stderr=f"leaking {pat} on stderr".encode(),
        )(spec, out)
        seen_on_disk.extend(p.read_bytes() for p in out.iterdir())
        return done

    runtime = FakeRuntime(
        handlers(
            gitleaks=leaky_gitleaks,
            semgrep=writes({"semgrep.sarif": SEMGREP}, stderr=f"warning near {slack}\n".encode()),
        )
    )
    scan = Scan(tmp_path, runtime)
    (scan.root / ".git").mkdir()
    # the same secrets also sit where ingest stores text: a route path and a decorator
    (scan.root / "api" / "settings.py").write_text(
        f'GITHUB_TOKEN = "{pat}"\n\n@app.route("/hook/{pat}")\ndef hook(): pass\n'
    )
    (scan.root / "web" / "hook.js").write_text(f'const x = 1;\napp.post("/s/{slack}", handler);\n')
    scan.run()

    assert any(pat.encode() in blob for blob in seen_on_disk)  # the tool really wrote it
    assert not any(d.exists() for d in runtime.out_dirs)  # ...and it was wiped
    stored = scan.state_bytes() + canonical_export(scan.store).encode()
    for secret in (pat, slack, old):
        assert secret.encode() not in stored
        assert secret[:12].encode() not in stored
    assert b"[REDACTED:" in stored
    assert (scan.state / "logs" / "semgrep.log").read_bytes().startswith(b"warning near [REDACTED:")
    assert not (scan.state / "logs" / "gitleaks.log").exists()  # secret tools' stderr is dropped

    secrets = {n["props"]["preview"]: n for n in scan.nodes("Secret")}
    assert set(secrets) == {"ghp_…", "xoxb…", "AKIA…"}
    assert secrets["ghp_…"]["props"]["location"] == "file"
    assert secrets["AKIA…"]["props"]["location"] == "history"
    assert all(len(n["props"]["fingerprint"]) == 64 for n in secrets.values())
    assert all(n["props"]["verified_live"] == "unknown" for n in secrets.values())
    kinds = sorted((n["name"], n["props"]["location"]) for n in scan.nodes("Finding")
                   if n["props"]["category"] == "secret")  # fmt: skip
    assert kinds == [
        ("aws-access-token", "history"),
        ("github-pat", "file"),
        ("slack-bot-token", "file"),
    ]
    route = next(n for n in scan.nodes("Route") if "hook" in n["name"])
    assert route["name"].startswith("GET /hook/[REDACTED:") and "[REDACTED:" in route["key"]
    edge = scan.store.conn.execute(
        "SELECT COUNT(*) FROM edges WHERE dst = ? AND type = 'DEFINES' AND retired = 0",
        (route["id"],),
    ).fetchone()[0]
    assert edge == 1  # the scrubbed node kept its edges

    # a re-scan from the (scrubbed) parse cache is stable and still clean
    again = scan.run()
    assert again.writes.total == 0
    assert pat.encode() not in scan.state_bytes()


# -- AC9: failures become coverage gaps ---------------------------------------------------
def timed_out(spec: Any, out: Path) -> RunResult:
    return RunResult(None, timed_out=True)


@pytest.mark.parametrize(
    ("handler", "status"),
    [
        (writes({"semgrep.sarif": SEMGREP}, exit_code=2), "failed"),
        (timed_out, "timeout"),
        (writes({}), "output_missing"),
        (writes({"semgrep.sarif": "<html>502</html>"}), "invalid_output"),
        (writes({"semgrep.sarif": '{"runs": [{"invocations": [{"executionSuccessful": false}]}]}'}),
         "invalid_output"),
    ],
)  # fmt: skip
def test_tool_failures_become_coverage_gaps(tmp_path: Path, handler: Any, status: str) -> None:
    scan = Scan(tmp_path, FakeRuntime(handlers(semgrep=handler)))
    result = scan.run()
    assert result.scan_id == 1  # the scan itself still completes
    assert scan.outcomes["semgrep"].status == status and scan.outcomes["gitleaks"].status == "ok"
    (gap,) = tool_gaps(scan.store)
    assert gap["key"] == f"CoverageGap:semgrep::{status}" and gap["provenance"] == "TOOL"
    assert gap["props"]["category"] == "sast" and gap["props"]["detail"] == GAP_DETAIL[status]
    assert scan.nodes("Finding") == []
    assert q.stats(scan.store)["nodes"]["Function"] > 0  # the code graph is unaffected
    # once the tool works again the gap is retired, not left behind
    scan.runtime = FakeRuntime(handlers())
    scan.run()
    assert tool_gaps(scan.store) == [] and len(scan.nodes("Finding")) == 19


def test_no_runtime_offline_and_failed_install(tmp_path: Path) -> None:
    none = Scan(tmp_path / "a", None)
    none.run()
    assert {o.status for o in none.outcomes.values()} == {"sandbox_unavailable"}
    assert len(tool_gaps(none.store)) == 2

    offline_runtime = FakeRuntime(handlers(), installed=False)
    offline = Scan(tmp_path / "b", offline_runtime)
    offline.run(offline=True)
    assert {o.status for o in offline.outcomes.values()} == {"not_installed"}
    assert offline_runtime.pulled == [] and offline_runtime.runs == []

    broken = FakeRuntime(handlers(), installed=False)
    broken.fail_pull = True
    failing = Scan(tmp_path / "c", broken)
    failing.run()
    assert {o.status for o in failing.outcomes.values()} == {"install_failed"}


def test_missing_tools_are_installed_by_digest_unless_offline(tmp_path: Path) -> None:
    runtime = FakeRuntime(handlers(), installed=False)
    scan = Scan(tmp_path, runtime)
    scan.run()
    assert sorted(runtime.pulled) == sorted([PINS["semgrep"].ref, PINS["gitleaks"].ref])
    assert {o.status for o in scan.outcomes.values()} == {"ok"}


def test_user_exclusions_and_target_side_config_are_recorded(tmp_path: Path) -> None:
    scan = Scan(tmp_path, FakeRuntime(handlers()))
    (scan.root / ".gitleaks.toml").write_text("[allowlist]\npaths = ['.*']\n")
    (scan.root / ".semgrepignore").write_text("*\n")
    scan.run(skip=frozenset({"semgrep"}))
    gaps = {n["key"]: n["props"] for n in tool_gaps(scan.store)}
    assert set(gaps) == {
        "CoverageGap:semgrep::skipped_by_user",
        "CoverageGap:gitleaks::target_config_present",
    }
    assert gaps["CoverageGap:gitleaks::target_config_present"]["files"] == [".gitleaks.toml"]
    scan.run(only=frozenset({"semgrep"}))
    assert "CoverageGap:semgrep::target_config_present" in {n["key"] for n in tool_gaps(scan.store)}
    with pytest.raises(SelectionError, match="unknown tool"):
        scan.run(only=frozenset({"nessus"}))
    assert scan.store.last_scan_id() == 2  # the rejected scan wrote nothing


def test_tools_disabled_is_a_plain_ingest(tmp_path: Path) -> None:
    runtime = FakeRuntime(handlers())
    scan = Scan(tmp_path, runtime)
    scan.run(tools=False)
    assert runtime.runs == [] and scan.outcomes == {}
    assert scan.nodes("Finding") == [] and tool_gaps(scan.store) == []


# -- selection (AC3, first half) ----------------------------------------------------------
def test_selection_follows_repo_content() -> None:
    def names(profile: RepoProfile, **options: Any) -> list[str]:
        return [r.name for r in select(profile, ScanOptions(**options), TWO)[0]]

    code = RepoProfile(frozenset({"python"}), frozenset({"a.py"}))
    docs = RepoProfile(frozenset(), frozenset({"README.md"}))
    empty = RepoProfile(frozenset(), frozenset())
    assert names(code) == ["gitleaks", "semgrep"]
    assert names(docs) == ["gitleaks"]  # no supported language: no SAST, secrets still run
    assert names(empty) == []
    assert names(code, skip=frozenset({"gitleaks"})) == ["semgrep"]
    assert names(code, only=frozenset({"gitleaks"})) == ["gitleaks"]


# -- AC11: caching, no-op and determinism -------------------------------------------------
def test_unchanged_tree_reuses_results_and_writes_nothing(tmp_path: Path) -> None:
    runtime = FakeRuntime(handlers())
    scan = Scan(tmp_path, runtime)
    scan.run()
    runtime.runs.clear()
    again = scan.run()
    assert again.writes.total == 0 and again.files_parsed == []
    assert scan.outcomes["semgrep"].status == "cached" and scan.outcomes["semgrep"].findings == 19
    assert [tool for tool, _, _ in runtime.runs] == ["gitleaks"]  # secret scans are never cached
    (scan.root / "api" / "extra.py").write_text("import os\nos.system(cmd)\n")
    scan.run()
    assert scan.outcomes["semgrep"].status == "ok"  # the tree changed: the tool runs again


def test_two_fresh_scans_export_identically(tmp_path: Path) -> None:
    pat = token(9)

    def one(tag: str) -> str:
        leaks = writes({"dir.json": gitleaks_report(("github-pat", "api/app.py", 3, pat))})
        scan = Scan(tmp_path / tag, FakeRuntime(handlers(gitleaks=leaks)))
        scan.run()
        return canonical_export(scan.store)

    first, second = one("a"), one("b")
    assert first == second and pat not in first
    assert json.loads(first)["nodes"]
    assert "duration" not in first and "2024-01-01" not in first


def test_secret_fingerprints_use_a_per_database_salt_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("KUROJISHO_SECRET_SALT")
    pat = token(11)
    prints = []
    for tag in ("a", "b"):
        leaks = writes({"dir.json": gitleaks_report(("github-pat", "api/app.py", 3, pat))})
        scan = Scan(tmp_path / tag, FakeRuntime(handlers(gitleaks=leaks)))
        scan.run()
        scan.run()
        (secret,) = scan.nodes("Secret")
        prints.append(secret["props"]["fingerprint"])
        assert len(scan.store.get_meta("secret_salt") or "") == 64
        assert (
            scan.store.conn.execute("SELECT COUNT(*) FROM nodes WHERE type='Secret'").fetchone()[0]
            == 1
        )
    assert prints[0] != prints[1]  # same secret, different databases: hashes cannot be correlated
