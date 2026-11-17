"""M2-AC1, AC7, AC10: built tools (govulncheck), the CodeQL licence gate, import-sarif."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from kurojisho.cli import app
from kurojisho.config.settings import accept_licence, licence_accepted
from kurojisho.findings.model import ToolOutputError
from kurojisho.scanner import LicenceError, scan_with_tools
from kurojisho.store import Store
from kurojisho.store import queries as q
from kurojisho.tools.lock import LockError, parse_lock
from kurojisho.tools.manager import ToolManager
from kurojisho.tools.runners import RUNNERS, RepoProfile, RunContext, ScanOptions
from kurojisho.tools.runners.codeql import TERMS
from kurojisho.tools.runners.govulncheck import decode_stream
from kurojisho.tools.runtime import RunResult, RuntimeUnavailable
from kurojisho.tools.sandbox import OUT, build_command
from tests.conftest import CLOCK, copy_fixture
from tests.helpers import PINS, TOOL_OUTPUTS, FakeRuntime, all_handlers, make_intel, tool_gaps

runner = CliRunner()
BINARY = b"\x7fELF fake govulncheck"
GO_PIN = dataclasses.replace(PINS["govulncheck"], binary_sha256=hashlib.sha256(BINARY).hexdigest())


def go_build(spec: Any, out: Path) -> RunResult:
    """Plays `go install` during tool installation."""
    assert spec.entrypoint == "go" and spec.args == ("install", GO_PIN.build)
    (out / "govulncheck").write_bytes(BINARY)
    return RunResult(0)


def stream(*findings: dict[str, Any]) -> bytes:
    messages: list[dict[str, Any]] = [
        {"config": {"protocol_version": "v1.0.0", "scanner_name": "govulncheck"}},
        {"progress": {"message": "Scanning your code..."}},
        {"osv": {"id": "GO-2021-0113", "aliases": ["CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"]}},
        {"osv": {"id": "GO-2020-0015", "aliases": ["CVE-2020-14040"]}},
        *({"finding": f} for f in findings),
    ]
    return "\n".join(json.dumps(m, indent=2) for m in messages).encode()


TEXT = {"module": "golang.org/x/text", "version": "v0.3.0"}
FINDINGS = (
    {"osv": "GO-2021-0113", "fixed_version": "v0.3.7", "trace": [TEXT]},
    {"osv": "GO-2021-0113", "fixed_version": "v0.3.7",
     "trace": [{**TEXT, "package": "golang.org/x/text/language"}]},
    {"osv": "GO-2021-0113", "fixed_version": "v0.3.7",
     "trace": [{**TEXT, "package": "golang.org/x/text/language", "function": "Parse"}]},
    {"osv": "GO-2020-0015", "fixed_version": "v0.3.3", "trace": [TEXT]},
)  # fmt: skip


# -- tools built at install time -------------------------------------------------------------
def test_lock_requires_a_checksum_for_built_tools() -> None:
    base = (
        'schema = 1\n[[tool]]\nname = "t"\nversion = "1"\nimage = "golang"\n'
        f'digest = "sha256:{"a" * 64}"\nlicence = "MIT"\n'
    )
    good = base + f'build = "example.com/x/cmd/t@v1.2.3"\nbinary_sha256 = "{"b" * 64}"\n'
    assert parse_lock(good)["t"].build == "example.com/x/cmd/t@v1.2.3"
    for bad in (
        base + 'build = "example.com/x/cmd/t@v1.2.3"\n',  # no checksum
        base + f'build = "example.com/x/cmd/t@latest"\nbinary_sha256 = "{"b" * 64}"\n',
        base + f'build = "x; rm -rf /@v1"\nbinary_sha256 = "{"b" * 64}"\n',
        base + 'binary_sha256 = "abc"\n',
    ):
        with pytest.raises(LockError):
            parse_lock(bad)
    assert (
        PINS["govulncheck"].build.endswith("@v1.9.0")
        and len(PINS["govulncheck"].binary_sha256) == 64
    )


def test_built_tool_is_installed_only_if_its_binary_matches(tmp_path: Path) -> None:
    runtime = FakeRuntime({"govulncheck": go_build}, installed=False)
    manager = ToolManager(runtime, {"govulncheck": GO_PIN}, tools_dir=tmp_path / "tools")
    assert not manager.installed("govulncheck")
    assert manager.install() == ["govulncheck"] and manager.installed("govulncheck")
    binary = manager.binary_dir("govulncheck") / "govulncheck"
    assert binary.read_bytes() == BINARY and binary.stat().st_mode & 0o111
    # the build is the one run that gets network, and it sees no target code
    (_tool, spec, allow) = runtime.runs[0]
    assert allow is True and "--network=bridge" in runtime.commands[0]
    assert [m.target for m in spec.mounts] == ["/src", OUT]
    assert "binary checksum" in manager.status()[0].verification
    binary.write_bytes(b"tampered")
    assert not manager.installed("govulncheck")  # a changed binary no longer counts

    wrong = ToolManager(runtime, {"govulncheck": PINS["govulncheck"]}, tools_dir=tmp_path / "w")
    with pytest.raises(RuntimeUnavailable, match="refusing to install"):
        wrong.install()
    assert not wrong.installed("govulncheck")
    assert not (wrong.binary_dir("govulncheck") / "govulncheck").exists()
    failing = ToolManager(
        FakeRuntime({}, installed=False), {"govulncheck": GO_PIN}, tools_dir=tmp_path / "f"
    )
    with pytest.raises(RuntimeUnavailable, match="could not build"):
        failing.install()


def test_govulncheck_stream_parsing_keeps_the_deepest_reach(tmp_path: Path) -> None:
    profile = RepoProfile(frozenset({"go"}), frozenset({"svc/go.mod", "svc/main.go"}))
    ctx = RunContext(tmp_path, tmp_path, GO_PIN, profile, ScanOptions())
    found = RUNNERS["govulncheck"].parse(ctx, {"module:svc": stream(*FINDINGS)})
    by_id = {f.rule_id: f for f in found}
    assert set(by_id) == {"GO-2021-0113", "GO-2020-0015"}
    reached = by_id["GO-2021-0113"]
    assert reached.tool_reachability == "symbol" and reached.path == "svc/go.mod"
    assert reached.purl == "pkg:golang/golang.org/x/text@v0.3.0"
    assert reached.advisory_ids == ("CVE-2021-38561", "GHSA-ppp9-7jff-5vj2", "GO-2021-0113")
    assert reached.fixed_versions == ("v0.3.7",) and reached.severity.value == "Unknown"
    assert by_id["GO-2020-0015"].tool_reachability == "module"
    assert RUNNERS["govulncheck"].parse(ctx, {"module:svc": stream()}) == []
    assert len(decode_stream(b'{"a": 1}\n\n{"b": {"c": [1, 2]}} {"d": 3}')) == 3
    for garbage in (b"go: errors parsing go.mod", b'{"progress": {}}'):
        with pytest.raises(ToolOutputError):
            RUNNERS["govulncheck"].parse(ctx, {"module:svc": garbage})


def test_govulncheck_runs_from_the_built_binary_and_merges_with_other_scanners(
    tmp_path: Path,
) -> None:
    def tool(spec: Any, out: Path) -> RunResult:
        if spec.entrypoint == "go":
            return go_build(spec, out)
        assert spec.entrypoint == "/tools/govulncheck" and spec.workdir == "/src/svc"
        assert spec.args[:2] == ("-db", "file:///intel") and spec.env["GOPROXY"] == "off"
        return RunResult(0, stream(*FINDINGS))

    runtime = FakeRuntime(all_handlers(govulncheck=tool), installed=False)
    manager = ToolManager(runtime, {**PINS, "govulncheck": GO_PIN}, tools_dir=tmp_path / "tools")
    root = copy_fixture("vuln_app", tmp_path)
    store = Store(tmp_path / "state" / "graph.db")
    runners = {n: RUNNERS[n] for n in ("govulncheck", "osv-scanner")}
    _, outcomes = scan_with_tools(
        root, store, CLOCK, runtime=runtime, runners=runners, manager=manager,
        intel=make_intel(tmp_path / "intel", CLOCK),
    )  # fmt: skip
    assert {o.tool: o.status for o in outcomes} == {"govulncheck": "ok", "osv-scanner": "ok"}
    scan_runs = [(t, a) for t, s, a in runtime.runs if s.entrypoint != "go"]
    assert all(not allow for _, allow in scan_runs)  # only the install step had network
    command = next(c for c in runtime.commands if "--entrypoint=/tools/govulncheck" in c)
    assert (
        f"--mount=type=bind,source={manager.binary_dir('govulncheck')},target=/tools,readonly"
        in command
    )
    findings = [
        f
        for f in q.find_nodes(store, node_type="Finding")
        if "x/text" in (f["props"]["purl"] or "")
    ]
    reached = next(f for f in findings if f["name"] == "GO-2021-0113")
    assert reached["props"]["tool_reachability"] == "symbol" and reached["props"]["canonical"]
    same = [f for f in findings if f["props"]["fingerprint"] == reached["props"]["fingerprint"]]
    assert {f["props"]["tool"] for f in same} == {"govulncheck", "osv-scanner"}
    assert reached["props"]["group_severity"] != "Unknown"  # the other scanner supplied a rating


# -- CodeQL licence gate ------------------------------------------------------------------------
def gate_scan(tmp_path: Path, **options: Any):  # type: ignore[no-untyped-def]
    root = copy_fixture("vuln_app", tmp_path)
    store = Store(tmp_path / "state" / "graph.db")
    runtime = FakeRuntime(all_handlers())
    runners = {n: RUNNERS[n] for n in ("codeql", "semgrep")}
    result = scan_with_tools(root, store, CLOCK, runtime=runtime, options=ScanOptions(**options),
                             runners=runners)  # fmt: skip
    return store, runtime, result


def test_codeql_is_off_by_default(tmp_path: Path) -> None:
    store, _runtime, (_, outcomes) = gate_scan(tmp_path)
    assert [o.tool for o in outcomes] == ["semgrep"]
    assert tool_gaps(store) == []


def test_codeql_refuses_to_run_without_licence_acceptance(tmp_path: Path) -> None:
    assert not licence_accepted("codeql")
    with pytest.raises(LicenceError, match="open-source codebases and for academic research"):
        gate_scan(tmp_path, enable=frozenset({"codeql"}))
    store = Store(tmp_path / "state" / "graph.db")
    assert store.last_scan_id() is None  # refused before anything was scanned or written


def test_codeql_with_acceptance_is_reported_as_not_installed_in_this_build(tmp_path: Path) -> None:
    accept_licence("codeql", "2024-01-01T00:00:00Z", TERMS)
    assert licence_accepted("codeql")
    store, runtime, (_, outcomes) = gate_scan(tmp_path, enable=frozenset({"codeql"}))
    statuses = {o.tool: o.status for o in outcomes}
    assert statuses == {"codeql": "not_installed", "semgrep": "ok"}
    assert [tool for tool, _, _ in runtime.runs] == ["semgrep"]
    (gap,) = tool_gaps(store)
    assert (
        gap["key"] == "CoverageGap:codeql::not_installed"
        and gap["props"]["tool_version"] == "unpinned"
    )


def test_codeql_commands_never_build_the_target(tmp_path: Path) -> None:
    pin = dataclasses.replace(PINS["semgrep"], name="codeql", version="2.0.0")
    profile = RepoProfile(
        frozenset({"python", "typescript", "tsx", "java", "go"}), frozenset({"a.py"})
    )
    ctx = RunContext(tmp_path, tmp_path / "out", pin, profile, ScanOptions())
    ctx.tools_dir = tmp_path / "bundle"
    steps = RUNNERS["codeql"].steps(ctx)
    assert [s.name for s in steps] == [
        "create:java",
        "analyze:java",
        "create:javascript",
        "analyze:javascript",
        "create:python",
        "analyze:python",
    ]  # fmt: skip  (Go is absent: it cannot be extracted without building)
    for step in steps:
        command = build_command("docker", step.spec, name="n", uid=1000, gid=1000)
        assert "--network=none" in command and "--entrypoint=/tools/codeql/codeql" in command
        if step.name.startswith("create:"):
            assert "--build-mode=none" in step.spec.args and "--source-root=/src" in step.spec.args
    assert not RUNNERS["codeql"].applicable(RepoProfile(frozenset({"go"}), frozenset({"m.go"})))
    sarif_doc = (TOOL_OUTPUTS / "semgrep" / "vuln_app.sarif").read_bytes()
    parsed = RUNNERS["codeql"].parse(ctx, {"create:python": b"", "analyze:python": sarif_doc})
    assert len(parsed) == 19 and parsed[0].tool == "codeql"


def cli(*args: str, code: int = 0) -> str:
    result = runner.invoke(app, list(args))
    assert result.exit_code == code, result.output
    return result.output


def test_codeql_gate_through_the_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "250")
    monkeypatch.setattr("kurojisho.cli.detect_runtime", lambda _p=None: FakeRuntime(all_handlers()))
    root = copy_fixture("vuln_app", tmp_path)
    refused = cli("scan", str(root), "--enable", "codeql", "--tools", "codeql", code=2)
    assert "licence-restricted" in refused and "accept-licence codeql --yes" in refused
    empty = runner.invoke(app, ["query", "stats", "--json", "--repo", str(root)]).stdout
    assert json.loads(empty)["nodes"] == {}  # refused before anything was scanned
    shown = cli("tools", "accept-licence", "codeql", code=1)
    assert "GitHub Advanced Security" in shown and "not recorded" in shown
    assert not licence_accepted("codeql")
    assert "acceptance recorded" in cli("tools", "accept-licence", "codeql", "--yes")
    assert licence_accepted("codeql")
    assert "has no licence gate" in cli("tools", "accept-licence", "semgrep", "--yes", code=2)
    allowed = cli("scan", str(root), "--enable", "codeql", "--tools", "codeql")
    assert "tool: codeql" in allowed and "not_installed" in allowed


# -- import-sarif ----------------------------------------------------------------------------------
def test_import_sarif_uses_the_same_normaliser_and_survives_rescans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KUROJISHO_SECRET_SALT", "s")
    monkeypatch.setattr("kurojisho.cli.detect_runtime", lambda _p=None: FakeRuntime(all_handlers()))
    monkeypatch.setattr("kurojisho.scanner.RUNNERS", {"semgrep": RUNNERS["semgrep"]})
    root = copy_fixture("vuln_app", tmp_path)
    report = TOOL_OUTPUTS / "semgrep" / "vuln_app.sarif"
    repo = ["--repo", str(root)]
    assert "imported 19 result(s) from ci-scan" in cli(
        "import-sarif", str(report), "--tool", "ci-scan", *repo
    )
    stats = json.loads(runner.invoke(app, ["query", "stats", "--json", *repo]).stdout)
    assert stats["nodes"]["Finding"] == 19 and stats["nodes"]["Function"] > 0
    listed = json.loads(
        runner.invoke(app, ["query", "nodes", "--type", "Finding", "--json", *repo]).stdout
    )
    assert all(f["props"]["imported"] and f["props"]["tool"] == "ci-scan" for f in listed)
    assert all(f["provenance"] == "TOOL" and f["evidence"][0]["content_hash"] for f in listed)
    assert listed[0]["props"]["rule_id"].startswith("rules.kurojisho.")

    again = cli("import-sarif", str(report), "--tool", "ci-scan", *repo)
    assert "wrote 0 row(s)" in again  # importing the same file twice changes nothing
    cli("scan", str(root), "--no-tools")
    assert (
        json.loads(runner.invoke(app, ["query", "stats", "--json", *repo]).stdout)["nodes"][
            "Finding"
        ]
        == 19
    )
    # a real run of the same rules agrees line for line: the imported copies become duplicates
    cli("scan", str(root))
    store = Store(root / ".kurojisho" / "graph.db")
    dupes = store.conn.execute(
        "SELECT COUNT(*) FROM edges WHERE type = 'DUPLICATE_OF' AND retired = 0"
    ).fetchone()[0]
    assert dupes == 19
    canonical = {
        f["props"]["tool"]
        for f in q.find_nodes(store, node_type="Finding")
        if f["props"]["canonical"]
    }
    assert canonical == {"semgrep"}


def test_import_sarif_rejects_bad_input(tmp_path: Path) -> None:
    root = copy_fixture("vuln_app", tmp_path)
    bad = tmp_path / "bad.sarif"
    bad.write_text("<html>")
    repo = ["--repo", str(root)]
    assert "not valid JSON" in cli("import-sarif", str(bad), "--tool", "x", *repo, code=2)
    assert "cannot read" in cli(
        "import-sarif", str(tmp_path / "none"), "--tool", "x", *repo, code=2
    )
    assert "simple name" in cli("import-sarif", str(bad), "--tool", "a b;c", *repo, code=2)
    assert "sast, iac" in cli(
        "import-sarif", str(bad), "--tool", "x", "--category", "sca", *repo, code=2
    )
    assert not (root / ".kurojisho").exists()
