"""M2-AC3 / M2-AC4 / M2-AC5: each adapter against output recorded from the real tool."""

from __future__ import annotations

import json
import random
import string
from pathlib import Path
from typing import Any

import pytest

from kurojisho.findings.model import ToolOutputError
from kurojisho.findings.sbom import parse_cyclonedx
from kurojisho.scanner import scan_with_tools, select
from kurojisho.store import Store
from kurojisho.store import queries as q
from kurojisho.store.graph import canonical_export
from kurojisho.tools.runners import RUNNERS, RepoProfile, RunContext, ScanOptions
from kurojisho.tools.runtime import RunResult
from kurojisho.tools.sandbox import build_command
from tests.conftest import CLOCK, copy_fixture
from tests.helpers import PINS, FakeRuntime, all_handlers, recorded

FIRST_HALF = {"bandit", "checkov", "gitleaks", "gosec", "semgrep", "syft", "trufflehog"}


@pytest.fixture(autouse=True)
def fixed_salt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUROJISHO_SECRET_SALT", "test-salt")


def ctx(tool: str, tmp_path: Path, files: set[str] | None = None, **options: Any) -> RunContext:
    profile = RepoProfile(frozenset({"python", "go"}), frozenset(files or {"a.py"}), has_git=True)
    return RunContext(tmp_path, tmp_path / "out", PINS[tool], profile, ScanOptions(**options))


def scan(tmp_path: Path, runtime: FakeRuntime, only: set[str], **options: Any) -> Store:
    root = copy_fixture("vuln_app", tmp_path)
    store = Store(tmp_path / "state" / "graph.db")
    runners = {name: RUNNERS[name] for name in only}
    scan_with_tools(root, store, CLOCK, runtime=runtime, options=ScanOptions(**options),
                    runners=runners)  # fmt: skip
    return store


def findings(store: Store, tool: str) -> list[dict[str, Any]]:
    return [n for n in q.find_nodes(store, node_type="Finding") if n["props"]["tool"] == tool]


# -- selection ---------------------------------------------------------------------------
def test_tools_are_selected_from_what_the_repo_contains() -> None:
    def names(langs: set[str], files: set[str]) -> set[str]:
        profile = RepoProfile(frozenset(langs), frozenset(files))
        return {r.name for r in select(profile, ScanOptions(), RUNNERS)[0]} & FIRST_HALF

    always = {"gitleaks", "trufflehog", "syft"}
    assert names({"python"}, {"a.py"}) == always | {"semgrep", "bandit"}
    assert names({"go"}, {"main.go"}) == always | {"semgrep"}  # no go.mod: gosec cannot load it
    assert names({"go"}, {"svc/go.mod", "svc/main.go"}) == always | {"semgrep", "gosec"}
    assert names(set(), {"deploy/main.tf"}) == always | {"checkov"}
    assert names(set(), {"Dockerfile"}) == always | {"checkov"}
    assert names(set(), {"k8s/app.yml"}) == always | {"checkov"}
    assert names(set(), {"README.md"}) == always
    assert names(set(), set()) == set()


@pytest.mark.parametrize("tool", sorted(FIRST_HALF))
def test_every_adapter_step_is_a_valid_sandboxed_command(tool: str, tmp_path: Path) -> None:
    files = {"a.py", "svc/go.mod", "svc/main.go", "x.tf"}
    for options in ({}, {"verify_secrets": True}):
        steps = RUNNERS[tool].steps(ctx(tool, tmp_path, files, **options))
        assert steps
        for step in steps:
            allow = PINS[tool].network and bool(options)
            command = build_command("docker", step.spec, name="n", uid=1000, gid=1000,
                                    allow_network=allow)  # fmt: skip
            assert f"--mount=type=bind,source={tmp_path},target=/src,readonly" in command
            expected = (
                "--network=bridge" if (tool == "trufflehog" and options) else "--network=none"
            )
            assert expected in command, (tool, options)
            assert step.spec.image == PINS[tool].ref


# -- SAST and IaC --------------------------------------------------------------------------
def test_bandit(tmp_path: Path) -> None:
    store = scan(tmp_path, FakeRuntime(all_handlers()), {"bandit"})
    got = {(f["name"], f["props"]["span"][0]): f for f in findings(store, "bandit")}
    assert len(got) == 10 and all(f["props"]["path"] == "api/app.py" for f in got.values())
    sqli = got[("B608", 16)]
    assert sqli["props"]["cwe"] == ["CWE-89"] and sqli["props"]["raw_severity"] == "Medium"
    assert sqli["confidence"] == 0.7  # bandit's own MEDIUM confidence for string-built SQL
    assert got[("B602", 28)]["props"]["raw_severity"] == "High"
    assert got[("B307", 22)]["props"]["cwe"] == ["CWE-78"]
    assert "SELECT" not in json.dumps(sqli)  # no code snippets are stored
    bad = ctx("bandit", tmp_path)
    for garbage in (b"nope", b"[]", b'{"results": [{}]}'):
        with pytest.raises(ToolOutputError):
            RUNNERS["bandit"].parse(bad, {"scan": garbage})


def test_gosec_paths_are_relative_to_the_repo_and_use_its_own_ratings(tmp_path: Path) -> None:
    store = scan(tmp_path, FakeRuntime(all_handlers()), {"gosec"})
    got = {(f["name"], f["props"]["span"][0]): f for f in findings(store, "gosec")}
    assert len(got) == 9 and all(f["props"]["path"] == "svc/main.go" for f in got.values())
    assert got[("G402", 26)]["props"]["cwe"] == ["CWE-295"]
    assert got[("G402", 26)]["props"]["raw_severity"] == "High"
    assert got[("G104", 18)]["props"]["raw_severity"] == "Low"  # SARIF level alone said "warning"
    assert got[("G114", 31)]["props"]["raw_severity"] == "Medium"
    assert got[("G204", 17)]["confidence"] == 0.9
    function = store.conn.execute(
        "SELECT n.name FROM edges e JOIN nodes n ON n.id = e.dst "
        "WHERE e.src = ? AND n.type = 'Function'",
        (got[("G204", 17)]["id"],),
    ).fetchone()
    assert function[0] == "run"


def test_checkov(tmp_path: Path) -> None:
    store = scan(tmp_path, FakeRuntime(all_handlers()), {"checkov"})
    got = findings(store, "checkov")
    assert len(got) == 37 and {f["props"]["category"] for f in got} == {"iac"}
    assert {f["props"]["path"] for f in got} == {
        "deploy/Dockerfile",
        "deploy/k8s.yaml",
        "deploy/main.tf",
    }
    rules = {f["name"] for f in got}
    assert {
        "CKV_DOCKER_7",
        "CKV_K8S_16",
        "CKV_AWS_20",
    } <= rules  # latest tag, privileged, public ACL
    assert all(f["props"]["raw_severity"] == "High" for f in got)  # checkov gives no rating offline
    assert all(f["props"]["span"] for f in got)


def test_sast_tools_agreeing_on_a_line_are_deduplicated(tmp_path: Path) -> None:
    store = scan(tmp_path, FakeRuntime(all_handlers()), {"semgrep", "bandit", "gosec"})
    dupes = store.conn.execute(
        "SELECT s.name, d.name, json_extract(d.props, '$.group_severity'), "
        "json_extract(d.props, '$.reported_by') FROM edges e JOIN nodes s ON s.id = e.src "
        "JOIN nodes d ON d.id = e.dst WHERE e.type = 'DUPLICATE_OF' ORDER BY 1"
    ).fetchall()
    pairs = {(r[0], r[1]) for r in dupes}
    assert ("B608", "kurojisho.python.sql-string-built") in pairs  # CWE-89, api/app.py:16
    assert ("B301", "kurojisho.python.unsafe-deserialization") in pairs  # CWE-502, line 32
    assert ("G402", "kurojisho.go.tls-verification-disabled") in pairs  # CWE-295, svc/main.go:26
    sqli = next(r for r in dupes if r[0] == "B608")
    assert sqli[2] == "High" and json.loads(sqli[3]) == ["bandit", "semgrep"]
    canonical = store.conn.execute(
        "SELECT COUNT(*) FROM nodes WHERE type = 'Finding' AND json_extract(props, '$.canonical')"
    ).fetchone()[0]
    assert canonical == 19 + 10 + 9 - len(dupes)


# -- secrets ---------------------------------------------------------------------------------
def trufflehog_lines(*items: tuple[str, str, str, str], verified: bool | None = None) -> bytes:
    """(detector, mode, file, raw) in TruffleHog's JSONL shape."""
    lines = [b'{"level":"info","msg":"running source"}']
    for detector, mode, path, raw in items:
        meta: dict[str, Any] = {"file": path if mode == "Git" else f"/src/{path}", "line": 1}
        if mode == "Git":
            meta["commit"] = "c" * 40
        item: dict[str, Any] = {
            "SourceMetadata": {"Data": {mode: meta}},
            "DetectorName": detector,
            "DetectorDescription": f"{detector} tokens grant access.",
            "Verified": bool(verified),
            "Raw": raw,
            "RawV2": raw + ":extra-part" if detector == "AWS" else "",
            "Redacted": raw[:6],
        }
        lines.append(json.dumps(item).encode())
    return b"\n".join(lines) + b"\n"


def secret(seed: int, prefix: str) -> str:
    return prefix + "".join(random.Random(seed).choices(string.ascii_letters + string.digits, k=36))


def test_trufflehog_and_gitleaks_agree_on_one_secret(tmp_path: Path) -> None:
    from tests.helpers import gitleaks_report, writes

    pat, aws = secret(1, "ghp_"), secret(2, "AKIA")

    def hog(spec: Any, _out: Path) -> RunResult:
        if spec.args[0] == "git":
            found = [("Github", "Git", "api/app.py", pat), ("AWS", "Git", "gone.env", aws)]
        else:
            found = [
                ("Github", "Filesystem", "api/app.py", pat),
                ("Github", "Filesystem", ".git/objects/ab/cd", pat),
            ]
        return RunResult(0, trufflehog_lines(*found))

    leaks = writes(
        {"dir.json": gitleaks_report(("github-pat", "api/app.py", 3, pat)), "git.json": "[]"}
    )
    runtime = FakeRuntime(all_handlers(trufflehog=hog, gitleaks=leaks))
    root = copy_fixture("vuln_app", tmp_path)
    (root / ".git").mkdir()
    store = Store(tmp_path / "state" / "graph.db")
    runners = {n: RUNNERS[n] for n in ("gitleaks", "trufflehog")}
    scan_with_tools(root, store, CLOCK, runtime=runtime, options=ScanOptions(), runners=runners)

    hog_findings = {(f["name"], f["props"]["location"]) for f in findings(store, "trufflehog")}
    assert hog_findings == {
        ("Github", "file"),
        ("AWS", "history"),
    }  # .git objects and HEAD dupes dropped
    secrets = {n["props"]["preview"]: n["props"] for n in q.find_nodes(store, node_type="Secret")}
    assert secrets["ghp_…"]["reported_by"] == ["gitleaks", "trufflehog"]
    assert secrets["ghp_…"]["verified_live"] == "unknown"
    stored = canonical_export(store) + json.dumps(
        [tuple(r) for r in store.conn.execute("SELECT * FROM tool_cache")]
    )
    assert pat not in stored and aws not in stored and "extra-part" not in stored
    assert [a for _, spec, _ in runtime.runs for a in spec.args if a == "--no-verification"]
    assert not any(allow for _, _, allow in runtime.runs)


def test_trufflehog_verification_is_opt_in_and_sets_verified_live(tmp_path: Path) -> None:
    live, dead = secret(3, "ghp_"), secret(4, "xoxb-")

    def hog(spec: Any, _out: Path) -> RunResult:
        assert "--no-verification" not in spec.args
        lines = trufflehog_lines(("Github", "Filesystem", "api/app.py", live), verified=True)
        lines += trufflehog_lines(("Slack", "Filesystem", "web/server.js", dead), verified=False)
        return RunResult(0, lines)

    runtime = FakeRuntime(all_handlers(trufflehog=hog))
    store = scan(tmp_path, runtime, {"trufflehog", "semgrep"}, verify_secrets=True)
    states = {
        n["name"]: n["props"]["verified_live"] for n in q.find_nodes(store, node_type="Secret")
    }
    assert states == {"Github": "true", "Slack": "false"}
    granted = {tool: allow for tool, _, allow in runtime.runs}
    assert granted == {"trufflehog": True, "semgrep": False}  # only TruffleHog gets the network
    with pytest.raises(ToolOutputError):
        RUNNERS["trufflehog"].parse(ctx("trufflehog", tmp_path), {"fs": b"not json\n"})
    with pytest.raises(ToolOutputError):
        RUNNERS["trufflehog"].parse(ctx("trufflehog", tmp_path), {"fs": b'{"DetectorName": "X"}\n'})


# -- SBOM ------------------------------------------------------------------------------------
def test_syft_sbom_enriches_known_packages_and_adds_missed_ones(tmp_path: Path) -> None:
    sbom = json.loads(recorded("syft", "vuln_app.cdx.json"))
    for component in sbom["components"]:
        if component.get("name") == "lodash":
            component["licenses"] = [{"license": {"id": "MIT"}}]
    sbom["components"].append(
        {
            "type": "library", "name": "left-pad", "version": "1.3.0",
            "purl": "pkg:npm/left-pad@1.3.0?package-id=abc",
            "licenses": [{"expression": "WTFPL"}],
            "properties": [{"name": "syft:location:0:path", "value": "/src/web/package-lock.json"}],
        }
    )  # fmt: skip
    from tests.helpers import writes

    runtime = FakeRuntime(all_handlers(syft=writes({"sbom.json": json.dumps(sbom)})))
    store = scan(tmp_path, runtime, {"syft"})
    packages = {n["props"]["purl"]: n for n in q.find_nodes(store, node_type="Package")}
    lodash = packages["pkg:npm/lodash@4.17.15"]
    assert lodash["provenance"] == "EXTRACTED"  # our own parser found it first
    assert lodash["props"]["license"] == "MIT" and lodash["props"]["sbom"] is True
    assert lodash["props"]["direct"] is True  # ingest facts are kept
    assert {e["source"].split("@")[0] for e in lodash["evidence"]} == {
        "manifest:package-lock.json",
        "syft",
    }
    flask = packages["pkg:pypi/flask@0.12.2"]
    assert flask["props"]["license"] is None and flask["props"]["sbom"] is True
    added = packages["pkg:npm/left-pad@1.3.0"]
    assert added["provenance"] == "TOOL" and added["confidence"] == 0.9
    assert (added["props"]["direct"], added["props"]["scope"]) == (None, "unknown")
    assert added["props"]["licenses"] == ["WTFPL"]
    owner = store.conn.execute(
        "SELECT s.key, e.provenance FROM edges e JOIN nodes s ON s.id = e.src "
        "WHERE e.dst = ? AND e.type = 'DEPENDS_ON'", (added["id"],),
    ).fetchall()  # fmt: skip
    assert [tuple(r) for r in owner] == [("Module:web", "TOOL")]
    assert q.find_nodes(store, node_type="Finding") == []
    with pytest.raises(ToolOutputError):
        parse_cyclonedx(b'{"bomFormat": "SPDX"}')
    with pytest.raises(ToolOutputError):
        parse_cyclonedx(b"{")


def test_sbom_results_survive_the_cache(tmp_path: Path) -> None:
    runtime = FakeRuntime(all_handlers())
    root = copy_fixture("vuln_app", tmp_path)
    store = Store(tmp_path / "state" / "graph.db")
    runners = {"syft": RUNNERS["syft"]}
    for expected in ("ok", "cached"):
        result, outcomes = scan_with_tools(root, store, CLOCK, runtime=runtime, runners=runners)
        assert outcomes[0].status == expected
    assert result.writes.total == 0
    package = q.find_nodes(store, node_type="Package", name="vuln-web")[0]
    assert package["provenance"] == "TOOL"
