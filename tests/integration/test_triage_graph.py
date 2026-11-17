"""M3: reach, exploit and impact read from a real scanned graph, end to end into severity."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from kurojisho.findings.model import RawFinding
from kurojisho.model import Severity
from tests.conftest import CLOCK
from tests.helpers import Graph, make_intel

S = Severity
SYMBOLS = [{"module": "yaml", "symbols": ["load"]}]
FLASK = "from flask import Flask, request\nimport os, shlex\napp = Flask(__name__)\n"
TIER1 = 'assets:\n  - {id: pay, paths: ["**"], tier: 1, data_classes: [PCI], exposure: internet}\n'
TIER4 = 'assets:\n  - {id: tool, paths: ["**"], tier: 4, exposure: internal}\n'


@pytest.fixture(autouse=True)
def fixed_salt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUROJISHO_SECRET_SALT", "test-salt")


def sast(
    path: str, line: int, cwe: str, severity: Severity = S.HIGH, rule: str = "r"
) -> RawFinding:
    return RawFinding(
        "probe", "1", "sast", f"{rule}-{path}-{line}", "m", severity,
        cwe=(cwe,), path=path, start_line=line, end_line=line,
    )  # fmt: skip


def sca(
    purl: str, advisory: str, severity: Severity = S.HIGH, path: str = "requirements.txt", **kw: Any
) -> RawFinding:
    return RawFinding(
        "probe", "1", "sca", advisory, "m", severity, path=path, purl=purl,
        advisory_ids=(advisory,), **kw,
    )  # fmt: skip


def triaged(
    tmp_path: Path, files: dict[str, str], findings: list[RawFinding], **kw: Any
) -> dict[str, dict[str, Any]]:
    graph = Graph(tmp_path, files, findings=findings, **kw)
    return {props["rule_id"]: props for props in graph.nodes("Finding").values()}


def line_of(source: str, needle: str) -> int:
    return next(i for i, text in enumerate(source.splitlines(), 1) if needle in text)


APP = (
    FLASK
    + """
from flask_login import login_required

@app.route("/run")
def run():
    os.system("ls " + request.args["dir"])

@app.route("/safe")
def safe():
    os.system("ls " + shlex.quote(request.args["dir"]))

@app.route("/me")
@login_required
def me():
    os.system("id " + request.args["user"])

@app.route("/admin")
@admin_required
def admin():
    os.system("id " + request.args["user"])

def orphan(value):
    os.system(value)

@app.route("/hash")
def hash_it():
    return digest(request.args["v"])

def digest(value):
    import hashlib
    return hashlib.md5(value).hexdigest()

def unused():
    import hashlib
    return hashlib.md5(b"x").hexdigest()

@celery.task
def nightly(job):
    os.system("backup " + job)

app.run(debug=True)
"""
)


def app_findings() -> list[RawFinding]:
    marks = {
        "run": 'os.system("ls " + request.args["dir"])',
        "safe": "shlex.quote",
        "me": 'os.system("id " + request.args["user"])',
        "orphan": "os.system(value)",
        "nightly": 'os.system("backup "',
    }
    out = [sast("app.py", line_of(APP, text), "CWE-78", rule=name) for name, text in marks.items()]
    lines = [i for i, t in enumerate(APP.splitlines(), 1) if 'os.system("id "' in t]
    out.append(sast("app.py", lines[1], "CWE-78", rule="admin"))
    md5 = [i for i, t in enumerate(APP.splitlines(), 1) if "hashlib.md5" in t]
    out.append(sast("app.py", md5[0], "CWE-327", S.MEDIUM, "digest"))
    out.append(sast("app.py", md5[1], "CWE-327", S.MEDIUM, "unused"))
    out.append(sast("app.py", line_of(APP, "debug=True"), "CWE-489", S.MEDIUM, "debug"))
    return out


def by_rule(found: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {key.split("-")[0]: props for key, props in found.items()}


def test_code_findings_high_value_internet_asset(tmp_path: Path) -> None:
    found = by_rule(
        triaged(tmp_path, {"app.py": APP, "kurojisho.context.yaml": TIER1}, app_findings())
    )

    def summary(name: str) -> tuple[str, str | None, str]:
        return (
            found[name]["final_severity"],
            found[name]["triage_rule"],
            found[name]["reach"]["value"],
        )

    assert summary("run") == ("Critical", "TRI-01", "R4")
    assert found["run"]["entry_points"] == ["app.py::http GET /run"]
    assert found["run"]["impact"]["value"] == "I3" and found["run"]["asset"] == "pay"
    # Strong sanitizer on the only path: not exploitable as written, flagged for review,
    # but still High on a tier-1 internet asset. The severity is not waved away.
    assert summary("safe") == ("High", "TRI-02", "R4")
    assert found["safe"]["exploit"]["value"] == "E0"
    assert found["safe"]["triage_state"] == "false_positive_candidate"
    assert "needs_reviewer_ack" in found["safe"]["flags"]
    # Auth proven by import: exactly one step down. Auth guessed by name: nothing.
    assert summary("me") == ("High", "TRI-01", "R4") and found["me"]["auth_applied"] is True
    assert (
        summary("admin") == ("Critical", "TRI-01", "R4") and found["admin"]["auth_applied"] is False
    )
    # Nothing calls it: unknown, never "dead code".
    assert summary("orphan") == ("High", "TRI-03", "R0")
    assert found["orphan"]["flags"] == ["needs_manual_review"]
    # Not a taint weakness: reach is that of the enclosing function.
    assert summary("digest") == ("High", "TRI-02", "R4")
    assert summary("unused") == ("High", "TRI-03", "R0")
    # Queue consumers are internal entry points.
    assert summary("nightly") == ("High", "TRI-03", "R3")
    assert summary("debug") == ("High", "TRI-02", "R4")
    assert found["debug"]["reach"]["confidence"] == 0.7  # module-level code
    for props in found.values():
        assert props["reasons"] and props["final_severity"] and props["reach"]["reason"]


def test_same_code_low_value_internal_asset(tmp_path: Path) -> None:
    found = by_rule(
        triaged(tmp_path, {"app.py": APP, "kurojisho.context.yaml": TIER4}, app_findings())
    )
    assert found["run"]["impact"]["value"] == "I1"
    assert (found["run"]["final_severity"], found["run"]["triage_rule"]) == ("High", "TRI-02")
    # R4, E0 (sanitized), I1: Medium, and the evidence qualifies, so raw High is lowered.
    assert (found["safe"]["final_severity"], found["safe"]["guards"]) == ("Medium", [])
    # Unknown reach and low impact: no rule; the tool's severity stands.
    assert (found["orphan"]["final_severity"], found["orphan"]["triage_state"]) == (
        "High",
        "unmatched",
    )
    # R3 + I1 would be Medium, but the entry point was recognised by decorator name only
    # (0.5), so that lowering is not allowed.
    assert (found["nightly"]["final_severity"], found["nightly"]["guards"]) == (
        "High",
        ["GUARD-02"],
    )
    assert found["unused"]["final_severity"] == "Medium"  # raw Medium kept


def test_without_a_context_file_impact_is_assumed_and_never_lowers(tmp_path: Path) -> None:
    found = by_rule(triaged(tmp_path, {"app.py": APP}, app_findings()))
    impact = found["run"]["impact"]
    assert (impact["value"], impact["assumed"], impact["qualifies"]) == ("I2", True, False)
    assert found["run"]["final_severity"] == "Critical"
    assert all(
        Severity(p["final_severity"]).rank >= Severity(p["group_severity"]).rank
        for p in found.values()
    )


def test_test_code_is_r1_by_its_path(tmp_path: Path) -> None:
    files = {
        "tests/test_x.py": "import os\ndef test_it(v):\n    os.system(v)\n",
        "kurojisho.context.yaml": TIER1,
    }
    found = triaged(tmp_path, files, [sast("tests/test_x.py", 3, "CWE-78")])
    (props,) = found.values()
    assert (props["final_severity"], props["triage_rule"], props["reach"]["value"]) == (
        "Info",
        "TRI-06",
        "R1",
    )
    assert props["reach"]["provenance"] == "EXTRACTED" and props["guards"] == []


def test_context_conflict_uses_the_worse_exposure(tmp_path: Path) -> None:
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata: {labels: {app: api}}
    spec: {containers: [{name: api, image: "api:1"}]}
---
apiVersion: v1
kind: Service
metadata: {name: api}
spec: {type: LoadBalancer, selector: {app: api}}
"""
    context = 'assets:\n  - {id: api, paths: ["api/**"], tier: 1, exposure: none}\n'
    source = FLASK + '@app.route("/x")\ndef x():\n    os.system(request.args["c"])\n'
    files = {
        "api/app.py": source,
        "api/Dockerfile": "FROM python:3.12\nCOPY . /app\n",
        "k8s.yaml": manifest,
        "kurojisho.context.yaml": context,
    }
    finding = sast("api/app.py", line_of(source, "os.system"), "CWE-78")
    (props,) = triaged(tmp_path / "a", files, [finding]).values()
    assert props["exposure"] == "internet" and props["impact"]["value"] == "I3"
    assert "deployment files disagree" in props["impact"]["reason"]
    assert props["final_severity"] == "Critical"
    del files["k8s.yaml"]  # nothing contradicts the context: its word is taken (ASSERTED)
    (props,) = triaged(tmp_path / "b", files, [finding]).values()
    assert (props["exposure"], props["impact"]["value"]) == ("none", "I1")
    assert (props["final_severity"], props["triage_rule"]) == ("High", "TRI-02")


# -- dependencies -------------------------------------------------------------------------
LOCK = """{"name": "web", "lockfileVersion": 3, "packages": {
  "": {"name": "web", "dependencies": {"lodash": "4.17.0"}, "devDependencies": {"mocha": "9.0.0"}},
  "node_modules/lodash": {"version": "4.17.0"},
  "node_modules/mocha": {"version": "9.0.0", "dev": true}
}}"""
PACKAGE = (
    '{"name": "web", "dependencies": {"lodash": "4.17.0"}, "devDependencies": {"mocha": "9.0.0"}}'
)
GO = """package main

import "golang.org/x/text/language"

func parse(w http.ResponseWriter, r *http.Request) {
	language.Parse(r.URL.Query().Get("l"))
}

func main() {
	http.HandleFunc("/p", parse)
}
"""


def test_dependency_reachability_states(tmp_path: Path) -> None:
    files = {
        "package.json": PACKAGE,
        "package-lock.json": LOCK,
        "go.mod": "module example.com/m\n\nrequire golang.org/x/text v0.3.0\n",
        "main.go": GO,
        "kurojisho.context.yaml": TIER1,
    }
    text = "pkg:golang/golang.org/x/text@v0.3.0"
    findings = [
        sca("pkg:npm/lodash@4.17.0", "CVE-2020-1", path="package-lock.json"),
        sca("pkg:npm/mocha@9.0.0", "CVE-2020-2", path="package-lock.json",
            fixed_versions=("9.0.1",)),
        sca(text, "GO-1", path="go.mod", tool_reachability="symbol",
            symbol="golang.org/x/text/language.Parse", callers=("main.go:6",)),
        sca(text, "GO-2", path="go.mod", tool_reachability="package"),
        sca(text, "GO-3", path="go.mod", tool_reachability="symbol", symbol="x.Y"),
    ]  # fmt: skip
    found = triaged(tmp_path, files, findings)

    def summary(rule: str) -> tuple[str, str | None, str, str]:
        p = found[rule]
        return p["final_severity"], p["triage_rule"], p["reach"]["value"], p["reach"]["provenance"]

    # No symbol data: unknown. High on a tier-1 asset, flagged for a human.
    assert summary("CVE-2020-1") == ("High", "TRI-03", "R0", "INFERRED")
    assert found["CVE-2020-1"]["vex"] == {"status": "under_investigation"}
    assert found["CVE-2020-1"]["exploit"]["assumed"] is True  # no intel cached
    # Dev-only by the lockfile: not shipped.
    assert summary("CVE-2020-2") == ("Info", "TRI-06", "R1", "EXTRACTED")
    assert found["CVE-2020-2"]["vex"] == {
        "status": "not_affected",
        "justification": "component_not_present",
    }
    # govulncheck traced the call into an HTTP handler.
    assert summary("GO-1") == ("Critical", "TRI-01", "R4", "TOOL")
    assert found["GO-1"]["entry_points"] == ["main.go::http ANY /p"]
    assert found["GO-1"]["vex"] == {"status": "affected"}
    # govulncheck says the symbol is not called: Low, and that claim comes from a tool.
    assert summary("GO-2") == ("Low", "TRI-05", "R2", "TOOL")
    assert found["GO-2"]["vex"]["justification"] == "vulnerable_code_not_in_execute_path"
    # Called, caller not located: reachable, entry point unknown.
    assert summary("GO-3") == ("High", "TRI-03", "R3", "TOOL")


def test_kev_floor_and_intel_backed_exploitability(tmp_path: Path) -> None:
    pom = """<project><modelVersion>4.0.0</modelVersion><groupId>d</groupId>
<artifactId>a</artifactId>
<version>1</version><dependencies><dependency><groupId>org.apache.logging.log4j</groupId>
<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>"""
    purl = "pkg:maven/org.apache.logging.log4j:log4j-core@2.14.1"
    findings = [
        sca(purl, "CVE-2021-44228", S.LOW, path="pom.xml", fixed_versions=("2.15.0",)),
        sca(purl, "CVE-2000-0001", S.LOW, path="pom.xml"),
    ]
    intel = make_intel(tmp_path / "intel", CLOCK)
    found = triaged(
        tmp_path / "repo", {"pom.xml": pom, "kurojisho.context.yaml": TIER4}, findings, intel=intel
    )
    shell = found["CVE-2021-44228"]
    assert (shell["final_severity"], shell["triage_rule"]) == ("Critical", "EXP-01")
    assert shell["exploit"]["value"] == "E3" and shell["exploit"]["provenance"] == "INTEL"
    other = found["CVE-2000-0001"]
    # Not in KEV, no EPSS score: assumed exploitable; R0 + I1 matches no rule; raw Low stays.
    assert (other["final_severity"], other["triage_state"]) == ("Low", "unmatched")
    assert other["exploit"]["assumed"] is True


def test_inferred_not_called_is_only_a_hint(tmp_path: Path) -> None:
    """An advisory names its symbols and we see no call: R2 at 0.6 cannot lower (GUARD-02)."""
    from kurojisho.config.context import load_context
    from kurojisho.model import NodeType
    from kurojisho.triage import triage as run_triage

    graph = Graph(tmp_path, {"requirements.txt": "pyyaml==5.1\n", "kurojisho.context.yaml": TIER1},
                  findings=[sca("pkg:pypi/pyyaml@5.1", "CVE-2020-1747")])  # fmt: skip
    # Re-run triage on the stored graph with symbol data added to the advisory.
    import json

    from kurojisho.model import Edge, Node

    rows = graph.store.conn.execute("SELECT * FROM nodes WHERE retired = 0").fetchall()
    nodes = [
        Node(type=r["type"], key=r["key"], name=r["name"], owner_file=r["owner_file"],
             props=json.loads(r["props"]), provenance=r["provenance"], confidence=r["confidence"],
             evidence=json.loads(r["evidence"]))
        for r in rows
    ]  # fmt: skip
    nodes = [
        n.model_copy(update={"props": {**n.props, "symbols": SYMBOLS}})
        if n.type is NodeType.ADVISORY else n
        for n in nodes
    ]  # fmt: skip
    erows = graph.store.conn.execute("SELECT * FROM edges WHERE retired = 0").fetchall()
    edges = [
        Edge(type=r["type"], src=r["src"], dst=r["dst"], discriminator=r["discriminator"],
             props=json.loads(r["props"]), provenance=r["provenance"], confidence=r["confidence"],
             evidence=json.loads(r["evidence"]))
        for r in erows
    ]  # fmt: skip
    out = run_triage(nodes, edges, load_context(TIER1), True)
    (finding,) = [n for n in out if n.type is NodeType.FINDING]
    assert finding.props["reach"]["value"] == "R2" and finding.props["reach"]["qualifies"] is False
    assert finding.props["final_severity"] == "High" and finding.props["guards"] == ["GUARD-02"]
    assert finding.props["vex"] == {"status": "under_investigation"}


# -- secrets, IaC, duplicates ---------------------------------------------------------------
def test_secrets_iac_and_duplicates(tmp_path: Path) -> None:
    def leak(path: str, value: str, **kw: Any) -> RawFinding:
        return RawFinding("probe", "1", "secret", f"key-{path}", "m", S.UNKNOWN, path=path,
                          start_line=1, end_line=1, secret=value, **kw)  # fmt: skip

    files = {
        "config.py": 'KEY = "AKIAQWERTYUIOPASDFGH"\n',
        "tests/fixtures/sample.py": 'KEY = "AKIAZXCVBNMLKJHGFDSA"\n',
        ".github/workflows/ci.yml": (
            "name: ci\non: push\nenv: {T: ghp_abcdefghijklmnopqrstuvwxyz0123456789}\n"
        ),
        "live.py": 'KEY = "AKIA1234567890ABCDEF"\n',
        "k8s.yaml": "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {containers: []}\n",
    }
    findings: list[RawFinding] = [
        leak("config.py", "AKIAQWERTYUIOPASDFGH"),
        leak("tests/fixtures/sample.py", "AKIAZXCVBNMLKJHGFDSA"),
        leak(".github/workflows/ci.yml", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        leak("live.py", "AKIA1234567890ABCDEF", verified_live="true"),
        RawFinding("probe", "1", "iac", "CKV_1", "m", S.MEDIUM, path="k8s.yaml", start_line=1),
    ]
    # Secret findings are never persisted for re-import, so they go straight to a scan.
    from kurojisho.findings.locate import FunctionIndex
    from kurojisho.findings.normalise import build_findings
    from kurojisho.findings.secrets import SecretHasher
    from kurojisho.ingest.pipeline import Extension, IngestState, scan
    from kurojisho.store import Store

    for name, content in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(content)
    store = Store(":memory:")

    def extend(state: IngestState) -> Extension:
        built = build_findings(
            findings, hashes=state.hashes, functions=FunctionIndex(state.nodes),
            hasher=SecretHasher(b"salt"),
        )  # fmt: skip
        return Extension(built.nodes, built.edges, built.scrubber)

    scan(tmp_path, store, CLOCK, extend=extend)
    import json

    rows = store.conn.execute("SELECT props FROM nodes WHERE type = 'Finding'").fetchall()
    found = {p["rule_id"]: p for p in (json.loads(r[0]) for r in rows)}
    assert (found["key-config.py"]["final_severity"], found["key-config.py"]["triage_rule"]) == (
        "High",
        "SEC-02",
    )
    ci = found["key-.github/workflows/ci.yml"]
    assert (ci["final_severity"], ci["triage_rule"]) == ("High", "SEC-02")
    fixture = found["key-tests/fixtures/sample.py"]
    assert (fixture["final_severity"], fixture["triage_state"]) == ("Unknown", "unmatched")
    live = found["key-live.py"]
    assert (live["final_severity"], live["triage_rule"], live["fix"]) == (
        "Critical", "SEC-01", "rotate_then_purge_history",
    )  # fmt: skip
    assert (found["CKV_1"]["final_severity"], found["CKV_1"]["triage_state"]) == (
        "Medium",
        "unmatched",
    )
    fixes = dict(store.conn.execute(
        "SELECT json_extract(n.props, '$.type'), COUNT(*) FROM edges e "
        "JOIN nodes n ON n.id = e.dst "
        "WHERE e.type = 'FIXED_BY' GROUP BY 1"
    ).fetchall())  # fmt: skip
    assert fixes == {"rotate": 4, "config": 1}
    blob = "\n".join(str(tuple(r)) for r in store.conn.execute("SELECT * FROM nodes").fetchall())
    assert "AKIA" not in blob.replace("AKIA…", "") and "ghp_abcdef" not in blob


def test_duplicates_inherit_the_canonical_decision(tmp_path: Path) -> None:
    source = FLASK + '@app.route("/x")\ndef x():\n    os.system(request.args["c"])\n'
    line = line_of(source, "os.system")
    first = sast("app.py", line, "CWE-78", S.MEDIUM, "a")
    second = RawFinding("other", "2", "sast", "b", "m", S.HIGH, cwe=("CWE-78",), path="app.py",
                        start_line=line, end_line=line)  # fmt: skip
    found = triaged(tmp_path, {"app.py": source}, [first, second])
    states = sorted(p["triage_state"] for p in found.values())
    assert states == ["duplicate", "triaged"]
    assert {p["final_severity"] for p in found.values()} == {"Critical"}
    assert {p["triage_rule"] for p in found.values()} == {"TRI-01"}
