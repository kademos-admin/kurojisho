"""M3 exit gate: full scan of the vulnerable fixture, triaged, reported in every format."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML
from syrupy.assertion import SnapshotAssertion
from typer.testing import CliRunner

from kurojisho.cli import app
from kurojisho.model import Severity
from kurojisho.report.model import load_report
from kurojisho.report.render import FORMATS, render
from kurojisho.scanner import scan_with_tools
from kurojisho.store import Store
from kurojisho.tools.runners import RUNNERS
from tests.conftest import CLOCK, FIXTURES, copy_fixture
from tests.helpers import FakeRuntime, all_handlers, gitleaks_report, make_intel, writes

DEFAULT = {n: r for n, r in RUNNERS.items() if not r.opt_in}
CONTEXT = """\
assets:
  - {id: public-api, paths: ["api/**"], tier: 1, data_classes: [PII, PCI], exposure: internet}
  - {id: web, paths: ["web/**"], tier: 2, exposure: internet}
  - {id: batch, paths: ["java/**"], tier: 4, exposure: none}
defaults: {tier: 3}
"""
SECRET = "AKIA" + "Q7RZ2XWV5N8TJKPL"  # generated for this test; never a real credential


@pytest.fixture(autouse=True)
def fixed_salt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUROJISHO_SECRET_SALT", "test-salt")


def scanned(tmp_path: Path, *, context: bool = True, secret: bool = False) -> Store:
    root = copy_fixture("vuln_app", tmp_path)
    if context:
        (root / "kurojisho.context.yaml").write_text(CONTEXT)
    handlers = all_handlers()
    if secret:
        (root / "api" / "settings.py").write_text(f'AWS_KEY = "{SECRET}"\n')
        leak = gitleaks_report(("aws-key", "api/settings.py", 1, SECRET))
        handlers = all_handlers(gitleaks=writes({"dir.json": leak, "git.json": "[]"}))
    store = Store(tmp_path / "state" / "graph.db")
    scan_with_tools(
        root, store, CLOCK, runtime=FakeRuntime(handlers), runners=DEFAULT,
        intel=make_intel(tmp_path / "intel", CLOCK),
    )  # fmt: skip
    return store


def findings(store: Store) -> list[dict[str, Any]]:
    rows = store.conn.execute("SELECT props FROM nodes WHERE type = 'Finding' AND retired = 0")
    return [json.loads(r[0]) for r in rows]


def test_every_finding_is_triaged_with_reasons_and_a_fix(tmp_path: Path) -> None:
    store = scanned(tmp_path)
    found = findings(store)
    assert len(found) == 245
    for props in found:
        assert props["final_severity"] in {s.value for s in Severity}
        assert props["triage_state"] != "untriaged" and props["reasons"]
        if props["category"] in ("sast", "sca"):
            for factor in ("reach", "exploit", "impact"):
                assert props[factor]["reason"] and props[factor]["provenance"]
    canonical = sum(p["triage_state"] != "duplicate" for p in found)
    fixed = store.conn.execute(
        "SELECT COUNT(DISTINCT src) FROM edges WHERE type = 'FIXED_BY' AND retired = 0"
    ).fetchone()[0]
    assert fixed == canonical  # every reported finding comes with a fix
    kinds = dict(
        store.conn.execute(
            "SELECT json_extract(props, '$.type'), COUNT(*) FROM nodes "
            "WHERE type = 'Remediation' AND retired = 0 GROUP BY 1"
        ).fetchall()
    )
    assert set(kinds) >= {"upgrade", "code_patch", "config"}
    log4j = next(p for p in found if "CVE-2021-44228" in (p.get("advisory_ids") or []))
    assert (log4j["final_severity"], log4j["triage_rule"]) == ("Critical", "EXP-01")


def test_business_context_changes_severity_and_only_with_evidence(tmp_path: Path) -> None:
    with_context = {
        (p["path"], (p["span"] or [0])[0], p["rule_id"]): p
        for p in findings(scanned(tmp_path / "a"))
        if p["category"] == "sast"
    }
    without = {
        (p["path"], (p["span"] or [0])[0], p["rule_id"]): p
        for p in findings(scanned(tmp_path / "b", context=False))
        if p["category"] == "sast"
    }
    key = ("api/app.py", 16, "kurojisho.python.sql-string-built")
    assert with_context[key]["impact"]["value"] == "I3" and without[key]["impact"]["assumed"]
    assert with_context[key]["final_severity"] == without[key]["final_severity"] == "Critical"
    # Nothing is ever below the tool's own severity when there is no context to justify it.
    for props in without.values():
        assert Severity(props["final_severity"]).rank >= Severity(props["group_severity"]).rank
    # The Java code sits in a tier-4, unexposed asset and nothing reaches it: R0 with I0
    # matches no rule, so the tool's rating stands (GUARD-01 territory, not a downgrade).
    java = [p for (path, _, _), p in with_context.items() if path.startswith("java/")]
    assert java and all(p["final_severity"] == p["group_severity"] for p in java)
    assert all(p["impact"]["value"] == "I0" and p["reach"]["value"] == "R0" for p in java)


def test_reachability_precision_and_recall_against_labels(tmp_path: Path) -> None:
    """M3-AC3 on the in-repo labelled fixture: is "reachable from an entry point" right?"""
    labels = YAML(typ="safe").load((FIXTURES / "vuln_app" / "expected.yaml").read_text())
    truth = {(path, line): reachable for path, line, reachable in labels["entry_reachable"]}
    answers: dict[tuple[str, int], str] = {}
    for props in findings(scanned(tmp_path)):
        if props["tool"] == "semgrep":
            answers[(props["path"], props["span"][0])] = props["reach"]["value"]
    assert set(answers) == set(truth)
    said = {k for k, v in answers.items() if v == "R4"}
    real = {k for k, v in truth.items() if v}
    precision = len(said & real) / len(said)
    recall = len(said & real) / len(real)
    assert (precision, recall) == (1.0, 1.0)
    # What is not reachable is reported as unknown, never as a proven "not reachable".
    assert {answers[k] for k in truth if k not in real} == {"R0"}


@pytest.mark.parametrize("fmt", FORMATS)
def test_report_golden(fmt: str, tmp_path: Path, snapshot: SnapshotAssertion) -> None:
    assert render(load_report(scanned(tmp_path)), fmt) == snapshot


def test_reports_are_well_formed_and_agree_with_each_other(tmp_path: Path) -> None:
    report = load_report(scanned(tmp_path))
    data = json.loads(render(report, "json"))
    assert data["schema"] == "kurojisho.report/1" and sum(data["summary"].values()) == len(
        data["findings"]
    )
    ranks = [Severity(f["final_severity"]).rank for f in data["findings"]]
    assert ranks == sorted(ranks, reverse=True)
    assert data["coverage_gaps"] and all(f["remediation"] for f in data["findings"])

    sarif = json.loads(render(report, "sarif"))
    assert sarif["version"] == "2.1.0"
    (run,) = sarif["runs"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert len(run["results"]) == len(data["findings"])
    for result in run["results"]:
        assert result["ruleId"] in rule_ids and result["level"] in ("error", "warning", "note")
        assert result["message"]["text"] and result["partialFingerprints"]["kurojisho/v1"]
    critical = [r for r in run["results"] if r["properties"]["final_severity"] == "Critical"]
    assert critical and all(r["level"] == "error" for r in critical)

    sca = [f for f in data["findings"] if f["category"] == "sca"]
    vex = json.loads(render(report, "openvex"))
    assert vex["@context"] == "https://openvex.dev/ns/v0.2.0" and vex["@id"].startswith("urn:")
    assert len(vex["statements"]) == len(sca)
    for statement in vex["statements"]:
        assert statement["status"] in ("affected", "not_affected", "under_investigation")
        assert statement["products"][0]["@id"].startswith("pkg:")
        # OpenVEX requires a justification for not_affected and an action for affected.
        assert ("justification" in statement) == (statement["status"] == "not_affected")
        assert ("action_statement" in statement) == (statement["status"] == "affected")
    cdx = json.loads(render(report, "cyclonedx-vex"))
    assert (cdx["bomFormat"], cdx["specVersion"]) == ("CycloneDX", "1.5")
    assert len(cdx["vulnerabilities"]) == len(sca)
    states = {v["analysis"]["state"] for v in cdx["vulnerabilities"]}
    assert states <= {"exploitable", "not_affected", "in_triage"}
    # No finding here has evidence that its package is unused, so none may claim so.
    assert all(s["status"] != "not_affected" for s in vex["statements"])

    markdown = render(report, "md")
    assert "## What was not checked" in markdown and "iac_not_modelled" in markdown
    listed = markdown.count("\n### [")
    assert listed == len(report.at_least(Severity.MEDIUM)) < len(report.findings)
    assert render(report, "md", Severity.CRITICAL).count("\n### [") == data["summary"]["Critical"]


def test_two_scans_give_byte_identical_reports(tmp_path: Path) -> None:
    first = load_report(scanned(tmp_path / "a"))
    second = load_report(scanned(tmp_path / "b"))
    for fmt in FORMATS:
        assert render(first, fmt) == render(second, fmt)


def test_raw_secrets_never_reach_any_report(tmp_path: Path) -> None:
    store = scanned(tmp_path, secret=True)
    report = load_report(store)
    secret = [f for f in report.findings if f.props["category"] == "secret"]
    assert secret and secret[0].props["triage_rule"] == "SEC-02"
    assert secret[0].fix is not None and secret[0].fix["type"] == "rotate"
    for fmt in FORMATS:
        text = render(report, fmt)
        assert SECRET not in text and SECRET[4:] not in text


def test_report_command(tmp_path: Path) -> None:
    store = scanned(tmp_path)
    store.close()
    db = ["--db", str(tmp_path / "state" / "graph.db")]
    runner = CliRunner()
    shown = runner.invoke(app, ["report", *db])
    assert shown.exit_code == 0 and shown.stdout.startswith("# Security findings: vuln_app")
    target = tmp_path / "out.sarif"
    saved = runner.invoke(app, ["report", "--format", "sarif", "-o", str(target), *db])
    assert saved.exit_code == 0 and json.loads(target.read_text())["version"] == "2.1.0"
    only = runner.invoke(app, ["report", "-f", "json", "--min-severity", "critical", *db])
    assert {f["final_severity"] for f in json.loads(only.stdout)["findings"]} == {"Critical"}
    assert runner.invoke(app, ["report", "--format", "pdf", *db]).exit_code != 0
    assert runner.invoke(app, ["report", "--min-severity", "urgent", *db]).exit_code != 0
    empty = ["--db", str(tmp_path / "none" / "graph.db")]
    assert runner.invoke(app, ["report", *empty]).exit_code != 0
