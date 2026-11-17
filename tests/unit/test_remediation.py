"""M3-AC8: remediation advice per finding type."""

from __future__ import annotations

import pytest

from kurojisho.model import EdgeType, Evidence, Node, NodeType, Provenance, node_key
from kurojisho.remediate.build import (
    breaking_risk,
    build_remediations,
    pick_fix,
    templates,
    version_key,
)

EV = (Evidence(path="a.py", source="semgrep@1", start_line=3, end_line=3),)


def finding(name: str, category: str, state: str = "triaged", **props: object) -> Node:
    return Node(
        type=NodeType.FINDING, key=node_key(NodeType.FINDING, name), name=name,
        props={"category": category, "triage_state": state, "tool": "t", "rule_id": name, **props},
        provenance=Provenance.TOOL, confidence=0.9, evidence=EV,
    )  # fmt: skip


@pytest.mark.parametrize(
    ("current", "fixed", "want"),
    [
        ("1.2.3", ["1.2.5", "1.3.0", "2.0.0"], "1.2.5"),  # smallest fix above what is installed
        ("1.4.0", ["1.2.5", "1.3.0", "2.0.0"], "2.0.0"),  # fixes at or below it do not help
        ("v0.3.0", ["v0.3.7"], "v0.3.7"),
        ("2.0.0", ["1.9.9"], None),
        ("1.0", [], None),
        ("weird", ["2.1.0", "1.0.0"], "1.0.0"),  # cannot compare: the lowest listed
        ("1.2.3", ["release-candidate"], None),
        ("2.14.1", ["2.15.0", "2.12.2", "2.3.1"], "2.15.0"),
    ],
)
def test_pick_fix(current: str, fixed: list[str], want: str | None) -> None:
    assert pick_fix(current, fixed) == want


@pytest.mark.parametrize(
    ("current", "target", "want"),
    [
        ("1.2.3", "1.2.9", "low"),
        ("1.2.3", "1.4.0", "medium"),
        ("1.2.3", "2.0.0", "high"),
        ("0.3.0", "0.4.0", "high"),  # 0.x minors may break
        ("0.3.0", "0.3.7", "low"),
        ("v1.2", "v1.2.1", "low"),
        ("abc", "1.0.0", "unknown"),
        ("1.0.0", None, "unknown"),
        (None, "1.0.0", "unknown"),
    ],
)
def test_breaking_risk(current: str | None, target: str | None, want: str) -> None:
    assert breaking_risk(current, target) == want


def test_version_key() -> None:
    assert version_key("v1.2.3-beta.4+build") == (1, 2, 3)
    assert version_key("2.15.0.Final") == (2, 15, 0)
    assert version_key("nothing") is None


def test_one_upgrade_per_package_covers_every_advisory() -> None:
    purl = "pkg:pypi/flask@1.0.0"
    nodes = [
        finding("CVE-1", "sca", purl=purl, fixed_versions=["1.0.1", "2.0.0"]),
        finding("CVE-2", "sca", purl=purl, fixed_versions=["1.1.0"]),
        finding("CVE-3", "sca", purl=purl, fixed_versions=[]),
        finding("CVE-9", "sca", "duplicate", purl=purl, fixed_versions=["9.9.9"]),
    ]
    (remedy,), edges = build_remediations(nodes)
    props = remedy.props
    assert (props["type"], props["fixed_version"], props["breaking_risk"]) == (
        "upgrade",
        "1.1.0",
        "medium",
    )
    assert props["unfixed_advisories"] == ["CVE-3"] and props["purl"] == purl
    assert remedy.provenance is Provenance.TOOL and remedy.name == "Upgrade pypi/flask to 1.1.0"
    assert len(edges) == 3 and {e.type for e in edges} == {EdgeType.FIXED_BY}
    assert all(e.dst == remedy.id for e in edges)


def test_package_without_any_fix_gets_a_compensating_control() -> None:
    (remedy,), _ = build_remediations(
        [finding("CVE-1", "sca", purl="pkg:npm/left@1.0.0", fixed_versions=[])]
    )
    assert remedy.props["type"] == "compensating" and remedy.props["fixed_version"] is None
    assert remedy.props["unfixed_advisories"] == ["CVE-1"]


def test_secrets_code_and_config() -> None:
    nodes = [
        finding("aws-key", "secret"),
        finding("gh-token", "secret"),
        finding("sqli-1", "sast", cwe=["CWE-89"]),
        finding("sqli-2", "sast", cwe=["CWE-564", "CWE-20"]),
        finding("odd", "sast", cwe=["CWE-9999"]),
        finding("CKV_K8S_1", "iac"),
        finding("skipped", "sast", "untriaged", cwe=["CWE-89"]),
    ]
    remedies, edges = build_remediations(nodes)
    by_type = {r.key.split(":", 1)[1]: r for r in remedies}
    assert sorted(by_type) == [
        "code_patch::review",
        "code_patch::sql-injection",
        "config::t::CKV_K8S_1",
        "rotate::rotate_then_purge_history",
    ]
    rotate = by_type["rotate::rotate_then_purge_history"]
    assert (
        "Revoke and replace" in rotate.props["guidance"] and len(rotate.props["verify_steps"]) == 3
    )
    sql = by_type["code_patch::sql-injection"]
    assert sql.props["diff"] is None and sql.provenance is Provenance.INFERRED
    assert len(edges) == 6  # the untriaged finding gets none
    assert sum(e.dst == sql.id for e in edges) == 2


def test_templates_are_complete_and_unambiguous() -> None:
    data = templates()
    seen: set[str] = set()
    for template in [
        *data["code_patch"],
        data["default_code_patch"],
        data["config"],
        data["rotate"],
    ]:
        assert template["title"] and template["guidance"] and template["verify_steps"]
        claimed = set(template.get("cwe", []))
        assert not claimed & seen  # one template per weakness
        seen |= claimed
    assert build_remediations([]) == ([], [])
