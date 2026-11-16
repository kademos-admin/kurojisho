"""M2-AC4 / M2-AC5 / M2-AC6: normalisation, dedupe and secret hygiene."""

from __future__ import annotations

import json
import random

import pytest
from hypothesis import given
from hypothesis import strategies as st

from kurojisho.findings import sarif
from kurojisho.findings.locate import FunctionIndex
from kurojisho.findings.model import (
    RawFinding,
    ToolOutputError,
    dumps,
    extract_cwes,
    loads,
    normalise_purl,
    severity_from_cvss,
    severity_from_word,
)
from kurojisho.findings.normalise import build_findings, canonical_advisory, worst
from kurojisho.findings.secrets import Scrubber, SecretHasher
from kurojisho.model import EdgeType, NodeType, Provenance, Severity, canonical_json
from tests.helpers import fn

HASHER = SecretHasher(b"test-salt")
HASHES = {"app.py": "h1", "lib.js": "h2", "requirements.txt": "h3"}
FUNCS = FunctionIndex(
    [
        fn("outer", "app.py", path="app.py", span=[1, 20]),
        fn("outer.inner", "app.py", path="app.py", span=[5, 8]),
        fn("<module>", "app.py", path="app.py", span=[1, 99], synthetic=True),
    ]
)


def raw(tool: str = "semgrep", **kwargs: object) -> RawFinding:
    base: dict[str, object] = {
        "tool": tool,
        "tool_version": "1.0",
        "category": "sast",
        "rule_id": "r1",
        "message": "msg",
        "severity": Severity.HIGH,
        "path": "app.py",
        "start_line": 6,
    }
    return RawFinding(**{**base, **kwargs})  # type: ignore[arg-type]


def build(raws: list[RawFinding]):  # type: ignore[no-untyped-def]
    return build_findings(raws, hashes=HASHES, functions=FUNCS, hasher=HASHER)


def findings(graph) -> list:  # type: ignore[no-untyped-def,type-arg]
    return [n for n in graph.nodes if n.type is NodeType.FINDING]


# -- helpers ----------------------------------------------------------------------------
def test_severity_mapping_never_turns_unknown_into_low() -> None:
    assert severity_from_word("CRITICAL") is Severity.CRITICAL
    assert severity_from_word("moderate") is Severity.MEDIUM
    assert severity_from_word("weird") is Severity.UNKNOWN
    assert severity_from_word(None) is Severity.UNKNOWN
    assert severity_from_cvss(None) is Severity.UNKNOWN
    assert [severity_from_cvss(s) for s in (9.8, 7.0, 4.0, 0.1, 0.0)] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    assert worst([Severity.MEDIUM, Severity.UNKNOWN]) is Severity.UNKNOWN
    assert worst([Severity.HIGH, Severity.UNKNOWN]) is Severity.HIGH
    assert worst([Severity.UNKNOWN, Severity.CRITICAL, Severity.LOW]) is Severity.CRITICAL


def test_cwe_purl_and_advisory_helpers() -> None:
    assert extract_cwes("CWE-89: SQL injection", "external/cwe/cwe-079", "cwe_89") == (
        "CWE-89",
        "CWE-79",
    )
    assert normalise_purl("pkg:pypi/Flask_Login@0.5?x=1") == "pkg:pypi/flask-login@0.5"
    assert normalise_purl("pkg:npm/%40scope/lib@1.0.0") == "pkg:npm/%40scope/lib@1.0.0"
    assert normalise_purl("pkg:maven/org.x/lib@2?type=jar") == "pkg:maven/org.x/lib@2"
    assert normalise_purl("pkg:golang/github.com/a/b@v1.2.3") == "pkg:golang/github.com/a/b@v1.2.3"
    assert normalise_purl("not a purl") is None and normalise_purl(None) is None
    assert canonical_advisory({"PYSEC-1", "GHSA-b", "CVE-2020-2", "CVE-2020-1"}) == "CVE-2020-1"
    assert canonical_advisory({"PYSEC-1", "GHSA-b"}) == "GHSA-b"


def test_raw_finding_normalises_and_round_trips() -> None:
    finding = raw(message="  a\n  b " + "x" * 400, cwe=("CWE-1", "CWE-1"), end_line=2)
    assert len(finding.message) == 300 and "\n" not in finding.message
    assert finding.cwe == ("CWE-1",) and finding.end_line == 6
    assert loads(dumps([finding])) == [finding]
    with pytest.raises(ValueError, match="never serialised"):
        dumps([raw(secret="hunter2hunter2")])
    assert "hunter2hunter2" not in repr(raw(secret="hunter2hunter2"))


# -- SARIF ------------------------------------------------------------------------------
def sarif_doc(**result: object) -> str:
    base = {
        "ruleId": "py.sqli",
        "level": "error",
        "message": {"text": "SQL built by concatenation"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "file:///src/app.py"},
                    "region": {"startLine": 6, "endLine": 7, "snippet": {"text": "SECRET CODE"}},
                }
            }
        ],
    }
    rules = [
        {
            "id": "py.sqli",
            "properties": {"tags": ["CWE-89: SQLi", "security"], "confidence": "HIGH"},
        },
        {"id": "scored", "properties": {"security-severity": "9.1", "cwe": ["CWE-78"]}},
    ]
    doc = {"runs": [{"tool": {"driver": {"rules": rules}}, "results": [{**base, **result}]}]}
    return json.dumps(doc)


def test_sarif_result_becomes_a_finding_without_code_snippets() -> None:
    (finding,) = sarif.parse(sarif_doc(), tool="semgrep", version="1.2")
    assert (finding.rule_id, finding.path, finding.start_line, finding.end_line) == (
        "py.sqli",
        "app.py",
        6,
        7,
    )
    assert (finding.severity, finding.cwe, finding.confidence) == (Severity.HIGH, ("CWE-89",), 0.9)
    assert "SECRET CODE" not in json.dumps(finding.to_json())


def test_sarif_severity_sources_and_paths() -> None:
    def one(**result: object) -> RawFinding:
        return sarif.parse(sarif_doc(**result), tool="t", version="1")[0]

    assert one(ruleId="scored").severity is Severity.CRITICAL
    assert one(ruleId="scored").cwe == ("CWE-78",)
    assert one(level="warning").severity is Severity.MEDIUM
    assert one(level="note").severity is Severity.LOW
    assert one(level="none").severity is Severity.UNKNOWN
    assert one(ruleId="unlisted", level=None).severity is Severity.UNKNOWN
    assert one(locations=[]).path is None
    assert sarif.relative_path("src/a.py", ()) == "src/a.py"
    assert sarif.relative_path("file:///src/a%20b.py") == "a b.py"
    assert sarif.relative_path("/src/../../etc/passwd") is None
    assert sarif.relative_path("file:///etc/passwd") == "etc/passwd"  # dropped later: unknown file
    assert sarif.parse(sarif_doc(kind="pass"), tool="t", version="1") == []
    assert one(message={}).message == "py.sqli"


@pytest.mark.parametrize("bad", ["", "not json", "[]", '{"runs": 3}', '{"version": "2.1.0"}'])
def test_garbage_sarif_is_an_error_not_an_empty_result(bad: str) -> None:
    with pytest.raises(ToolOutputError):
        sarif.parse(bad, tool="t", version="1")
    with pytest.raises(ToolOutputError, match="ruleId"):
        sarif.parse('{"runs": [{"results": [{"level": "error"}]}]}', tool="t", version="1")


# -- nodes, location, dedupe ------------------------------------------------------------
def test_finding_node_shape_and_location() -> None:
    graph = build([raw(cwe=("CWE-89",))])
    (node,) = findings(graph)
    assert node.provenance is Provenance.TOOL and node.owner_file == "app.py"
    assert node.props["raw_severity"] == "High" and node.props["final_severity"] is None
    assert node.props["triage_state"] == "untriaged" and node.props["canonical"] is True
    assert node.evidence[0].source == "semgrep@1.0" and node.evidence[0].note == "rule:r1"
    assert (node.evidence[0].start_line, node.evidence[0].content_hash) == (6, "h1")
    located = {e.props["by"]: e.dst for e in graph.edges if e.type is EdgeType.LOCATED_IN}
    assert set(located) == {"file", "span"}
    assert located["span"] == fn("outer.inner", "app.py").id  # innermost, never the synthetic one


def test_findings_outside_functions_or_known_files() -> None:
    graph = build(
        [
            raw(start_line=50),
            raw(rule_id="r2", path="gone.py", commit="c" * 40),
            raw(rule_id="r3", path=None, start_line=None),
        ]
    )
    by_rule = {n.name: n for n in findings(graph)}
    assert by_rule["r1"].props["location"] == "file"
    assert by_rule["r2"].props["location"] == "history" and by_rule["r2"].owner_file is None
    assert by_rule["r2"].evidence[0].path == "."
    assert by_rule["r2"].evidence[0].note == "rule:r2 at gone.py@cccccccccccc"
    assert by_rule["r3"].props["location"] is None
    assert [e.props["by"] for e in graph.edges if e.type is EdgeType.LOCATED_IN] == ["file"]


def test_cross_tool_duplicates_link_and_never_lower_severity() -> None:
    graph = build(
        [
            raw("bandit", rule_id="B608", cwe=("CWE-89",), severity=Severity.CRITICAL),
            raw("semgrep", cwe=("CWE-89",), severity=Severity.MEDIUM),
            raw("semgrep", rule_id="other", cwe=("CWE-78",)),  # same line, different weakness
            raw("gosec", rule_id="G1", cwe=("CWE-89",), start_line=7),  # different line
        ]
    )
    nodes = {(n.props["tool"], n.name): n for n in findings(graph)}
    canonical, duplicate = nodes[("semgrep", "r1")], nodes[("bandit", "B608")]
    assert canonical.props["canonical"] and not duplicate.props["canonical"]
    assert canonical.props["raw_severity"] == "Medium"
    assert canonical.props["group_severity"] == "Critical" == duplicate.props["group_severity"]
    assert canonical.props["reported_by"] == ["bandit", "semgrep"]
    dupes = [e for e in graph.edges if e.type is EdgeType.DUPLICATE_OF]
    assert [(e.src, e.dst) for e in dupes] == [(duplicate.id, canonical.id)]
    assert dupes[0].provenance is Provenance.INFERRED and dupes[0].confidence == 0.9
    assert nodes[("semgrep", "other")].props["canonical"]
    assert nodes[("gosec", "G1")].props["canonical"]


def test_findings_without_cwe_only_dedupe_within_a_tool_and_rule() -> None:
    graph = build([raw("a"), raw("b"), raw("a")])
    assert len(findings(graph)) == 2  # identical report from one tool collapses
    assert not [e for e in graph.edges if e.type is EdgeType.DUPLICATE_OF]


def test_dependency_findings_merge_on_any_shared_alias() -> None:
    def dep(tool: str, *ids: str, purl: str = "pkg:pypi/flask@0.12") -> RawFinding:
        return raw(
            tool, category="sca", rule_id=ids[0], path="requirements.txt", start_line=None,
            purl=purl, advisory_ids=ids, severity=Severity.UNKNOWN,
        )  # fmt: skip

    graph = build(
        [
            dep("trivy", "CVE-2018-1"),
            dep("osv-scanner", "GHSA-x", "CVE-2018-1", "PYSEC-9"),
            dep("grype", "GHSA-x"),
            dep("grype", "GHSA-other"),
            dep("trivy", "CVE-2018-1", purl="pkg:pypi/jinja2@2.0"),
        ]
    )
    groups: dict[str, list[str]] = {}
    for node in findings(graph):
        groups.setdefault(node.props["fingerprint"], []).append(node.props["tool"])
    assert sorted(sorted(g) for g in groups.values()) == [
        ["grype"],
        ["grype", "osv-scanner", "trivy"],
        ["trivy"],
    ]
    canonical = next(
        n for n in findings(graph) if n.props["canonical"] and len(n.props["reported_by"]) == 3
    )
    assert (
        canonical.props["tool"] == "osv-scanner"
        and canonical.props["purl"] == "pkg:pypi/flask@0.12"
    )
    exact = [e for e in graph.edges if e.type is EdgeType.DUPLICATE_OF]
    assert len(exact) == 2 and all(e.confidence == 1.0 for e in exact)


@given(st.permutations(range(6)))
def test_output_is_independent_of_tool_and_finding_order(order: list[int]) -> None:
    raws = [
        raw("bandit", rule_id="B608", cwe=("CWE-89",), severity=Severity.LOW),
        raw("semgrep", cwe=("CWE-89",), severity=Severity.HIGH),
        raw("gosec", cwe=("CWE-89",), severity=Severity.UNKNOWN),
        raw("semgrep", rule_id="x", start_line=3),
        raw("gitleaks", category="secret", secret="AKIAABCDEFGHIJKLMNOP", rule_id="aws"),
        raw("trufflehog", category="secret", secret="AKIAABCDEFGHIJKLMNOP", rule_id="AWS"),
    ]
    reference = build([RawFinding(**vars(r)) for r in raws])
    shuffled = build([RawFinding(**vars(raws[i])) for i in order])
    assert [n.row_hash() for n in shuffled.nodes] == [n.row_hash() for n in reference.nodes]
    assert [e.row_hash() for e in shuffled.edges] == [e.row_hash() for e in reference.edges]
    for node in findings(reference):
        if node.props["category"] == "sast" and node.props["cwe"]:
            assert node.props["group_severity"] == "High"  # never below any member


# -- secrets ----------------------------------------------------------------------------
def test_hasher_is_salted_and_previews_reveal_little() -> None:
    value = "ghp_" + "a1B2" * 9
    assert HASHER.fingerprint(value) == HASHER.fingerprint(value)
    assert HASHER.fingerprint(value) != SecretHasher(b"other").fingerprint(value)
    assert len(HASHER.fingerprint(value)) == 64 and value not in HASHER.fingerprint(value)
    assert HASHER.preview(value) == "ghp_…"
    assert HASHER.preview("short") == "…"
    with pytest.raises(ValueError, match="salt"):
        SecretHasher(b"")


def test_secret_findings_store_only_fingerprint_and_preview() -> None:
    value = "".join(random.Random(1).choices("abcdefghjkmnpqrstuvwxyz23456789", k=40))
    graph = build(
        [
            raw("gitleaks", category="secret", rule_id="generic-api-key", secret=value,
                entropy=4.4321, message=f"found {value} in code"),
            raw("trufflehog", category="secret", rule_id="Generic", secret=value, path="lib.js",
                start_line=2, secret_type="Generic"),
            raw("gitleaks", category="secret", rule_id="generic-api-key", secret=value,
                path="old.env", commit="d" * 40),
            raw("semgrep", message=f"hardcoded {value}", start_line=9),
        ]
    )  # fmt: skip
    blob = canonical_json([n.content() for n in graph.nodes] + [e.content() for e in graph.edges])
    assert value not in blob and value[:10] not in blob
    fingerprint = HASHER.fingerprint(value)
    assert f"[REDACTED:{fingerprint[:8]}]" in blob  # scrubbed even from another tool's message
    (secret,) = [n for n in graph.nodes if n.type is NodeType.SECRET]
    assert secret.key == f"Secret:{fingerprint}"
    assert secret.props["preview"] == value[:4] + "…" and secret.props["entropy"] == 4.43
    assert secret.props["verified_live"] == "unknown" and secret.props["location"] == "file"
    assert secret.props["reported_by"] == ["gitleaks", "trufflehog"]
    assert secret.props["types"] == ["Generic", "generic-api-key"]
    located = [e for e in graph.edges if e.type is EdgeType.LOCATED_IN and e.src == secret.id]
    assert len(located) == 2
    same = [n for n in findings(graph) if n.props.get("secret_fingerprint") == fingerprint]
    assert len(same) == 3 and len({n.props["fingerprint"] for n in same}) == 1
    assert sum(n.props["canonical"] for n in same) == 1
    assert next(n for n in same if n.props["canonical"]).props["tool"] == "trufflehog"


def test_history_only_secret() -> None:
    graph = build(
        [raw("gitleaks", category="secret", secret="x" * 30, path="gone", commit="e" * 40)]
    )
    (secret,) = [n for n in graph.nodes if n.type is NodeType.SECRET]
    assert secret.props["location"] == "history"
    assert not [e for e in graph.edges if e.type is EdgeType.LOCATED_IN]


def test_scrubber_handles_nesting_multiline_and_short_values() -> None:
    scrubber = Scrubber()
    assert not scrubber and scrubber.text("unchanged") == "unchanged"
    scrubber.add("-----BEGIN KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\n-----END KEY-----", "f" * 64)
    scrubber.add("tiny", "0" * 64)  # too short to be a secret; scrubbing it would mangle text
    scrubber.add("supersecretvalue123", "a" * 64)
    scrubber.add("supersecretvalue123-extended", "b" * 64)
    assert scrubber.text("a tiny thing") == "a tiny thing"
    assert scrubber.text("k=MIIEvQIBADANBgkqhkiG9w0BAQEF;") == "k=[REDACTED:ffffffff];"
    assert scrubber.text("supersecretvalue123-extended") == "[REDACTED:bbbbbbbb]"
    assert scrubber.bytes(b"x supersecretvalue123 y") == b"x [REDACTED:aaaaaaaa] y"
    node = fn("f", decorators=["auth('supersecretvalue123')"], nested={"supersecretvalue123": [1]})
    clean = scrubber.node(node)
    assert "supersecretvalue123" not in canonical_json(clean.content())
    assert scrubber.node(fn("g")) == fn("g")
