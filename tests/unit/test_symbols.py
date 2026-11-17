"""M3-AC6: VulnerableSymbol nodes and USES_SYMBOL edges."""

from __future__ import annotations

import json
from pathlib import Path

from kurojisho.enrich.code import Code
from kurojisho.enrich.symbols import build_symbols
from kurojisho.ingest.code.build import build_code_graph
from kurojisho.ingest.code.parser import extract
from kurojisho.intel.advisories import _symbols
from kurojisho.model import Edge, EdgeType, Evidence, Node, NodeType, Provenance, node_key
from kurojisho.tools.lock import load_lock
from kurojisho.tools.runners import RUNNERS
from kurojisho.tools.runners.base import RepoProfile, RunContext, ScanOptions

EV = (Evidence(path="go.mod", source="test"),)
VULN = {"module": "golang.org/x/text", "version": "v0.3.0", "package": "golang.org/x/text/language"}


def node(kind: NodeType, name: str, provenance: Provenance, **props: object) -> Node:
    return Node(
        type=kind, key=node_key(kind, name), name=name, props=dict(props),
        provenance=provenance, confidence=0.9, evidence=EV,
    )  # fmt: skip


def code_for(files: dict[str, tuple[str, str]]) -> tuple[Code, list[Node]]:
    facts = {path: extract(lang, source.encode()) for path, (lang, source) in files.items()}
    hashes = dict.fromkeys(facts, "0" * 64)
    graph = build_code_graph(hashes, facts)
    assert graph.resolver is not None
    return Code(facts, hashes, graph.resolver, {n.id for n in graph.nodes}), graph.nodes


def test_govulncheck_trace_gives_the_symbol_and_first_party_callers(tmp_path: Path) -> None:
    trace = [
        {**VULN, "function": "Parse", "receiver": "*Tag"},
        {**VULN, "function": "helper", "position": {"filename": "language/x.go", "line": 9}},
        {"module": "example.com/svc", "function": "lookup",
         "position": {"filename": "main.go", "line": 12}},
        {"module": "example.com/svc", "function": "main",
         "position": {"filename": "/abs/main.go", "line": 30}},
    ]  # fmt: skip
    stream = "\n".join(
        json.dumps(m)
        for m in (
            {"config": {"scanner_version": "v1.9.0"}},
            {"osv": {"id": "GO-2021-0113", "aliases": ["CVE-2021-38561"]}},
            {"finding": {"osv": "GO-2021-0113", "fixed_version": "v0.3.7", "trace": trace}},
        )
    ).encode()
    profile = RepoProfile(frozenset({"go"}), frozenset({"svc/go.mod"}))
    ctx = RunContext(tmp_path, tmp_path, load_lock()["govulncheck"], profile, ScanOptions())
    (finding,) = RUNNERS["govulncheck"].parse(ctx, {"module:svc": stream})
    assert finding.symbol == "golang.org/x/text/language.Tag.Parse"
    # Frames inside the dependency (they carry a version) and absolute paths are left out.
    assert finding.callers == ("svc/main.go:12",)
    assert type(finding).from_json(finding.to_json()) == finding


def test_tool_traced_call_becomes_a_tool_edge() -> None:
    code, code_nodes = code_for({"svc/main.go": ("go", "package main\n\nfunc lookup() {\n}\n")})
    finding = node(
        NodeType.FINDING, "f1", Provenance.TOOL,
        tool="govulncheck", tool_version="1.9.0", rule_id="GO-2021-0113",
        purl="pkg:golang/golang.org/x/text@v0.3.0", advisory_ids=["CVE-2021-38561", "GO-2021-0113"],
        symbol="golang.org/x/text/language.Parse", callers=["svc/main.go:3", "svc/gone.go:1"],
    )  # fmt: skip
    nodes, edges = build_symbols(code, [*code_nodes, finding], [])
    (symbol,) = nodes
    assert symbol.type is NodeType.VULNERABLE_SYMBOL and symbol.provenance is Provenance.TOOL
    assert symbol.props == {
        "purl": "pkg:golang/golang.org/x/text@v0.3.0",
        "symbol": "golang.org/x/text/language.Parse",
        "advisory_id": "CVE-2021-38561",
    }
    (edge,) = edges
    assert edge.type is EdgeType.USES_SYMBOL and edge.provenance is Provenance.TOOL
    assert edge.dst == symbol.id and edge.evidence[0].start_line == 3


def test_advisory_symbols_are_matched_against_calls_by_qualified_name() -> None:
    code, code_nodes = code_for(
        {
            "app.py": ("python", "import yaml\n\ndef parse(text):\n    return yaml.load(text)\n"),
            "other.py": ("python", "import yaml\n\ndef dump(x):\n    return yaml.safe_dump(x)\n"),
            "m.py": ("python", "from yaml import Loader\n\ndef go(s):\n    return s.load()\n"),
        }
    )
    package = node(NodeType.PACKAGE, "pyyaml", Provenance.EXTRACTED, purl="pkg:pypi/pyyaml@5.1")
    advisory = node(
        NodeType.ADVISORY, "CVE-2020-1747", Provenance.INTEL, id="CVE-2020-1747",
        symbols=[{"module": "yaml", "symbols": ["load"]}],
    )  # fmt: skip
    affected = Edge(
        type=EdgeType.AFFECTED_BY, src=package.id, dst=advisory.id,
        provenance=Provenance.TOOL, confidence=0.9, evidence=EV,
    )  # fmt: skip
    nodes, edges = build_symbols(code, [*code_nodes, package, advisory], [affected])
    (symbol,) = nodes
    assert symbol.name == "yaml.load" and symbol.provenance is Provenance.INTEL
    by_file = {e.owner_file: (e.provenance.value, e.confidence) for e in edges}
    assert by_file == {
        "app.py": ("INFERRED", 0.9),  # yaml.load, bound by the import
        "m.py": ("INFERRED", 0.5),  # some .load() in a file that imports yaml: a guess
    }
    # No advisory symbols, or no code: nothing is claimed either way.
    assert build_symbols(None, [package, advisory], [affected]) == ([], [])
    assert build_symbols(code, code_nodes, []) == ([], [])


def test_symbols_are_read_from_osv_records() -> None:
    record = {
        "affected": [
            {"ecosystem_specific": {"imports": [
                {"path": "golang.org/x/text/language", "symbols": ["Parse", "MatchStrings"]},
                {"path": "golang.org/x/text/empty"},
            ]}},
            {"ecosystem_specific": {"affected_functions": ["yaml.load", "noModule"]}},
            {"ecosystem_specific": "unexpected"},
            {},
        ]
    }  # fmt: skip
    assert _symbols(record) == [
        {"module": "golang.org/x/text/language", "symbols": ["MatchStrings", "Parse"]},
        {"module": "yaml", "symbols": ["load"]},
    ]
    assert _symbols({}) == []
