"""VulnerableSymbol nodes and the USES_SYMBOL edges that make a dependency reachable."""

from __future__ import annotations

from collections import defaultdict

from kurojisho.enrich.catalogue import EXACT, NAME_ONLY
from kurojisho.enrich.code import Code
from kurojisho.findings.locate import FunctionIndex
from kurojisho.model import Edge, EdgeType, Evidence, Node, NodeType, Provenance, node_key

_FAMILY = {"pypi": "python", "npm": "js", "golang": "go", "maven": "java"}


def _ecosystem(purl: str) -> str:
    return purl.removeprefix("pkg:").split("/", 1)[0]


def build_symbols(
    code: Code | None, nodes: list[Node], edges: list[Edge]
) -> tuple[list[Node], list[Edge]]:
    """Two kinds of evidence, never mixed up:

    * a scanner traced the call itself (govulncheck): ``TOOL``;
    * an advisory names the symbols and we find calls to them by name: ``INFERRED``.

    Finding no call is recorded as ``calls_found: 0`` and nothing more: this graph cannot
    prove a symbol is never called.
    """
    out_nodes: dict[str, Node] = {}
    out_edges: dict[str, Edge] = {}
    functions = FunctionIndex(nodes)
    by_id = {n.id: n for n in nodes}

    def symbol_node(
        purl: str,
        advisory: str,
        symbol: str,
        provenance: Provenance,
        evidence: tuple[Evidence, ...],
    ) -> Node:
        key = node_key(NodeType.VULNERABLE_SYMBOL, purl, advisory, symbol)
        if key not in out_nodes:
            out_nodes[key] = Node(
                type=NodeType.VULNERABLE_SYMBOL,
                key=key,
                name=symbol,
                props={"purl": purl, "symbol": symbol, "advisory_id": advisory},
                provenance=provenance,
                confidence=1.0,
                evidence=evidence,
            )
        return out_nodes[key]

    def uses(src: str, dst: Node, provenance: Provenance, confidence: float, ev: Evidence) -> None:
        edge = Edge(
            type=EdgeType.USES_SYMBOL,
            src=src,
            dst=dst.id,
            owner_file=ev.path if ev.path != "." else None,
            provenance=provenance,
            confidence=confidence,
            evidence=(ev,),
        )
        known = out_edges.get(edge.id)
        if known is None or confidence > known.confidence:
            out_edges[edge.id] = edge

    # 1. What a scanner traced.
    for node in nodes:
        props = node.props
        if node.type is not NodeType.FINDING or not props.get("symbol") or not props.get("purl"):
            continue
        advisory = sorted(props.get("advisory_ids") or [props["rule_id"]])[0]
        symbol = symbol_node(
            props["purl"], advisory, props["symbol"], Provenance.TOOL, node.evidence
        )
        for caller in props.get("callers") or []:
            path, _, line = caller.rpartition(":")
            src = functions.innermost(path, int(line)) if line.isdigit() else None
            if src is not None:
                evidence = Evidence(
                    path=path,
                    source=f"{props['tool']}@{props['tool_version']}",
                    start_line=int(line),
                    end_line=int(line),
                    note=f"calls {props['symbol']}",
                )
                uses(src, symbol, Provenance.TOOL, node.confidence, evidence)

    # 2. Symbols named by advisories, matched against calls by qualified name.
    wanted: dict[str, dict[str, list[tuple[str, str, str]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for edge in edges:
        if edge.type is not EdgeType.AFFECTED_BY:
            continue
        package, advisory_node = by_id.get(edge.src), by_id.get(edge.dst)
        if package is None or advisory_node is None:
            continue
        purl = package.props.get("purl") or ""
        family = _FAMILY.get(_ecosystem(purl))
        for entry in advisory_node.props.get("symbols") or []:
            for name in entry["symbols"]:
                if family is not None:
                    wanted[family][f"{entry['module']}.{name}"].append(
                        (purl, advisory_node.props["id"], name)
                    )
    if code is not None and wanted:
        for family in sorted(wanted):
            for qualified in sorted(wanted[family]):
                for purl, advisory, name in wanted[family][qualified]:
                    symbol_node(
                        purl,
                        advisory,
                        qualified,
                        Provenance.INTEL,
                        (Evidence(path=".", source="intel:osv", note=f"{advisory}:{name}"),),
                    )
        for path in sorted(code.facts):
            family = code.family(path)
            if family not in wanted:
                continue
            index = wanted[family]
            modules = set(code.aliases(path).values())
            for call in code.facts[path].calls:
                full = f"{call.receiver}.{call.name}" if call.receiver else call.name
                called = code.qualify(path, full)
                hits = [(called, EXACT)] if called is not None and called in index else []
                if not hits and call.kind == "attr":
                    # Method on a value of unknown type: the name matches and the file
                    # imports the module. A guess, and labelled as one.
                    hits = [
                        (q, NAME_ONLY)
                        for q in sorted(index)
                        if q.rpartition(".")[2] == call.name
                        and any(
                            m == q.rpartition(".")[0] or m.startswith(q.rpartition(".")[0] + ".")
                            for m in modules
                        )
                    ]
                for key, confidence in hits:
                    for purl, advisory, _ in index[key]:
                        target = out_nodes[
                            node_key(NodeType.VULNERABLE_SYMBOL, purl, advisory, key)
                        ]
                        src = code.func_id((path, call.caller))
                        if by_id.get(src) is None or by_id[src].type is not NodeType.FUNCTION:
                            continue
                        evidence = code.ev(path, call.line, note=f"calls {key}")
                        uses(src, target, Provenance.INFERRED, confidence, evidence)
    return (
        [out_nodes[k] for k in sorted(out_nodes)],
        [out_edges[k] for k in sorted(out_edges)],
    )
