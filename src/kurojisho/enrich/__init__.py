"""Security enrichment of the code graph: entry points, controls and taint flows."""

from __future__ import annotations

from dataclasses import dataclass, field

from kurojisho.enrich.code import Code
from kurojisho.enrich.entrypoints import build_entrypoints, find_entrypoints
from kurojisho.enrich.taint import TaintAnalysis
from kurojisho.ingest.code.build import CodeGraph
from kurojisho.ingest.code.extract import FileFacts
from kurojisho.model import Edge, Node


@dataclass
class Enrichment:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    code: Code | None = None


def enrich(graph: CodeGraph, facts: dict[str, FileFacts], hashes: dict[str, str]) -> Enrichment:
    """Everything here is derived from cached facts, so it is as incremental as they are."""
    if graph.resolver is None or not facts:
        return Enrichment()
    code = Code(facts, hashes, graph.resolver, {n.id for n in graph.nodes})
    entries = find_entrypoints(code)
    nodes, edges = build_entrypoints(code, entries)
    taint_nodes, taint_edges = TaintAnalysis(code, entries).run().build()
    return Enrichment(nodes + taint_nodes, edges + taint_edges, code)
