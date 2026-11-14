"""Package nodes and DEPENDS_ON edges from parsed manifest records."""

from __future__ import annotations

import posixpath
from collections import defaultdict

from kurojisho.ingest.deps.base import Dep, worst_scope
from kurojisho.ingest.keys import container_id
from kurojisho.model import (
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    Provenance,
    node_id,
    node_key,
)


def _evidence(dep: Dep, hashes: dict[str, str]) -> Evidence:
    return Evidence(
        path=dep.manifest,
        source=f"manifest:{posixpath.basename(dep.manifest)}",
        start_line=dep.line,
        end_line=dep.line,
        content_hash=hashes.get(dep.manifest),
        note=dep.note,
    )


def build_packages(deps: list[Dep], hashes: dict[str, str]) -> tuple[list[Node], list[Edge]]:
    by_purl: dict[str, list[Dep]] = defaultdict(list)
    by_edge: dict[tuple[str, str], list[Dep]] = defaultdict(list)
    for dep in deps:
        by_purl[dep.purl].append(dep)
        by_edge[(posixpath.dirname(dep.manifest), dep.purl)].append(dep)
    nodes = []
    for purl in sorted(by_purl):
        group = by_purl[purl]
        first = group[0]
        nodes.append(
            Node(
                type=NodeType.PACKAGE,
                key=node_key(NodeType.PACKAGE, purl),
                name=first.name,
                props={
                    "purl": purl,
                    "ecosystem": first.ecosystem,
                    "name": first.name,
                    "version": first.version,
                    "version_specs": sorted({d.spec for d in group if d.spec}),
                    "direct": any(d.direct for d in group),
                    "scope": worst_scope(d.scope for d in group).value,
                    "license": None,  # TODO(M2): filled from the SBOM; None means unknown
                },
                provenance=Provenance.EXTRACTED,
                confidence=max(d.confidence for d in group),
                evidence=tuple(_evidence(d, hashes) for d in group),
            )
        )
    edges = []
    for directory, purl in sorted(by_edge):
        group = by_edge[(directory, purl)]
        manifests = sorted({d.manifest for d in group})
        edges.append(
            Edge(
                type=EdgeType.DEPENDS_ON,
                src=container_id(directory),
                dst=node_id(node_key(NodeType.PACKAGE, purl)),
                owner_file=manifests[0],
                props={
                    "direct": any(d.direct for d in group),
                    "scope": worst_scope(d.scope for d in group).value,
                    "version_specs": sorted({d.spec for d in group if d.spec}),
                    "manifests": manifests,
                },
                provenance=Provenance.EXTRACTED,
                confidence=max(d.confidence for d in group),
                evidence=tuple(_evidence(d, hashes) for d in group),
            )
        )
    return nodes, edges
