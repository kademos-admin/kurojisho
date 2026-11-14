"""Business context -> Asset nodes and BELONGS_TO edges. All ASSERTED: a human said so."""

from __future__ import annotations

from kurojisho.config.context import Context, glob_match
from kurojisho.ingest.keys import file_id
from kurojisho.model import Edge, EdgeType, Evidence, Node, NodeType, Provenance, node_key


def build_assets(
    context: Context, context_path: str, content_hash: str, files: list[str]
) -> tuple[list[Node], list[Edge]]:
    nodes: list[Node] = []
    edges: list[Edge] = []
    for asset in context.assets:
        evidence = (
            Evidence(
                path=context_path,
                source="context-file",
                start_line=asset.line,
                end_line=asset.line,
                content_hash=content_hash,
            ),
        )
        node = Node(
            type=NodeType.ASSET,
            key=node_key(NodeType.ASSET, asset.id),
            name=asset.id,
            owner_file=context_path,
            props={
                "id": asset.id,
                "paths": list(asset.paths),
                "tier": asset.tier,
                "asvs_level": asset.asvs_level,
                "data_classes": list(asset.data_classes),
                "exposure": asset.exposure,
                "regulatory": list(asset.regulatory),
                "defaulted": list(asset.defaulted),
            },
            provenance=Provenance.ASSERTED,
            confidence=1.0,
            evidence=evidence,
        )
        nodes.append(node)
        for path in files:
            if asset.matches(path):
                patterns = [p for p in asset.paths if glob_match(p, path)]
                edges.append(
                    Edge(
                        type=EdgeType.BELONGS_TO,
                        src=file_id(path),
                        dst=node.id,
                        owner_file=context_path,
                        props={"matched": patterns},
                        provenance=Provenance.ASSERTED,
                        confidence=1.0,
                        evidence=evidence,
                    )
                )
    return nodes, edges
