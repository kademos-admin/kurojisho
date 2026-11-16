"""CycloneDX SBOM (from Syft) -> licences on existing Package nodes, plus packages the
native manifest parsers did not see."""

from __future__ import annotations

import json
import posixpath
from dataclasses import asdict, dataclass
from typing import Any

from kurojisho.findings.model import ToolOutputError, normalise_purl
from kurojisho.findings.sarif import relative_path
from kurojisho.ingest.keys import container_id
from kurojisho.model import Edge, EdgeType, Evidence, Node, NodeType, Provenance, node_key

_SKIPPED_TYPES = {"file", "operating-system"}


@dataclass(frozen=True)
class SbomPackage:
    purl: str
    name: str
    version: str | None
    licences: tuple[str, ...] = ()
    locations: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> SbomPackage:
        return cls(
            data["purl"], data["name"], data["version"],
            tuple(data["licences"]), tuple(data["locations"]),
        )  # fmt: skip


def parse_cyclonedx(text: str | bytes) -> list[SbomPackage]:
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ToolOutputError("SBOM is not valid JSON") from exc
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ToolOutputError("SBOM is not a CycloneDX document")
    merged: dict[str, SbomPackage] = {}
    for component in doc.get("components") or []:
        if not isinstance(component, dict) or component.get("type") in _SKIPPED_TYPES:
            continue
        purl = normalise_purl(component.get("purl"))
        if purl is None:
            continue
        licences = set()
        for entry in component.get("licenses") or []:
            licence = (entry or {}).get("license") or {}
            value = licence.get("id") or licence.get("name") or (entry or {}).get("expression")
            if isinstance(value, str) and value:
                licences.add(value)
        locations = set()
        for prop in component.get("properties") or []:
            name, value = str((prop or {}).get("name")), (prop or {}).get("value")
            if (
                name.startswith("syft:location:")
                and name.endswith(":path")
                and isinstance(value, str)
            ):
                path = relative_path(value)
                if path:
                    locations.add(path)
        previous = merged.get(purl)
        version = component.get("version")
        merged[purl] = SbomPackage(
            purl,
            str(component.get("name") or purl),
            version if isinstance(version, str) and version else None,
            tuple(sorted(licences | set(previous.licences if previous else ()))),
            tuple(sorted(locations | set(previous.locations if previous else ()))),
        )
    return [merged[p] for p in sorted(merged)]


def merge_sbom(
    nodes: list[Node], packages: list[SbomPackage], hashes: dict[str, str], source: str
) -> tuple[list[Node], list[Edge]]:
    """Enrich ``nodes`` in place where the SBOM names a known package; return new Package
    nodes and DEPENDS_ON edges for packages only the SBOM tool found."""
    index = {n.key: i for i, n in enumerate(nodes) if n.type is NodeType.PACKAGE}
    new_nodes: list[Node] = []
    new_edges: list[Edge] = []
    for package in packages:
        known = [p for p in package.locations if p in hashes]
        evidence = tuple(
            Evidence(path=p, source=source, content_hash=hashes[p]) for p in known
        ) or (Evidence(path=".", source=source, note=f"sbom component {package.purl}"),)
        key = node_key(NodeType.PACKAGE, package.purl)
        licence = {"license": package.licences[0] if package.licences else None,
                   "licenses": list(package.licences), "sbom": True}  # fmt: skip
        if key in index:
            current = nodes[index[key]]
            data = current.model_dump()
            data["props"] = {**current.props, **licence}
            data["evidence"] = (*data["evidence"], *(e.model_dump() for e in evidence))
            nodes[index[key]] = Node.model_validate(data)
            continue
        ecosystem = package.purl.split(":", 1)[1].split("/", 1)[0]
        node = Node(
            type=NodeType.PACKAGE,
            key=key,
            name=package.name,
            props={
                "purl": package.purl,
                "ecosystem": ecosystem,
                "name": package.name,
                "version": package.version,
                "version_specs": [],
                "direct": None,  # the SBOM does not say; unknown, not "transitive"
                "scope": "unknown",
                **licence,
            },
            provenance=Provenance.TOOL,
            confidence=0.9,
            evidence=evidence,
        )
        new_nodes.append(node)
        for directory in sorted({posixpath.dirname(p) for p in known}):
            here = sorted(p for p in known if posixpath.dirname(p) == directory)
            new_edges.append(
                Edge(
                    type=EdgeType.DEPENDS_ON,
                    src=container_id(directory),
                    dst=node.id,
                    owner_file=here[0],
                    props={
                        "direct": None,
                        "scope": "unknown",
                        "version_specs": [],
                        "manifests": here,
                    },
                    provenance=Provenance.TOOL,
                    confidence=0.9,
                    evidence=tuple(e for e in evidence if e.path in here),
                )
            )
    return new_nodes, new_edges
