"""Advisory nodes (INTEL) and AFFECTED_BY edges for the vulnerabilities scanners reported."""

from __future__ import annotations

import csv
import gzip
import io
import json
import zipfile
from collections import defaultdict
from functools import cached_property
from typing import Any

from kurojisho.findings.normalise import canonical_advisory
from kurojisho.intel.cache import IntelCache
from kurojisho.model import Edge, EdgeType, Evidence, Node, NodeType, Provenance, node_id, node_key

MAX_SUMMARY = 300


class IntelData:
    """Read-only view of the cached feeds. A missing feed yields None (unknown), never a
    default such as "not exploited"."""

    def __init__(self, cache: IntelCache) -> None:
        self.cache = cache
        self._zips: list[zipfile.ZipFile] | None = None

    @cached_property
    def kev(self) -> dict[str, str] | None:
        path = self.cache.root / "feeds" / "kev.json"
        if not self.cache.has("kev") or not path.is_file():
            return None
        try:
            items = json.loads(path.read_bytes())["vulnerabilities"]
            return {str(i["cveID"]): str(i.get("dateAdded") or "") for i in items}
        except (ValueError, KeyError, TypeError, OSError):
            return None

    @cached_property
    def epss(self) -> dict[str, tuple[float, float]] | None:
        path = self.cache.root / "feeds" / "epss.csv.gz"
        if not self.cache.has("epss") or not path.is_file():
            return None
        scores: dict[str, tuple[float, float]] = {}
        try:
            with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
                rows = csv.reader(line for line in handle if not line.startswith("#"))
                for row in rows:
                    if len(row) >= 3 and row[0].startswith("CVE-"):
                        scores[row[0]] = (float(row[1]), float(row[2]))
        except (OSError, ValueError, EOFError):
            return None
        return scores

    def osv(self, ids: list[str]) -> dict[str, Any] | None:
        """The OSV record for any of ``ids``, from the per-ecosystem dumps."""
        if self._zips is None:
            self._zips = []
            for path in sorted((self.cache.root / "osv").glob("osv-scalibr/*/all.zip")):
                try:
                    self._zips.append(zipfile.ZipFile(path))
                except (OSError, zipfile.BadZipFile):
                    continue
        for identifier in ids:
            for archive in self._zips:
                try:
                    with archive.open(f"{identifier}.json") as handle:
                        record: dict[str, Any] = json.load(io.TextIOWrapper(handle, "utf-8"))
                        return record
                except (KeyError, ValueError, OSError):
                    continue
        return None

    def nvd_score(self, cve: str) -> float | None:
        path = self.cache.root / "nvd" / f"{cve}.json"
        if not path.is_file():
            return None
        try:
            metrics = json.loads(path.read_bytes())["vulnerabilities"][0]["cve"]["metrics"]
        except (ValueError, KeyError, IndexError, TypeError, OSError):
            return None
        scores = [
            entry["cvssData"]["baseScore"]
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30")
            for entry in metrics.get(key) or []
            if isinstance((entry.get("cvssData") or {}).get("baseScore"), int | float)
        ]
        return float(max(scores)) if scores else None


def _clusters(alias_sets: list[set[str]]) -> list[set[str]]:
    """Merge alias sets that share any identifier, across packages and tools."""
    merged: list[set[str]] = []
    for ids in sorted(alias_sets, key=sorted):
        current = set(ids)
        rest = []
        for cluster in merged:
            if cluster & current:
                current |= cluster
            else:
                rest.append(cluster)
        merged = [*rest, current]
    return merged


def build_advisories(
    finding_nodes: list[Node], intel: IntelData | None
) -> tuple[list[Node], list[Edge]]:
    sca = [
        n for n in finding_nodes if n.type is NodeType.FINDING and n.props.get("category") == "sca"
    ]
    clusters = _clusters([set(n.props["advisory_ids"]) for n in sca if n.props.get("advisory_ids")])
    by_id = {identifier: canonical_advisory(c) for c in clusters for identifier in c}
    members: dict[str, list[Node]] = defaultdict(list)
    aliases: dict[str, set[str]] = defaultdict(set)
    for node in sca:
        ids = node.props.get("advisory_ids") or []
        if ids and node.props.get("purl"):
            members[by_id[ids[0]]].append(node)
            aliases[by_id[ids[0]]] |= set(ids)
    nodes: list[Node] = []
    edges: list[Edge] = []
    for advisory in sorted(members):
        group = members[advisory]
        ids = sorted(aliases[advisory])
        cves = [i for i in ids if i.startswith("CVE-")]
        scores = [n.props["cvss"] for n in group if n.props.get("cvss") is not None]
        props: dict[str, Any] = {
            "id": advisory,
            "aliases": ids,
            "summary": None,
            "cvss": max(scores) if scores else None,
            "cvss_v3_vector": None,
            "cvss_v4_vector": None,
            # None = unknown. A missing feed must not read as "not exploited".
            "kev": None,
            "kev_added": None,
            "epss": None,
            "epss_percentile": None,
            "exploit_public": None,  # TODO(M3): exploit-availability sources
            "fixed_versions": sorted(
                {v for n in group for v in n.props.get("fixed_versions") or []}
            ),
            "reported_by": sorted({n.props["tool"] for n in group}),
        }
        used: list[str] = []
        if intel is not None:
            record = intel.osv([i for i in ids if not i.startswith("CVE-")] + cves)
            if record is not None:
                used.append("osv")
                summary = record.get("summary")
                props["summary"] = " ".join(str(summary).split())[:MAX_SUMMARY] if summary else None
                for entry in record.get("severity") or []:
                    if entry.get("type") == "CVSS_V3":
                        props["cvss_v3_vector"] = entry.get("score")
                    elif entry.get("type") == "CVSS_V4":
                        props["cvss_v4_vector"] = entry.get("score")
            if intel.kev is not None:
                used.append("kev")
                hit = next((c for c in cves if c in intel.kev), None)
                props["kev"] = hit is not None
                props["kev_added"] = intel.kev[hit] or None if hit else None
            if intel.epss is not None and cves:
                rated = [intel.epss[c] for c in cves if c in intel.epss]
                if rated:
                    used.append("epss")
                    props["epss"], props["epss_percentile"] = max(rated)
            nvd = [s for s in (intel.nvd_score(c) for c in cves) if s is not None]
            if nvd:
                used.append("nvd")
                props["cvss"] = max([*nvd, *scores])
        if used and intel is not None:
            snapshot = intel.cache.snapshot_id()[:16]
            provenance = Provenance.INTEL
            evidence: tuple[Evidence, ...] = (
                Evidence(path=".", source="intel:" + "+".join(used), note=f"snapshot:{snapshot}"),
            )
        else:  # nothing cached: all we know is what the scanners said
            provenance = Provenance.TOOL
            evidence = tuple(e for n in group for e in n.evidence)
        node = Node(
            type=NodeType.ADVISORY,
            key=node_key(NodeType.ADVISORY, advisory),
            name=advisory,
            props=props,
            provenance=provenance,
            confidence=1.0,
            evidence=evidence,
        )
        nodes.append(node)
        by_purl: dict[str, list[Node]] = defaultdict(list)
        for finding in group:
            by_purl[finding.props["purl"]].append(finding)
        for purl in sorted(by_purl):
            reporters = by_purl[purl]
            edges.append(
                Edge(
                    type=EdgeType.AFFECTED_BY,
                    src=node_id(node_key(NodeType.PACKAGE, purl)),
                    dst=node.id,
                    props={
                        "reported_by": sorted({n.props["tool"] for n in reporters}),
                        "fixed_versions": sorted(
                            {v for n in reporters for v in n.props.get("fixed_versions") or []}
                        ),
                    },
                    # A scanner matched this package version against its database.
                    provenance=Provenance.TOOL,
                    confidence=max(n.confidence for n in reporters),
                    evidence=tuple(e for n in reporters for e in n.evidence),
                )
            )
    return nodes, edges
