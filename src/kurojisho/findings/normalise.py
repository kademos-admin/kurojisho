"""Raw tool findings -> Finding / Secret nodes, LOCATED_IN and DUPLICATE_OF edges."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from kurojisho.findings.locate import FunctionIndex
from kurojisho.findings.model import RawFinding
from kurojisho.findings.secrets import Scrubber, SecretHasher
from kurojisho.ingest.keys import file_id
from kurojisho.model import (
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    Provenance,
    Severity,
    node_id,
    node_key,
)

#: When tools agree on a finding, the one with the richest evidence becomes canonical.
TOOL_PRIORITY = [
    "codeql",
    "semgrep",
    "bandit",
    "gosec",
    "checkov",
    "govulncheck",
    "osv-scanner",
    "trivy",
    "grype",
    "trufflehog",
    "gitleaks",
]
_ID_RANK = (re.compile(r"^CVE-"), re.compile(r"^GHSA-"))


@dataclass
class FindingGraph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    scrubber: Scrubber = field(default_factory=Scrubber)


def _digest(*parts: object) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()


def canonical_advisory(ids: set[str]) -> str:
    """One stable id for a set of aliases: prefer CVE, then GHSA, then anything else."""
    ranked = sorted(
        ids, key=lambda i: (next((n for n, r in enumerate(_ID_RANK) if r.match(i)), 9), i)
    )
    return ranked[0] if ranked else ""


def _tool_rank(tool: str) -> int:
    return TOOL_PRIORITY.index(tool) if tool in TOOL_PRIORITY else len(TOOL_PRIORITY)


def worst(severities: list[Severity]) -> Severity:
    """Highest severity; UNKNOWN outranks MEDIUM and loses only to a known HIGH or CRITICAL."""
    return max(severities, key=lambda s: (s.rank, s is not Severity.UNKNOWN))


@dataclass
class _Item:
    raw: RawFinding
    secret_fp: str = ""
    preview: str = ""
    fingerprint: str = ""

    @property
    def instance(self) -> str:
        r = self.raw
        return _digest(
            r.tool, r.rule_id, r.path, r.start_line, r.end_line, r.purl, *r.advisory_ids,
            self.secret_fp, r.commit,
        )[:20]  # fmt: skip

    @property
    def key(self) -> str:
        return node_key(NodeType.FINDING, self.raw.tool, self.instance)


def _fingerprints(items: list[_Item]) -> None:
    """Assign the cross-tool dedupe fingerprint to every item."""
    by_purl: dict[str, list[_Item]] = defaultdict(list)
    for item in items:
        r = item.raw
        if r.category == "secret" and item.secret_fp:
            item.fingerprint = _digest("secret", item.secret_fp)
        elif r.category == "sca" and r.purl and r.advisory_ids:
            by_purl[r.purl].append(item)
        elif r.cwe:
            # TODO(M3): add the source entry point once taint paths exist.
            item.fingerprint = _digest("code", r.cwe[0], r.path, r.start_line)
        else:
            item.fingerprint = _digest("rule", r.tool, r.rule_id, r.path, r.start_line)
    for purl, group in by_purl.items():
        # Tools name the same advisory differently (CVE / GHSA / PYSEC); merge on any overlap.
        clusters: list[tuple[set[str], list[_Item]]] = []
        for item in sorted(group, key=lambda i: i.key):
            ids = set(item.raw.advisory_ids)
            merged_ids, merged_items = ids, [item]
            rest = []
            for cluster_ids, cluster_items in clusters:
                if cluster_ids & merged_ids:
                    merged_ids = merged_ids | cluster_ids
                    merged_items = cluster_items + merged_items
                else:
                    rest.append((cluster_ids, cluster_items))
            clusters = [*rest, (merged_ids, merged_items)]
        for ids, members in clusters:
            fingerprint = _digest("dep", purl, canonical_advisory(ids))
            for member in members:
                member.fingerprint = fingerprint


def build_findings(
    raws: list[RawFinding],
    *,
    hashes: dict[str, str],
    functions: FunctionIndex,
    hasher: SecretHasher,
) -> FindingGraph:
    graph = FindingGraph()
    unique: dict[str, _Item] = {}
    for raw in raws:
        item = _Item(raw)
        if raw.secret is not None:
            item.secret_fp = hasher.fingerprint(raw.secret)
            item.preview = hasher.preview(raw.secret)
            graph.scrubber.add(raw.secret, item.secret_fp)
            for other in raw.scrub_also:
                graph.scrubber.add(other, item.secret_fp)
            raw.secret, raw.scrub_also = None, ()  # raw values are not needed past this point
        unique.setdefault(item.key, item)
    items = sorted(unique.values(), key=lambda i: i.key)
    _fingerprints(items)

    groups: dict[str, list[_Item]] = defaultdict(list)
    for item in items:
        groups[item.fingerprint].append(item)
    for fingerprint in sorted(groups):
        members = sorted(groups[fingerprint], key=lambda i: (_tool_rank(i.raw.tool), i.key))
        canonical = members[0]
        group_severity = worst([m.raw.severity for m in members])
        reported_by = sorted({m.raw.tool for m in members})
        for member in members:
            node = _finding_node(member, hashes, group_severity, reported_by, member is canonical)
            graph.nodes.append(node)
            _locate(graph, member, node, hashes, functions)
            if member is not canonical:
                exact = member.raw.category in ("secret", "sca")
                graph.edges.append(
                    Edge(
                        type=EdgeType.DUPLICATE_OF,
                        src=node.id,
                        dst=node_id(canonical.key),
                        owner_file=node.owner_file,
                        props={"fingerprint": fingerprint},
                        provenance=Provenance.INFERRED,
                        confidence=1.0 if exact else 0.9,
                        evidence=node.evidence,
                    )
                )
    _secrets(graph, items, hashes)
    graph.nodes = [graph.scrubber.node(n) for n in graph.nodes]
    graph.edges = [graph.scrubber.edge(e) for e in graph.edges]
    return graph


def _evidence(item: _Item, hashes: dict[str, str]) -> tuple[Evidence, ...]:
    r = item.raw
    known = r.path is not None and r.path in hashes
    note = f"rule:{r.rule_id}"
    if not known and r.path:
        note += f" at {r.path}" + (f"@{r.commit[:12]}" if r.commit else "")
    return (
        Evidence(
            path=r.path if known and r.path else ".",
            source=f"{r.tool}@{r.tool_version}",
            start_line=r.start_line if known else None,
            end_line=r.end_line if known else None,
            content_hash=hashes.get(r.path or ""),
            note=note,
        ),
    )


def _finding_node(
    item: _Item,
    hashes: dict[str, str],
    group_severity: Severity,
    reported_by: list[str],
    canonical: bool,
) -> Node:
    r = item.raw
    known = r.path is not None and r.path in hashes
    props: dict[str, Any] = {
        "tool": r.tool,
        "tool_version": r.tool_version,
        "category": r.category,
        "rule_id": r.rule_id,
        "message": r.message,
        "cwe": list(r.cwe),
        "raw_severity": r.severity.value,
        "raw_severity_native": r.severity_native,
        # Highest severity any tool gave this issue: a duplicate can raise it, never lower it.
        "group_severity": group_severity.value,
        "final_severity": None,  # set by the triage engine
        "triage_state": "untriaged",
        "reasons": [],
        "fingerprint": item.fingerprint,
        "canonical": canonical,
        "reported_by": reported_by,
        "path": r.path,
        "span": [r.start_line, r.end_line] if r.start_line else None,
        "location": ("file" if known else "history" if r.commit else "unknown") if r.path else None,
        "imported": r.imported,
    }
    if r.category == "sca":
        props.update(
            purl=r.purl,
            advisory_ids=list(r.advisory_ids),
            fixed_versions=list(r.fixed_versions),
            cvss=r.cvss,
            tool_reachability=r.tool_reachability or None,
            symbol=r.symbol or None,
            callers=list(r.callers),
        )
    if r.category == "secret":
        props.update(
            secret_fingerprint=item.secret_fp,
            secret_type=r.secret_type or r.rule_id,
            verified_live=r.verified_live,
            commit=r.commit,
        )
    return Node(
        type=NodeType.FINDING,
        key=item.key,
        name=r.rule_id,
        owner_file=r.path if known else None,
        props=props,
        provenance=Provenance.TOOL,
        confidence=r.confidence,
        evidence=_evidence(item, hashes),
    )


def _locate(
    graph: FindingGraph, item: _Item, node: Node, hashes: dict[str, str], functions: FunctionIndex
) -> None:
    r = item.raw
    if r.path is None or r.path not in hashes:
        return
    targets = [(file_id(r.path), "file")]
    function = functions.innermost(r.path, r.start_line)
    if function is not None:
        targets.append((function, "span"))
    for dst, how in targets:
        graph.edges.append(
            Edge(
                type=EdgeType.LOCATED_IN,
                src=node.id,
                dst=dst,
                owner_file=r.path,
                props={"by": how},
                provenance=Provenance.TOOL,
                confidence=1.0,
                evidence=node.evidence,
            )
        )


def _verified(states: list[str]) -> str:
    """A secret is live if any verifier said so; dead only if one tested it and none found
    it live. A tool that did not test says nothing."""
    if "true" in states:
        return "true"
    return "false" if "false" in states else "unknown"


def _secrets(graph: FindingGraph, items: list[_Item], hashes: dict[str, str]) -> None:
    by_secret: dict[str, list[_Item]] = defaultdict(list)
    for item in items:
        if item.secret_fp:
            by_secret[item.secret_fp].append(item)
    for fingerprint in sorted(by_secret):
        members = by_secret[fingerprint]
        files = sorted({m.raw.path for m in members if m.raw.path and m.raw.path in hashes})
        entropies = [m.raw.entropy for m in members if m.raw.entropy is not None]
        evidence = tuple(e for m in members for e in _evidence(m, hashes))
        node = Node(
            type=NodeType.SECRET,
            key=node_key(NodeType.SECRET, fingerprint),
            name=sorted({m.raw.secret_type or m.raw.rule_id for m in members})[0],
            props={
                "types": sorted({m.raw.secret_type or m.raw.rule_id for m in members}),
                "fingerprint": fingerprint,
                "preview": members[0].preview,
                "location": "file" if files else "history",
                "verified_live": _verified([m.raw.verified_live for m in members]),
                "entropy": round(max(entropies), 2) if entropies else None,
                "reported_by": sorted({m.raw.tool for m in members}),
            },
            provenance=Provenance.TOOL,
            confidence=max(m.raw.confidence for m in members),
            evidence=evidence,
        )
        graph.nodes.append(node)
        for path in files:
            graph.edges.append(
                Edge(
                    type=EdgeType.LOCATED_IN,
                    src=node.id,
                    dst=file_id(path),
                    owner_file=path,
                    provenance=Provenance.TOOL,
                    confidence=1.0,
                    evidence=tuple(e for e in evidence if e.path == path) or evidence,
                )
            )
