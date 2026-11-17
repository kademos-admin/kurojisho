"""Remediation nodes and FIXED_BY edges. Fix text comes from ``templates.yaml`` only."""

from __future__ import annotations

import re
from collections import defaultdict
from functools import cache
from importlib import resources
from typing import Any

from ruamel.yaml import YAML

from kurojisho.model import Edge, EdgeType, Evidence, Node, NodeType, Provenance, node_key

SOURCE = "remediation-template"
_NUMBER = re.compile(r"\d+")


@cache
def templates() -> dict[str, Any]:
    text = resources.files("kurojisho.remediate").joinpath("templates.yaml").read_text("utf-8")
    data: dict[str, Any] = YAML(typ="safe").load(text)
    return data


def version_key(version: str) -> tuple[int, ...] | None:
    """Leading numeric components of a version; None when there are none to compare."""
    core = re.split(r"[-+~]", version.strip().lstrip("vV"), maxsplit=1)[0]
    parts = tuple(int(n) for n in _NUMBER.findall(core)[:4])
    return parts or None


def pick_fix(current: str | None, fixed: list[str]) -> str | None:
    """The smallest published fix above the installed version."""
    have = version_key(current or "")
    candidates = [(version_key(v), v) for v in fixed]
    usable = sorted((k, v) for k, v in candidates if k is not None and (have is None or k > have))
    if usable:
        return usable[0][1]
    # Nothing comparable: offer what the advisory lists rather than nothing.
    return sorted(fixed)[0] if fixed and have is None else None


def breaking_risk(current: str | None, target: str | None) -> str:
    """From the size of the version jump. ``unknown`` whenever it cannot be read."""
    have, want = version_key(current or ""), version_key(target or "")
    if have is None or want is None:
        return "unknown"
    have, want = (*have, 0, 0, 0)[:3], (*want, 0, 0, 0)[:3]
    if want[0] != have[0]:
        return "high"
    if want[1] != have[1]:
        return "high" if have[0] == 0 else "medium"  # 0.x minors may break
    return "low"


def _purl_version(purl: str) -> str | None:
    return purl.rpartition("@")[2] if "@" in purl else None


def _template_for(cwes: list[str]) -> dict[str, Any]:
    data = templates()
    for template in data["code_patch"]:
        if set(template["cwe"]) & set(cwes):
            template_: dict[str, Any] = template
            return template_
    fallback: dict[str, Any] = data["default_code_patch"]
    return fallback


def build_remediations(nodes: list[Node]) -> tuple[list[Node], list[Edge]]:
    data = templates()
    out: dict[str, Node] = {}
    edges: list[Edge] = []
    packages: dict[str, list[Node]] = defaultdict(list)

    def template_node(
        kind: str, subject: str, template: dict[str, Any], extra: dict[str, Any]
    ) -> Node:
        key = node_key(NodeType.REMEDIATION, kind, subject)
        if key not in out:
            out[key] = Node(
                type=NodeType.REMEDIATION,
                key=key,
                name=template["title"],
                props={
                    "type": kind,
                    "title": template["title"],
                    "guidance": " ".join(str(template["guidance"]).split()),
                    "diff": None,  # templates describe the change; they do not write it
                    "fixed_version": None,
                    "breaking_risk": None,
                    "verify_steps": list(template["verify_steps"]),
                    **extra,
                },
                # Advice chosen by weakness class, not a fact about this code.
                provenance=Provenance.INFERRED,
                confidence=0.7,
                evidence=(Evidence(path=".", source=SOURCE, note=str(template.get("id", kind))),),
            )
        return out[key]

    def fixed_by(finding: Node, remedy: Node) -> None:
        edges.append(
            Edge(
                type=EdgeType.FIXED_BY,
                src=finding.id,
                dst=remedy.id,
                owner_file=finding.owner_file,
                provenance=remedy.provenance,
                confidence=remedy.confidence,
                evidence=finding.evidence,
            )
        )

    findings = [
        n
        for n in nodes
        if n.type is NodeType.FINDING
        and n.props.get("triage_state") not in (None, "duplicate", "untriaged")
    ]
    for finding in findings:
        props = finding.props
        category = props["category"]
        if category == "sca" and props.get("purl"):
            packages[props["purl"]].append(finding)
        elif category == "secret":
            fixed_by(
                finding, template_node("rotate", "rotate_then_purge_history", data["rotate"], {})
            )
        elif category == "iac":
            subject = f"{props['tool']}::{props['rule_id']}"
            fixed_by(
                finding,
                template_node("config", subject, data["config"], {"rule_id": props["rule_id"]}),
            )
        else:
            template = _template_for(props.get("cwe") or [])
            fixed_by(
                finding,
                template_node(
                    "code_patch", template["id"], template, {"cwe": template.get("cwe", [])}
                ),
            )

    for purl in sorted(packages):
        group = packages[purl]
        current = _purl_version(purl)
        # One upgrade must clear every advisory on the package: take the highest of the
        # per-advisory minimum fixes.
        targets = [pick_fix(current, f.props.get("fixed_versions") or []) for f in group]
        unfixed = [f.name for f, t in zip(group, targets, strict=True) if t is None]
        known = sorted((version_key(t) or (), t) for t in targets if t is not None)
        target = known[-1][1] if known else None
        name = purl.removeprefix("pkg:").rpartition("@")[0]
        if target is None:
            extra = {"purl": purl, "unfixed_advisories": sorted(unfixed)}
            node = template_node("compensating", purl, data["no_fix"], extra)
        else:
            key = node_key(NodeType.REMEDIATION, "upgrade", purl)
            node = Node(
                type=NodeType.REMEDIATION,
                key=key,
                name=f"Upgrade {name} to {target}",
                props={
                    "type": "upgrade",
                    "title": f"Upgrade {name} to {target}",
                    "guidance": (
                        f"Upgrade {name} from {current or 'the installed version'} "
                        f"to {target} or later."
                    ),
                    "diff": None,
                    "purl": purl,
                    "fixed_version": target,
                    "breaking_risk": breaking_risk(current, target),
                    # Advisories on this package that this upgrade does not fix.
                    "unfixed_advisories": sorted(unfixed),
                    "verify_steps": list(data["upgrade"]["verify_steps"]),
                },
                # The fixed version is what the scanners' advisory data says.
                provenance=Provenance.TOOL,
                confidence=max(f.confidence for f in group),
                evidence=tuple(e for f in group for e in f.evidence)[:25],
            )
            out[key] = node
        for finding in group:
            fixed_by(finding, node)
    return [out[k] for k in sorted(out)], edges
