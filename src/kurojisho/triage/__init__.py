"""Triage: decide a final severity for every finding, with reasons and evidence."""

from __future__ import annotations

from typing import Any

from kurojisho.config.context import Context
from kurojisho.model import Edge, Node, NodeType
from kurojisho.triage.assess import GraphIndex, assess
from kurojisho.triage.engine import Factor, decide, explain


def _factor(factor: Factor | None) -> dict[str, Any] | None:
    if factor is None:
        return None
    return {
        "value": factor.value,
        "provenance": factor.provenance.value,
        "confidence": round(factor.confidence, 2),
        "reason": factor.reason,
        "assumed": factor.assumed,
        "qualifies": factor.qualifies,
    }


def _vex(category: str, reach: Factor | None, rule_vex: str | None) -> dict[str, str] | None:
    """VEX status for a dependency finding. "Not affected" is a strong public claim: it is
    made only when the rule that lowered the severity survived the guards."""
    if category != "sca" or reach is None:
        return None
    if reach.value in ("R4", "R3"):
        return {"status": "affected"}
    if rule_vex and reach.qualifies:
        return {"status": "not_affected", "justification": rule_vex}
    return {"status": "under_investigation"}


def triage(nodes: list[Node], edges: list[Edge], context: Context, has_context: bool) -> list[Node]:
    """Return ``nodes`` with every Finding triaged. Nothing else is changed."""
    if not any(n.type is NodeType.FINDING for n in nodes):
        return nodes
    index = GraphIndex(nodes, edges, context, has_context)
    decided: dict[str, dict[str, Any]] = {}
    for node in nodes:
        if node.type is not NodeType.FINDING or node.id in index.duplicate_of:
            continue
        assessment = assess(index, node)
        inputs = assessment.inputs
        decision = decide(inputs)
        update = explain(decision)
        update.update(
            reach=_factor(inputs.reach),
            exploit=_factor(inputs.exploit),
            impact=_factor(inputs.impact),
            entry_points=[e.split(":", 1)[1] for e in assessment.entry_points[:5]],
            asset=assessment.asset,
            exposure=assessment.exposure,
            auth_applied=any(r.startswith("AUTH-") for r in decision.reasons),
            fix=decision.fix,
            vex=_vex(inputs.category, inputs.reach, decision.vex),
        )
        decided[node.id] = update
    out = []
    for node in nodes:
        if node.type is not NodeType.FINDING:
            out.append(node)
            continue
        canonical = index.duplicate_of.get(node.id, node.id)
        result = decided.get(canonical)
        if result is None:  # a duplicate whose canonical finding is missing: leave as is
            out.append(node)
            continue
        if canonical != node.id:
            result = {**result, "triage_state": "duplicate"}
        out.append(node.model_copy(update={"props": {**node.props, **result}}))
    return out
