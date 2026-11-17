"""The triage decision: floors, the matrix, the authentication step, then the guards.

Everything severity-related is data in ``rules.yaml``. The engine adds only what cannot be
expressed there: the two guards, which hold whatever the rules say.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from functools import cache
from importlib import resources
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from ruamel.yaml import YAML

from kurojisho.model import Provenance, Severity
from kurojisho.model.enums import SEVERITY_ORDER
from kurojisho.triage.expr import Node, RuleSyntaxError, evaluate, parse

FACTS = frozenset(
    {
        "category",
        "reach",
        "exploit",
        "impact",
        "secret.verified_live",
        "location",
        "test_fixture_evidence",
        "advisory.kev",
        "sanitizer.strong_all_paths",
        "auth.all_entry_points_authenticated",
        "ai.untrusted_reaches_dangerous_tool",
        "ai.human_approval",
    }
)
REQUIRED_GUARDS = ("GUARD-01", "GUARD-02")
QUALIFYING_CONFIDENCE = 0.8
_QUALIFYING = {Provenance.EXTRACTED, Provenance.TOOL, Provenance.INTEL, Provenance.ASSERTED}


class RulesError(ValueError):
    """The rules file is unusable. Nothing is triaged with a broken rule set."""


def qualifies(provenance: Provenance, confidence: float) -> bool:
    """May this evidence lower a severity? (GUARD-02)"""
    if provenance in _QUALIFYING:
        return True
    return provenance is Provenance.INFERRED and confidence >= QUALIFYING_CONFIDENCE


@dataclass(frozen=True)
class Factor:
    """One input to a decision, with where it came from."""

    value: str
    provenance: Provenance
    confidence: float
    reason: str = ""
    #: True when the value is a stand-in for something we do not know.
    assumed: bool = False

    @property
    def qualifies(self) -> bool:
        return not self.assumed and qualifies(self.provenance, self.confidence)


UNKNOWN_AUTH = Factor("unknown", Provenance.INFERRED, 0.0)


@dataclass(frozen=True)
class Inputs:
    category: str  # sast | sca | secret | iac
    raw: Severity
    reach: Factor | None = None
    exploit: Factor | None = None
    impact: Factor | None = None
    #: "true" only when every reaching entry point requires authentication
    auth: Factor = UNKNOWN_AUTH
    #: "true" when a strong sanitizer covers the weakness on every path
    sanitizer: Factor = UNKNOWN_AUTH
    cwe: tuple[str, ...] = ()
    verified_live: str = "unknown"
    location: str = "unknown"
    test_fixture: bool = False
    kev: str = "unknown"

    def facts(self) -> dict[str, object]:
        return {
            "category": self.category,
            "reach": self.reach.value if self.reach else "none",
            "exploit": self.exploit.value if self.exploit else "none",
            "impact": self.impact.value if self.impact else "none",
            "secret.verified_live": self.verified_live,
            "location": self.location,
            "test_fixture_evidence": self.test_fixture,
            "advisory.kev": self.kev,
            "sanitizer.strong_all_paths": self.sanitizer.value == "true"
            and self.sanitizer.qualifies,
            "auth.all_entry_points_authenticated": self.auth.value == "true"
            and self.auth.qualifies,
            "ai.untrusted_reaches_dangerous_tool": False,
            "ai.human_approval": "unknown",
        }


@dataclass
class Decision:
    severity: Severity
    rule: str | None = None
    state: str = "triaged"
    reasons: list[str] = field(default_factory=list)
    guards: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    fix: str | None = None
    vex: str | None = None


# -- rule file --------------------------------------------------------------------------
class _Then(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity | None = None
    state: str | None = None
    reason: str = ""
    fix: str | None = None
    flag: str | None = None
    action: str | None = None
    vex: str | None = None
    map: list[str] = Field(default_factory=list)
    requires_evidence: bool = False
    reviewer_ack: bool = False


class _Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["floor", "matrix", "state"]
    applies_to: list[str]
    when: str
    then: _Then


class _Adjustment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    applies_to: list[str]
    when: str
    lower_by: Literal[1]  # never more than one step (spec 7.2)
    unless_cwe: list[str] = Field(default_factory=list)
    reason: str = ""


class _Guard(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    rule: str


class _File(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    rules: list[_Rule]
    adjustments: list[_Adjustment] = Field(default_factory=list)
    guards: list[_Guard]


@dataclass(frozen=True)
class RuleSet:
    rules: tuple[tuple[_Rule, Node], ...]
    adjustments: tuple[tuple[_Adjustment, Node], ...]
    guards: dict[str, str]

    @property
    def ids(self) -> list[str]:
        return (
            [r.id for r, _ in self.rules] + [a.id for a, _ in self.adjustments] + list(self.guards)
        )


def parse_rules(text: str) -> RuleSet:
    try:
        data = _File.model_validate(YAML(typ="safe").load(text))
        rules = tuple((r, parse(r.when, FACTS)) for r in data.rules)
        adjustments = tuple((a, parse(a.when, FACTS)) for a in data.adjustments)
    except RuleSyntaxError as exc:
        raise RulesError(str(exc)) from exc
    except Exception as exc:  # YAML and schema errors alike: the file is unusable
        raise RulesError(f"invalid rules file: {exc}") from exc
    for rule, _ in rules:
        if rule.kind == "state" and (rule.then.state is None or rule.then.severity is not None):
            raise RulesError(f"{rule.id}: a state rule sets a state and no severity")
        if rule.kind != "state" and rule.then.severity is None:
            raise RulesError(f"{rule.id}: a {rule.kind} rule must set a severity")
        if rule.then.severity is Severity.UNKNOWN:
            raise RulesError(f"{rule.id}: a rule cannot assign Unknown")
    ids = [r.id for r, _ in rules] + [a.id for a, _ in adjustments]
    if len(set(ids)) != len(ids):
        raise RulesError("duplicate rule id")
    guards = {g.id: g.rule for g in data.guards}
    missing = [g for g in REQUIRED_GUARDS if g not in guards]
    if missing:
        raise RulesError(f"rules file must declare {', '.join(missing)}")
    return RuleSet(rules, adjustments, guards)


@cache
def load_rules() -> RuleSet:
    text = resources.files("kurojisho.triage").joinpath("rules.yaml").read_text("utf-8")
    return parse_rules(text)


# -- decision ---------------------------------------------------------------------------
def _lower(severity: Severity, steps: int) -> Severity:
    index = SEVERITY_ORDER.index(severity.value)
    return Severity(SEVERITY_ORDER[max(0, index - steps)])


def _matrix(rules: RuleSet, inputs: Inputs) -> tuple[Severity | None, _Rule | None, list[str]]:
    """First matching matrix rule, then the authentication step. No guards here."""
    facts = inputs.facts()
    for rule, condition in rules.rules:
        if rule.kind != "matrix" or inputs.category not in rule.applies_to:
            continue
        if not evaluate(condition, facts):
            continue
        severity = rule.then.severity
        assert severity is not None  # checked when the rules were loaded
        notes = [f"{rule.id}: {rule.then.reason}"]
        for adjustment, when in rules.adjustments:
            if inputs.category not in adjustment.applies_to or not evaluate(when, facts):
                continue
            if set(inputs.cwe) & set(adjustment.unless_cwe):
                continue
            severity = _lower(severity, adjustment.lower_by)
            notes.append(f"{adjustment.id}: {adjustment.reason}")
            break  # one step at most, whatever the file lists
        return severity, rule, notes
    return None, None, []


def _worst_case(inputs: Inputs) -> list[Inputs]:
    """The same finding with every piece of non-qualifying evidence taken away."""
    exploit = inputs.exploit
    if exploit is not None and not exploit.qualifies:
        exploit = replace(exploit, value="E3")
    impact = inputs.impact
    if impact is not None and not impact.qualifies:
        impact = replace(impact, value="I3")
    base = replace(inputs, exploit=exploit, impact=impact)
    if inputs.reach is None or inputs.reach.qualifies:
        return [base]
    # Without the reach evidence we would know nothing: either it is reachable or unknown.
    return [replace(base, reach=replace(inputs.reach, value=v)) for v in ("R4", "R0")]


def decide(inputs: Inputs, rules: RuleSet | None = None) -> Decision:
    rules = rules or load_rules()
    raw = inputs.raw
    facts = inputs.facts()
    decision: Decision | None = None

    for rule, condition in rules.rules:
        applies = rule.kind == "floor" and inputs.category in rule.applies_to
        if applies and evaluate(condition, facts):
            assert rule.then.severity is not None
            decision = Decision(
                rule.then.severity,
                rule.id,
                reasons=[f"{rule.id}: {rule.then.reason}"],
                fix=rule.then.fix,
            )
            break

    if decision is None:
        severity, rule_, notes = _matrix(rules, inputs)
        if severity is None or rule_ is None:
            decision = Decision(
                raw,
                None,
                state="unmatched",
                reasons=["No triage rule covers this finding; the tool's severity is kept"],
                flags=["no_rule_matched"],
            )
        else:
            decision = Decision(severity, rule_.id, reasons=notes, vex=rule_.then.vex)
            if rule_.then.flag == "needs_manual_review_if_R0":
                if inputs.reach is not None and inputs.reach.value == "R0":
                    decision.flags.append("needs_manual_review")
            elif rule_.then.flag:
                decision.flags.append(rule_.then.flag)
            if severity.rank < raw.rank:
                reach = inputs.reach.value if inputs.reach else ""
                if reach == "R0":
                    decision.severity = raw
                    decision.guards.append("GUARD-01")
                    decision.reasons.append(
                        "GUARD-01: reachability is unknown, so the tool's severity is kept"
                    )
                else:
                    # What would the rules say without the evidence that may not lower?
                    bound = Severity.INFO
                    for variant in _worst_case(inputs):
                        outcome, _, _ = _matrix(rules, variant)
                        unknown = variant.reach is not None and variant.reach.value == "R0"
                        # GUARD-01 holds inside the what-if too: unknown reach keeps raw.
                        if outcome is None or (unknown and outcome.rank < raw.rank):
                            outcome = raw
                        if outcome.rank > bound.rank:
                            bound = outcome
                    allowed = bound if bound.rank < raw.rank else raw
                    if allowed.rank > severity.rank:
                        decision.severity = allowed
                        decision.guards.append("GUARD-02")
                        decision.reasons.append(
                            "GUARD-02: the evidence for a lower severity is inferred with "
                            "low confidence or assumed, so it is not applied"
                        )
                        decision.vex = None

    for rule, condition in rules.rules:
        applies = rule.kind == "state" and inputs.category in rule.applies_to
        if applies and rule.then.state and evaluate(condition, facts):
            decision.state = rule.then.state
            decision.reasons.append(f"{rule.id}: {rule.then.reason}")
            if rule.then.reviewer_ack:
                decision.flags.append("needs_reviewer_ack")
    return decision


def explain(decision: Decision) -> dict[str, Any]:
    return {
        "final_severity": decision.severity.value,
        "triage_state": decision.state,
        "triage_rule": decision.rule,
        "reasons": decision.reasons,
        "guards": decision.guards,
        "flags": sorted(set(decision.flags)),
    }
