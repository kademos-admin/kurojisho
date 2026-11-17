"""M3-AC1: one golden case (and its near misses) per rule ID, plus the rule language."""

from __future__ import annotations

from dataclasses import replace
from importlib import resources

import pytest
from syrupy.assertion import SnapshotAssertion

from kurojisho.model import Provenance, Severity
from kurojisho.triage.engine import (
    FACTS,
    Factor,
    Inputs,
    RulesError,
    decide,
    load_rules,
    parse_rules,
)
from kurojisho.triage.expr import RuleSyntaxError, evaluate, parse

S = Severity


def tool(value: str) -> Factor:
    return Factor(value, Provenance.TOOL, 0.9)


def guess(value: str, confidence: float = 0.5) -> Factor:
    return Factor(value, Provenance.INFERRED, confidence)


def finding(
    reach: str,
    exploit: str,
    impact: str,
    raw: Severity = S.MEDIUM,
    category: str = "sast",
    **kw: object,
) -> Inputs:
    return Inputs(category, raw, tool(reach), tool(exploit), tool(impact), **kw)  # type: ignore[arg-type]


def secret(live: str, location: str = "src", **kw: object) -> Inputs:
    return Inputs("secret", S.UNKNOWN, verified_live=live, location=location, **kw)  # type: ignore[arg-type]


def result(inputs: Inputs) -> tuple[str, str | None]:
    decision = decide(inputs)
    return decision.severity.value, decision.rule


# -- floors -----------------------------------------------------------------------------
def test_sec_01_live_credential_is_critical_wherever_it_is() -> None:
    for location in ("src", "ci_config", "history"):
        decision = decide(secret("true", location, test_fixture=True))
        assert (decision.severity, decision.rule) == (S.CRITICAL, "SEC-01")
        assert decision.fix == "rotate_then_purge_history" and decision.guards == []


def test_sec_02_unverified_secret_in_source_is_high() -> None:
    assert result(secret("unknown", "src")) == ("High", "SEC-02")
    assert result(secret("unknown", "ci_config")) == ("High", "SEC-02")
    # Near misses fall through to "no rule": the tool's Unknown is kept, never lowered.
    for miss in (
        secret("unknown", "history"),
        secret("unknown", "src", test_fixture=True),
        secret("false", "src"),
    ):
        decision = decide(miss)
        assert (decision.severity, decision.rule, decision.state) == (S.UNKNOWN, None, "unmatched")
        assert decision.flags == ["no_rule_matched"]


def test_exp_01_known_exploited_is_critical_unless_proven_unreachable() -> None:
    for reach in ("R4", "R3", "R0"):
        hit = finding(reach, "E3", "I0", S.LOW, "sca", kev="true")
        assert result(hit) == ("Critical", "EXP-01")
    assert result(finding("R2", "E3", "I3", S.LOW, "sca", kev="true")) == ("Low", "TRI-05")
    assert result(finding("R1", "E3", "I3", S.INFO, "sca", kev="true")) == ("Info", "TRI-06")
    # KEV membership unknown is not "true": the floor does not fire, the matrix still does.
    assert result(finding("R4", "E3", "I3", S.LOW, "sca", kev="unknown")) == ("Critical", "TRI-01")
    # A floor is never lowered, not even by authentication on every entry point.
    authed = finding("R4", "E3", "I0", S.LOW, "sca", kev="true", auth=tool("true"))
    assert result(authed) == ("Critical", "EXP-01")


def test_ai_01_is_declared_but_cannot_fire_before_milestone_4() -> None:
    assert "AI-01" in load_rules().ids
    assert all(
        decide(finding("R4", "E3", "I3", category=c)).rule != "AI-01" for c in ("sast", "sca")
    )


# -- matrix -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("reach", "exploit", "impact", "want"),
    [
        ("R4", "E2", "I2", ("Critical", "TRI-01")),
        ("R4", "E3", "I3", ("Critical", "TRI-01")),
        ("R4", "E2", "I1", ("High", "TRI-02")),  # exploitable, low impact
        ("R4", "E1", "I0", ("High", "TRI-02")),
        ("R4", "E0", "I2", ("High", "TRI-02")),  # not exploitable today, high impact
        ("R4", "E1", "I3", ("High", "TRI-02")),
        ("R3", "E3", "I2", ("High", "TRI-03")),
        ("R0", "E0", "I3", ("High", "TRI-03")),
        ("R3", "E3", "I1", ("Medium", "TRI-04")),
        ("R4", "E0", "I1", ("Medium", "TRI-04")),
        ("R4", "E0", "I0", ("Medium", "TRI-04")),
        ("R2", "E3", "I3", ("Low", "TRI-05")),
        ("R1", "E3", "I3", ("Info", "TRI-06")),
    ],
)
def test_matrix_rules_first_match_wins(
    reach: str, exploit: str, impact: str, want: tuple[str, str]
) -> None:
    # Raw Info, so no guard is in play: this is the matrix alone.
    assert result(finding(reach, exploit, impact, S.INFO)) == want
    assert result(finding(reach, exploit, impact, S.INFO, "sca")) == want


def test_tri_03_flags_manual_review_only_for_unknown_reach() -> None:
    assert decide(finding("R0", "E1", "I2")).flags == ["needs_manual_review"]
    assert decide(finding("R3", "E1", "I2")).flags == []


def test_tri_05_and_06_carry_their_vex_justification() -> None:
    assert (
        decide(finding("R2", "E1", "I1", S.LOW, "sca")).vex == "vulnerable_code_not_in_execute_path"
    )
    assert decide(finding("R1", "E1", "I1", S.INFO, "sca")).vex == "component_not_present"


def test_tri_07_sets_a_state_and_leaves_severity_alone() -> None:
    plain = decide(finding("R4", "E0", "I2", S.HIGH))
    covered = decide(
        finding("R4", "E0", "I2", S.HIGH, sanitizer=Factor("true", Provenance.INFERRED, 0.9))
    )
    assert plain.state == "triaged" and covered.state == "false_positive_candidate"
    assert covered.severity == plain.severity == S.HIGH
    assert "needs_reviewer_ack" in covered.flags and covered.reasons[-1].startswith("TRI-07")
    # A sanitizer matched by name only (0.5) is not evidence.
    weak = decide(finding("R4", "E0", "I2", S.HIGH, sanitizer=guess("true")))
    assert weak.state == "triaged"


def test_no_matrix_rule_for_unknown_reach_with_low_impact_keeps_the_raw_severity() -> None:
    decision = decide(finding("R0", "E3", "I1", S.HIGH))
    assert (decision.severity, decision.rule, decision.state) == (S.HIGH, None, "unmatched")
    assert decide(Inputs("iac", S.MEDIUM)).severity == S.MEDIUM


# -- authentication ---------------------------------------------------------------------
def test_auth_lowers_by_exactly_one_step_and_only_with_evidence() -> None:
    base = finding("R4", "E2", "I2", S.INFO)
    assert result(base) == ("Critical", "TRI-01")
    assert result(replace(base, auth=tool("true"))) == ("High", "TRI-01")
    assert result(replace(base, auth=guess("true"))) == ("Critical", "TRI-01")  # name match only
    assert result(replace(base, auth=tool("unknown"))) == ("Critical", "TRI-01")
    assert result(replace(base, auth=tool("false"))) == ("Critical", "TRI-01")
    lowered = decide(replace(base, auth=tool("true")))
    assert lowered.reasons[1].startswith("AUTH-01")


@pytest.mark.parametrize("cwe", ["CWE-639", "CWE-862", "CWE-863", "CWE-306"])
def test_auth_never_lowers_access_control_weaknesses(cwe: str) -> None:
    assert result(finding("R4", "E2", "I2", S.INFO, auth=tool("true"), cwe=(cwe,))) == (
        "Critical",
        "TRI-01",
    )


# -- guards -----------------------------------------------------------------------------
def test_guard_01_unknown_reach_never_goes_below_the_raw_severity() -> None:
    authed = finding("R0", "E0", "I2", S.HIGH, auth=tool("true"))  # TRI-03 High, auth -> Medium
    decision = decide(authed)
    assert (decision.severity, decision.guards) == (S.HIGH, ["GUARD-01"])
    critical = decide(finding("R0", "E0", "I2", S.CRITICAL))
    assert (critical.severity, critical.guards) == (S.CRITICAL, ["GUARD-01"])
    unknown = decide(finding("R0", "E0", "I2", S.UNKNOWN, auth=tool("true")))
    assert unknown.severity == S.UNKNOWN  # ranks with High; not lowered to Medium


def test_guard_02_low_confidence_inference_cannot_lower() -> None:
    proven = Inputs("sca", S.HIGH, tool("R1"), tool("E2"), tool("I2"))
    assert decide(proven).severity == S.INFO and decide(proven).guards == []
    for weak in (
        guess("R1", 0.5),
        guess("R1", 0.79),
        Factor("R1", Provenance.LLM_SUGGESTED, 1.0),
        Factor("R1", Provenance.EXTRACTED, 1.0, assumed=True),
    ):
        decision = decide(replace(proven, reach=weak))
        assert (decision.severity, decision.guards) == (S.HIGH, ["GUARD-02"]), weak
        assert decision.vex is None  # no "not affected" claim without the evidence
    assert decide(replace(proven, reach=guess("R1", 0.8))).severity == S.INFO


def test_guard_02_applies_to_each_factor_and_allows_what_the_proof_supports() -> None:
    # R4 / E0 / I1 -> Medium. Take the low-impact claim away and it is High (TRI-02).
    claim = Inputs("sast", S.HIGH, tool("R4"), tool("E0"), guess("I1"))
    assert (decide(claim).severity, decide(claim).guards) == (S.HIGH, ["GUARD-02"])
    # Assumed impact (no context file) is never used to lower either.
    assumed = replace(claim, impact=Factor("I1", Provenance.ASSERTED, 1.0, assumed=True))
    assert decide(assumed).severity == S.HIGH
    # Raw Critical; proven R3 / I1 gives Medium whatever the exploit level is, so the
    # unproven E0 changes nothing and the lowering stands.
    harmless = Inputs("sast", S.CRITICAL, tool("R3"), guess("E0"), tool("I1"))
    assert (decide(harmless).severity, decide(harmless).guards) == (S.MEDIUM, [])
    # Partly supported: without the weak E0 the proof gives High, not the raw Critical.
    partial = Inputs("sast", S.CRITICAL, tool("R4"), guess("E0"), tool("I0"))
    assert (decide(partial).severity, decide(partial).guards) == (S.HIGH, ["GUARD-02"])


def test_unproven_reach_cannot_lower_even_with_proven_auth_and_impact() -> None:
    """Regression (found by the property tests): with reach unproven, the what-if case
    "reach is really unknown" must itself obey GUARD-01, or proven authentication could
    pull a Critical down to Medium."""
    case = Inputs(
        "sast", S.CRITICAL, Factor("R1", Provenance.EXTRACTED, 1.0, assumed=True),
        tool("E0"), guess("I0"), auth=tool("true"),
    )  # fmt: skip
    decision = decide(case)
    assert (decision.severity, decision.guards) == (S.CRITICAL, ["GUARD-02"])
    for reach in ("R1", "R2", "R3", "R4"):
        for impact in (tool("I0"), guess("I0"), tool("I3")):
            weak = replace(case, reach=guess(reach), impact=impact)
            assert decide(weak).severity.rank >= S.CRITICAL.rank or reach == "R4"


def test_decision_table_golden(snapshot: SnapshotAssertion) -> None:
    """Every combination of the matrix inputs, as a readable table."""
    lines = []
    for raw in (S.CRITICAL, S.HIGH, S.MEDIUM, S.LOW, S.UNKNOWN):
        for reach in ("R0", "R1", "R2", "R3", "R4"):
            for exploit in ("E0", "E1", "E2", "E3"):
                for impact in ("I0", "I1", "I2", "I3"):
                    for label, make in (("proven", tool), ("guessed", guess)):
                        d = decide(Inputs("sast", raw, make(reach), make(exploit), make(impact)))
                        guards = ",".join(d.guards) or "-"
                        lines.append(
                            f"{raw.value:8} {reach} {exploit} {impact} {label:7} -> "
                            f"{d.severity.value:8} {d.rule or '-':6} {guards}"
                        )
    assert "\n".join(lines) == snapshot


# -- rule file and language -------------------------------------------------------------
def test_shipped_rules_have_every_spec_rule_in_spec_order() -> None:
    assert load_rules().ids == [
        "SEC-01", "SEC-02", "EXP-01", "AI-01", "TRI-01", "TRI-02", "TRI-03", "TRI-04", "TRI-05",
        "TRI-06", "TRI-07", "AUTH-01", "GUARD-01", "GUARD-02",
    ]  # fmt: skip


def shipped() -> str:
    return resources.files("kurojisho.triage").joinpath("rules.yaml").read_text("utf-8")


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("  - id: GUARD-01\n", "  - id: GUARD-09\n"),  # guards cannot be dropped
        ("lower_by: 1", "lower_by: 2"),  # auth never lowers by more than one
        ("reach == R4 and exploit >= E2", "reech == R4 and exploit >= E2"),  # unknown fact
        ("exploit >= E2 and impact >= I2", "exploit >= high and impact >= I2"),
        (
            'then: {severity: Critical, reason: "Live credential"',
            'then: {reason: "Live credential"',
        ),
        ("  - id: TRI-02\n", "  - id: TRI-01\n"),  # duplicate id
        ("version: 1", "version: 2"),
        ("kind: state", "kind: matrix"),
    ],
)
def test_broken_rule_files_are_rejected_whole(old: str, new: str) -> None:
    text = shipped()
    assert old in text
    with pytest.raises(RulesError):
        parse_rules(text.replace(old, new, 1))


def test_rules_are_data_changing_the_file_changes_the_outcome() -> None:
    edited = parse_rules(
        shipped().replace(
            'then: {severity: Critical, reason: "Reachable',
            'then: {severity: Medium, reason: "Reachable',
        )
    )
    assert decide(finding("R4", "E2", "I2", S.INFO), edited).severity == S.MEDIUM


def test_expression_language() -> None:
    facts = {"reach": "R4", "exploit": "E2", "impact": None, "test_fixture_evidence": False,
             "location": "src", "secret.verified_live": "unknown"}  # fmt: skip
    names = frozenset(facts)

    def check(text: str) -> bool:
        return evaluate(parse(text, names), facts)

    assert check("reach == R4 and (exploit >= E3 or exploit > E1)")
    assert check("not test_fixture_evidence and location in [src, ci_config]")
    assert check("secret.verified_live == unknown and impact == unknown")
    assert not check("impact >= I0") and not check("impact <= I3")  # unknown has no order
    assert not check("exploit >= I0")  # different scales never compare
    assert check("reach != R3") and not check("reach in [R3, R0]")
    assert check("not (reach == R3 or reach == R0) and exploit <= E2 and exploit < E3")
    assert not check("test_fixture_evidence")
    for bad in ("reach ==", "reach = R4", "reach == R4 and", "(reach == R4", "reach in R4",
                "reach in [R4", "bogus == 1", "reach == R4 extra", "reach == 'R4'", "and", "",
                "__import__ == x", "reach >= high"):  # fmt: skip
        with pytest.raises(RuleSyntaxError):
            parse(bad, names)
    assert {"reach", "exploit", "impact"} <= FACTS
