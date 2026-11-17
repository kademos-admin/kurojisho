"""M3-AC2: properties the engine must hold for every input, whatever the rules say."""

from __future__ import annotations

from dataclasses import replace

from hypothesis import given, settings
from hypothesis import strategies as st

from kurojisho.model import Provenance, Severity
from kurojisho.triage.engine import Factor, Inputs, decide, qualifies

severities = st.sampled_from(list(Severity))
provenances = st.sampled_from(list(Provenance))
confidences = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)


def factors(values: list[str]) -> st.SearchStrategy[Factor]:
    return st.builds(
        Factor,
        value=st.sampled_from(values),
        provenance=provenances,
        confidence=confidences,
        assumed=st.booleans(),
    )


reaches = factors(["R0", "R1", "R2", "R3", "R4"])
exploits = factors(["E0", "E1", "E2", "E3"])
impacts = factors(["I0", "I1", "I2", "I3"])
truth = factors(["true", "false", "unknown"])
cwes = st.lists(st.sampled_from(["CWE-89", "CWE-78", "CWE-862", "CWE-639"]), max_size=2).map(tuple)

code = st.builds(
    Inputs,
    category=st.sampled_from(["sast", "sca"]),
    raw=severities,
    reach=reaches,
    exploit=exploits,
    impact=impacts,
    auth=truth,
    sanitizer=truth,
    cwe=cwes,
    kev=st.sampled_from(["true", "false", "unknown"]),
)
secrets = st.builds(
    Inputs,
    category=st.just("secret"),
    raw=severities,
    verified_live=st.sampled_from(["true", "false", "unknown"]),
    location=st.sampled_from(["src", "ci_config", "history", "unknown"]),
    test_fixture=st.booleans(),
)
anything = st.one_of(code, secrets, st.builds(Inputs, category=st.just("iac"), raw=severities))


def weak(factor: Factor) -> Factor:
    """The same claim, resting on evidence that may not lower a severity."""
    return replace(factor, provenance=Provenance.INFERRED, confidence=min(factor.confidence, 0.79))


@settings(max_examples=2000)
@given(code)
def test_unknown_reach_never_lowers_below_raw(inputs: Inputs) -> None:
    assert inputs.reach is not None
    unknown = replace(inputs, reach=replace(inputs.reach, value="R0"))
    assert decide(unknown).severity.rank >= unknown.raw.rank


@settings(max_examples=2000)
@given(code, st.sampled_from([Provenance.INFERRED, Provenance.LLM_SUGGESTED]))
def test_low_confidence_or_llm_evidence_never_lowers_below_raw(
    inputs: Inputs, provenance: Provenance
) -> None:
    def demote(factor: Factor | None) -> Factor:
        assert factor is not None
        confidence = factor.confidence if provenance is Provenance.LLM_SUGGESTED else 0.79
        return replace(factor, provenance=provenance, confidence=min(factor.confidence, confidence))

    weakened = replace(
        inputs,
        reach=demote(inputs.reach),
        exploit=demote(inputs.exploit),
        impact=demote(inputs.impact),
        auth=demote(inputs.auth),
        sanitizer=demote(inputs.sanitizer),
    )
    assert decide(weakened).severity.rank >= weakened.raw.rank


@settings(max_examples=2000)
@given(code, st.sampled_from(["reach", "exploit", "impact"]))
def test_weakening_one_piece_of_evidence_never_lowers_the_result(inputs: Inputs, name: str) -> None:
    """Taking qualifying evidence away can only keep or raise the severity."""
    before = decide(inputs).severity.rank
    after = decide(replace(inputs, **{name: weak(getattr(inputs, name))})).severity.rank
    assert after >= min(before, inputs.raw.rank)


@settings(max_examples=2000)
@given(code)
def test_unproven_reach_never_lowers_below_raw(inputs: Inputs) -> None:
    """R1/R2/R3 are claims that something is less reachable; unproven, they change nothing."""
    assert inputs.reach is not None
    if inputs.reach.value == "R4":
        return
    unproven = replace(inputs, reach=weak(inputs.reach))
    assert decide(unproven).severity.rank >= unproven.raw.rank


@settings(max_examples=2000)
@given(code)
def test_authentication_lowers_by_at_most_one_step(inputs: Inputs) -> None:
    without = decide(replace(inputs, auth=Factor("unknown", Provenance.TOOL, 1.0)))
    with_auth = decide(replace(inputs, auth=Factor("true", Provenance.TOOL, 1.0)))
    assert without.severity.rank - with_auth.severity.rank in (0, 1)
    if set(inputs.cwe) & {"CWE-862", "CWE-639"}:
        assert with_auth.severity == without.severity


@settings(max_examples=2000)
@given(anything)
def test_floors_are_never_lowered_and_llm_never_qualifies(inputs: Inputs) -> None:
    decision = decide(inputs)
    if inputs.category == "secret" and inputs.verified_live == "true":
        assert decision.severity is Severity.CRITICAL
    reach = inputs.reach.value if inputs.reach is not None else ""
    if inputs.category == "sca" and inputs.kev == "true" and reach in ("R0", "R3", "R4"):
        assert decision.severity is Severity.CRITICAL
    if decision.rule is None:
        assert decision.severity is inputs.raw  # no rule: the tool's severity, untouched
    assert decision.reasons  # every decision says why
    assert not qualifies(Provenance.LLM_SUGGESTED, 1.0)


@settings(max_examples=300)
@given(anything)
def test_decisions_are_deterministic(inputs: Inputs) -> None:
    assert decide(inputs) == decide(inputs)
