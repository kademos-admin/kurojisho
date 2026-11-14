"""M1-AC1 / M1-AC4: model validation and stable identifiers."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from kurojisho.clock import FixedClock, SystemClock, clock_from_env, isoformat
from kurojisho.model import Edge, EdgeType, Evidence, Node, NodeType, Provenance, node_id, node_key
from tests.helpers import EV, call, fn


def test_node_requires_evidence() -> None:
    with pytest.raises(ValidationError):
        Node(
            type=NodeType.FILE,
            key="File:a.py",
            name="a.py",
            provenance=Provenance.EXTRACTED,
            confidence=1.0,
            evidence=(),
        )


@pytest.mark.parametrize("confidence", [-0.1, 1.01])
def test_confidence_is_bounded(confidence: float) -> None:
    with pytest.raises(ValidationError):
        Node.model_validate({**fn("f").model_dump(), "confidence": confidence})


def test_edge_requires_evidence_and_bounded_confidence() -> None:
    a, b = fn("a"), fn("b")
    with pytest.raises(ValidationError):
        Edge(
            type=EdgeType.CALLS,
            src=a.id,
            dst=b.id,
            provenance=Provenance.INFERRED,
            confidence=0.5,
            evidence=(),
        )
    with pytest.raises(ValidationError):
        Edge(
            type=EdgeType.CALLS,
            src=a.id,
            dst=b.id,
            provenance=Provenance.INFERRED,
            confidence=2,
            evidence=(EV,),
        )


def test_unknown_provenance_rejected() -> None:
    with pytest.raises(ValidationError):
        Node.model_validate({**fn("f").model_dump(), "provenance": "GUESSED"})


def test_evidence_span_validation() -> None:
    with pytest.raises(ValidationError):
        Evidence(path="a.py", source="t", start_line=5, end_line=4)
    with pytest.raises(ValidationError):
        Evidence(path="a.py", source="t", end_line=4)
    with pytest.raises(ValidationError):
        Evidence(path="", source="t")


def test_evidence_order_does_not_change_row_hash() -> None:
    e1 = Evidence(path="a.py", source="t", start_line=1, end_line=1)
    e2 = Evidence(path="a.py", source="t", start_line=9, end_line=9)
    n1 = fn("f").model_copy(update={"evidence": (e1, e2)})
    first = Node.model_validate(n1.model_dump())
    second = Node.model_validate({**n1.model_dump(), "evidence": (e2, e1, e2)})
    assert first.row_hash() == second.row_hash()
    assert len(second.evidence) == 2


def test_edge_discriminator_separates_parallel_edges() -> None:
    a, b = fn("a"), fn("b")
    plain = call(a, b)
    other = plain.model_copy(update={"discriminator": "x"})
    assert plain.id != other.id
    assert plain.id == call(a, b).id


@given(st.text(min_size=1), st.text(min_size=1))
def test_ids_are_stable_and_collision_resistant(a: str, b: str) -> None:
    ka, kb = node_key(NodeType.FUNCTION, a), node_key(NodeType.FUNCTION, b)
    assert node_id(ka) == node_id(ka)
    assert (node_id(ka) == node_id(kb)) == (a == b)
    assert node_id(node_key(NodeType.CLASS, a)) != node_id(ka)


def test_clocks() -> None:
    fixed = FixedClock(datetime(2024, 1, 2, 3, 4, 5, 999, tzinfo=UTC))
    assert isoformat(fixed.now()) == "2024-01-02T03:04:05Z"
    assert isoformat(clock_from_env({"SOURCE_DATE_EPOCH": "0"}).now()) == "1970-01-01T00:00:00Z"
    assert isinstance(clock_from_env({}), SystemClock)
    assert isinstance(clock_from_env({"SOURCE_DATE_EPOCH": "nope"}), SystemClock)
    assert SystemClock().now().tzinfo is UTC
