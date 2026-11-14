"""Regression: canonical graph export per fixture, pinned as a golden snapshot.

A change here means the graph for an unchanged codebase changed. Update the snapshot
(``pytest --snapshot-update``) only with a justification in the changelog.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from syrupy.assertion import SnapshotAssertion

from kurojisho.store.graph import canonical_export
from tests.conftest import FIXTURE_NAMES, Scanned


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_canonical_export_matches_golden(
    name: str, scan_fixture: Callable[..., Scanned], snapshot: SnapshotAssertion
) -> None:
    assert canonical_export(scan_fixture(name).store) == snapshot
