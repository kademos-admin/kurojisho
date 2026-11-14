"""Slow: incremental behaviour on a generated repository of a few thousand files."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from kurojisho.ingest.pipeline import scan
from kurojisho.store import Store
from kurojisho.store.graph import canonical_export
from tests.conftest import CLOCK

FILES = 2000


def generate(root: Path) -> None:
    for index in range(FILES):
        package = root / f"pkg{index % 40:02d}"
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").touch()
        previous = (index - 1) % FILES
        (package / f"mod{index}.py").write_text(
            f"from pkg{previous % 40:02d}.mod{previous} import run{previous}\n\n\n"
            f"class Worker{index}:\n"
            f"    def step(self, value):\n"
            f"        return run{previous}(value)\n\n\n"
            f"def run{index}(value):\n"
            f"    return Worker{index}().step(value)\n"
        )


@pytest.mark.slow
def test_incremental_scan_of_large_repo_is_cheap_and_correct(tmp_path: Path) -> None:
    root = tmp_path / "big"
    generate(root)
    store = Store(tmp_path / "g.db")
    started = time.perf_counter()
    first = scan(root, store, CLOCK)
    full_seconds = time.perf_counter() - started
    assert len(first.files_parsed) == FILES + 40

    noop = scan(root, store, CLOCK)
    assert noop.files_parsed == [] and noop.writes.total == 0

    target = root / "pkg07" / "mod7.py"
    target.write_text(target.read_text() + "\n\ndef extra7():\n    return run7(1)\n")
    started = time.perf_counter()
    result = scan(root, store, CLOCK)
    incremental_seconds = time.perf_counter() - started
    assert result.files_parsed == ["pkg07/mod7.py"]
    assert result.writes.nodes_inserted == 1
    assert result.writes.total < 20
    assert incremental_seconds < full_seconds

    fresh = Store(tmp_path / "fresh.db")
    scan(root, fresh, CLOCK)
    assert canonical_export(store) == canonical_export(fresh)
