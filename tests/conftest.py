"""Shared fixtures. Fixture repos are always copied out of the source tree before scanning."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kurojisho.clock import FixedClock
from kurojisho.ingest.pipeline import ScanResult, scan
from kurojisho.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_NAMES = ["py_flask_app", "js_express_app", "go_http_app", "java_spring_app"]
CLOCK = FixedClock(datetime(2024, 1, 1, tzinfo=UTC))


@dataclass
class Scanned:
    root: Path
    store: Store
    result: ScanResult

    def rescan(self, **kwargs: object) -> ScanResult:
        self.result = scan(self.root, self.store, CLOCK, **kwargs)  # type: ignore[arg-type]
        return self.result


def copy_fixture(name: str, dest: Path) -> Path:
    target = dest / name
    shutil.copytree(FIXTURES / name, target, ignore=shutil.ignore_patterns("expected.yaml"))
    return target


@pytest.fixture
def scan_fixture(tmp_path: Path) -> Callable[..., Scanned]:
    counter = iter(range(1000))

    def run(name: str) -> Scanned:
        work = tmp_path / f"run{next(counter)}"
        root = copy_fixture(name, work)
        store = Store(work / "graph.db")
        return Scanned(root, store, scan(root, store, CLOCK))

    return run


@pytest.fixture(autouse=True)
def isolated_user_dirs(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tests never read or write the real user cache (intel, built tools) or config."""
    base = tmp_path_factory.mktemp("user")
    monkeypatch.setenv("KUROJISHO_CACHE_DIR", str(base / "cache"))
    monkeypatch.setenv("KUROJISHO_CONFIG_DIR", str(base / "config"))
