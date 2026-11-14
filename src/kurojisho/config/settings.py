"""Locations of KuroJisho's own state. Nothing here is read from the scanned code."""

from __future__ import annotations

from pathlib import Path

STATE_DIR = ".kurojisho"
DB_NAME = "graph.db"


def default_db_path(root: Path) -> Path:
    return root / STATE_DIR / DB_NAME
