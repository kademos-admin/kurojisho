"""Locations of KuroJisho's own state. Nothing here is read from the scanned code."""

from __future__ import annotations

import json
import os
from pathlib import Path

STATE_DIR = ".kurojisho"
DB_NAME = "graph.db"


def default_db_path(root: Path) -> Path:
    return root / STATE_DIR / DB_NAME


# -- user-level configuration (licence acknowledgements) ---------------------------------
CONFIG_ENV = "KUROJISHO_CONFIG_DIR"


def config_dir() -> Path:
    override = os.environ.get(CONFIG_ENV)
    if override:
        return Path(override)
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "kurojisho"


def _licences() -> dict[str, dict[str, str]]:
    try:
        data = json.loads((config_dir() / "licences.json").read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def licence_accepted(tool: str) -> bool:
    return bool(_licences().get(tool, {}).get("accepted_at"))


def accept_licence(tool: str, accepted_at: str, terms: str) -> Path:
    """Record that the user accepted ``tool``'s licence terms. Returns the file written."""
    path = config_dir() / "licences.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _licences()
    data[tool] = {"accepted_at": accepted_at, "terms": terms}
    path.write_text(json.dumps(data, indent=1, sort_keys=True), "utf-8")
    return path
