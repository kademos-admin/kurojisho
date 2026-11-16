"""On-disk cache of vulnerability intelligence, shared by every scanned repository.

Only the host process writes here, and only in ``intel refresh`` (or the refresh a scan
performs when it is not ``--offline``). Scanners get the relevant directory read-only.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from kurojisho.clock import Clock, isoformat

CACHE_ENV = "KUROJISHO_CACHE_DIR"
MAX_AGE_HOURS = 24


def cache_root() -> Path:
    override = os.environ.get(CACHE_ENV)
    if override:
        return Path(override)
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "kurojisho"


class IntelCache:
    """Named sources under one directory, with a manifest recording what was fetched."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._manifest_path = root / "manifest.json"
        self.sources: dict[str, dict[str, Any]] = {}
        if self._manifest_path.is_file():
            try:
                loaded = json.loads(self._manifest_path.read_text("utf-8"))
                self.sources = dict(loaded.get("sources") or {})
            except (ValueError, OSError):
                self.sources = {}

    def dir(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def has(self, source: str) -> bool:
        return source in self.sources

    def record(self, source: str, sha256: str, clock: Clock, **extra: Any) -> None:
        self.sources[source] = {"sha256": sha256, "fetched_at": isoformat(clock.now()), **extra}
        self.root.mkdir(parents=True, exist_ok=True)
        text = json.dumps({"sources": self.sources}, indent=1, sort_keys=True)
        temporary = self._manifest_path.with_suffix(".tmp")
        temporary.write_text(text, "utf-8")
        temporary.replace(self._manifest_path)

    def age_hours(self, source: str, clock: Clock) -> float | None:
        entry = self.sources.get(source)
        if entry is None:
            return None
        fetched = datetime.fromisoformat(entry["fetched_at"].replace("Z", "+00:00"))
        return (clock.now() - fetched).total_seconds() / 3600

    def stale(self, source: str, clock: Clock) -> bool:
        age = self.age_hours(source, clock)
        return age is None or age > MAX_AGE_HOURS

    def snapshot_id(self, sources: list[str] | None = None) -> str:
        """Content identity of the cache (or of some sources): changes only when data does."""
        names = sorted(
            self.sources if sources is None else [s for s in sources if s in self.sources]
        )
        digest = hashlib.sha256()
        for name in names:
            digest.update(f"{name}\0{self.sources[name]['sha256']}\n".encode())
        return digest.hexdigest()
