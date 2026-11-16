"""Loader for ``tools.lock``: the pinned set of scanners KuroJisho is allowed to run."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from importlib import resources

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
SUPPORTED_SCHEMA = 1


class LockError(ValueError):
    """tools.lock is malformed or pins something loosely."""


@dataclass(frozen=True)
class ToolPin:
    name: str
    version: str
    image: str
    digest: str
    licence: str
    homepage: str = ""
    network: bool = False  # may the sandbox ever grant this tool network access?
    #: ``go install`` target for tools built at install time inside ``image``.
    build: str = ""
    #: Required checksum of the built binary.
    binary_sha256: str = ""

    @property
    def ref(self) -> str:
        """Immutable image reference. A tag is never used."""
        return f"{self.image}@{self.digest}"


def parse_lock(text: str) -> dict[str, ToolPin]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise LockError("tools.lock is not valid TOML") from exc
    if data.get("schema") != SUPPORTED_SCHEMA:
        raise LockError(f"tools.lock schema must be {SUPPORTED_SCHEMA}")
    pins: dict[str, ToolPin] = {}
    for entry in data.get("tool", []):
        missing = [k for k in ("name", "version", "image", "digest", "licence") if not entry.get(k)]
        if missing:
            raise LockError(f"tool entry {entry.get('name', '?')!r} lacks {', '.join(missing)}")
        unknown = set(entry) - {
            "name",
            "version",
            "image",
            "digest",
            "licence",
            "homepage",
            "network",
            "build",
            "binary_sha256",
        }
        if unknown:
            raise LockError(f"tool {entry['name']!r} has unknown keys: {sorted(unknown)}")
        if not _NAME.match(entry["name"]) or not _IMAGE.match(entry["image"]):
            raise LockError(f"tool {entry['name']!r} has an invalid name or image")
        if not _DIGEST.match(entry["digest"]):
            raise LockError(f"tool {entry['name']!r} must be pinned by sha256 digest")
        built = str(entry.get("build", "")), str(entry.get("binary_sha256", ""))
        if any(built) and not (
            re.fullmatch(r"[A-Za-z0-9._/-]+@v[0-9][A-Za-z0-9.+-]*", built[0])
            and re.fullmatch(r"[0-9a-f]{64}", built[1])
        ):
            raise LockError(f"tool {entry['name']!r}: build needs a versioned target and checksum")
        if entry["name"] in pins:
            raise LockError(f"tool {entry['name']!r} is listed twice")
        pins[entry["name"]] = ToolPin(
            name=entry["name"],
            version=str(entry["version"]),
            image=entry["image"],
            digest=entry["digest"],
            licence=entry["licence"],
            homepage=entry.get("homepage", ""),
            network=bool(entry.get("network", False)),
            build=built[0],
            binary_sha256=built[1],
        )
    return pins


def load_lock() -> dict[str, ToolPin]:
    text = resources.files("kurojisho.tools").joinpath("tools.lock").read_text("utf-8")
    return parse_lock(text)
