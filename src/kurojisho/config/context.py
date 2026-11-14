"""Loader for the human-owned business context file (``kurojisho.context.yaml``)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

CONTEXT_FILENAME = "kurojisho.context.yaml"
#: Fallbacks when the file gives no ``defaults``: ASVS Level 2 baseline, tier 3.
BUILTIN_DEFAULTS = {"asvs_level": 2, "tier": 3}


class ContextError(ValueError):
    """The context file is malformed. Scans stop rather than guess business context."""


@dataclass(frozen=True)
class Asset:
    id: str
    paths: tuple[str, ...]
    tier: int
    asvs_level: int
    data_classes: tuple[str, ...] = ()
    exposure: str | None = None  # None = not asserted; never read as "not exposed"
    regulatory: tuple[str, ...] = ()
    defaulted: tuple[str, ...] = ()  # fields filled from defaults, not asserted per asset
    line: int | None = None

    def matches(self, path: str) -> bool:
        return any(glob_match(pattern, path) for pattern in self.paths)


@dataclass(frozen=True)
class Context:
    assets: tuple[Asset, ...] = ()
    defaults: dict[str, int] = field(default_factory=lambda: dict(BUILTIN_DEFAULTS))
    # TODO(M4): the validated ``ai`` section is carried through untouched until AI nodes exist.
    ai: dict[str, Any] = field(default_factory=dict)


@cache
def _validator() -> Draft202012Validator:
    raw = resources.files("kurojisho.config").joinpath("schema/context.schema.json")
    return Draft202012Validator(json.loads(raw.read_text("utf-8")))


@cache
def _glob_regex(pattern: str) -> re.Pattern[str]:
    out = []
    i = 0
    pattern = pattern.lstrip("/").removeprefix("./")
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def glob_match(pattern: str, path: str) -> bool:
    """Anchored glob on POSIX paths: ``*`` stays within a segment, ``**`` crosses them.
    A pattern that names a directory also matches everything beneath it."""
    regex = _glob_regex(pattern)
    if regex.fullmatch(path) is not None:
        return True
    return _glob_regex(pattern.rstrip("/") + "/**").fullmatch(path) is not None


def load_context(text: str, source: str = CONTEXT_FILENAME) -> Context:
    try:
        raw = YAML(typ="rt").load(text)
    except (YAMLError, RecursionError) as exc:
        raise ContextError(f"{source}: not valid YAML") from exc
    if raw is None:
        return Context()
    plain = json.loads(json.dumps(raw, default=str))
    errors = sorted(_validator().iter_errors(plain), key=lambda e: list(e.absolute_path))
    if errors:
        details = "; ".join(
            f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in errors[:5]
        )
        raise ContextError(f"{source}: {details}")
    defaults = {**BUILTIN_DEFAULTS, **plain.get("defaults", {})}
    assets = []
    seen: set[str] = set()
    for index, item in enumerate(plain.get("assets", [])):
        if item["id"] in seen:
            raise ContextError(f"{source}: duplicate asset id {item['id']!r}")
        seen.add(item["id"])
        line = None
        try:
            line = int(raw["assets"][index].lc.line) + 1
        except (AttributeError, KeyError, IndexError, TypeError):
            line = None
        assets.append(
            Asset(
                id=item["id"],
                paths=tuple(item["paths"]),
                tier=item.get("tier", defaults["tier"]),
                asvs_level=item.get("asvs_level", defaults["asvs_level"]),
                data_classes=tuple(sorted(item.get("data_classes", []))),
                exposure=item.get("exposure"),
                regulatory=tuple(sorted(item.get("regulatory", []))),
                defaulted=tuple(k for k in ("asvs_level", "tier") if k not in item),
                line=line,
            )
        )
    return Context(tuple(assets), defaults, plain.get("ai", {}))
