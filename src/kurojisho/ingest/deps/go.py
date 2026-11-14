"""Go manifests: go.mod and go.sum."""

from __future__ import annotations

import re

from kurojisho.ingest.deps.base import Dep
from kurojisho.model import Scope

_REQUIRE = re.compile(r"^\s*([^\s()]+)\s+(v[^\s/]+)\s*(//\s*indirect)?")
_GO_DIRECTIVE = re.compile(r"^go\s+(\d+)\.(\d+)", re.MULTILINE)


def module_path(text: str) -> str | None:
    match = re.search(r"^module\s+(\S+)", text, re.MULTILINE)
    return match.group(1).strip('"') if match else None


def lists_all_modules(text: str) -> bool:
    """From Go 1.17 go.mod lists every module in the build, including indirect ones."""
    match = _GO_DIRECTIVE.search(text)
    return match is not None and (int(match.group(1)), int(match.group(2))) >= (1, 17)


def parse_go_mod(path: str, text: str) -> list[Dep]:
    out = []
    in_block = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if in_block:
            if line.startswith(")"):
                in_block = False
                continue
            body = line
        elif line.startswith("require ("):
            in_block = True
            continue
        elif line.startswith("require "):
            body = line[len("require ") :]
        else:
            continue
        match = _REQUIRE.match(body)
        if match is None:
            continue
        out.append(
            Dep(
                "golang",
                match.group(1).strip('"'),
                match.group(2),
                None,
                match.group(3) is None,
                Scope.RUNTIME,
                path,
                number,
            )
        )
    return out


def parse_go_sum(path: str, text: str, known: set[str]) -> list[Dep]:
    """Modules that appear only in go.sum. They may not be in the final build list, so the
    record carries reduced confidence rather than being dropped."""
    out: dict[tuple[str, str], Dep] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        parts = raw.split()
        if len(parts) != 3:
            continue
        name, version = parts[0], parts[1].removesuffix("/go.mod")
        if name in known or (name, version) in out:
            continue
        out[(name, version)] = Dep(
            "golang",
            name,
            version,
            None,
            False,
            Scope.RUNTIME,
            path,
            number,
            confidence=0.6,
            note="listed in go.sum only; may not be part of the build",
        )
    return list(out.values())
