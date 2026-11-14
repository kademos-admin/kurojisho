"""Shared types for manifest and lockfile parsing. Files are read, never executed."""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import quote

from kurojisho.model import Scope

#: Worst case first: when sources disagree, the package is treated as the more exposed one.
SCOPE_RANK = {Scope.RUNTIME: 0, Scope.UNKNOWN: 1, Scope.TEST: 2, Scope.DEV: 3}


@dataclass(frozen=True)
class Dep:
    ecosystem: str  # pypi | npm | golang | maven
    name: str
    version: str | None  # resolved version; None when only a range is declared
    spec: str | None  # declared constraint, verbatim
    direct: bool
    scope: Scope
    manifest: str  # repo-relative path of the file this record came from
    line: int | None = None
    confidence: float = 1.0
    note: str | None = None

    @property
    def purl(self) -> str:
        return purl(self.ecosystem, self.name, self.version)


class ManifestError(ValueError):
    """A manifest could not be parsed. Reported as a note on its File node."""


def normalise_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def purl(ecosystem: str, name: str, version: str | None) -> str:
    if ecosystem == "pypi":
        path = normalise_pypi(name)
    elif ecosystem == "npm":
        path = "/".join(quote(part, safe="") for part in name.split("/"))
    elif ecosystem == "maven":
        path = name.replace(":", "/")
    else:
        path = quote(name, safe="/.-_~")
    suffix = f"@{quote(version, safe='.-_~+')}" if version else ""
    return f"pkg:{ecosystem}/{path}{suffix}"


_URL_USERINFO = re.compile(r"//[^/@\s]+@")


def scrub_spec(spec: str | None) -> str | None:
    """Drop credentials embedded in a URL requirement (``https://user:token@host/...``)."""
    return None if spec is None else _URL_USERINFO.sub("//***@", spec)


def worst_scope(scopes: Iterable[Scope]) -> Scope:
    return min(scopes, key=lambda s: SCOPE_RANK[s])


def find_line(text: str, pattern: str) -> int | None:
    """1-based line of the first regex match, for evidence. None when not found."""
    match = re.search(pattern, text, re.MULTILINE)
    return None if match is None else text.count("\n", 0, match.start()) + 1


def reachable(graph: Mapping[str, Iterable[str]], roots: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    queue = deque(roots)
    while queue:
        item = queue.popleft()
        if item in seen:
            continue
        seen.add(item)
        queue.extend(graph.get(item, ()))
    return seen


def scope_by_reachability(
    name: str, runtime: set[str], dev: set[str], dev_scope: Scope = Scope.DEV
) -> Scope:
    if name in runtime:
        return Scope.RUNTIME
    if name in dev:
        return dev_scope
    return Scope.UNKNOWN
