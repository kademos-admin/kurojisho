"""Python manifests: requirements*.txt, pyproject.toml, uv.lock, poetry.lock."""

from __future__ import annotations

import re
import tomllib
from typing import Any

from kurojisho.ingest.deps.base import (
    Dep,
    ManifestError,
    find_line,
    normalise_pypi,
    reachable,
    scope_by_reachability,
    scrub_spec,
)
from kurojisho.model import Scope

_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_PIN = re.compile(r"^={2,3}\s*([^\s,;*]+)$")
_DEVISH = re.compile(r"(^|[-_./])(dev|develop|development|lint|docs?|ci)([-_.]|$)", re.I)
_TESTISH = re.compile(r"(^|[-_./])(tests?|testing)([-_.]|$)", re.I)


def group_scope(name: str) -> Scope:
    if _TESTISH.search(name):
        return Scope.TEST
    return Scope.DEV


def _file_scope(path: str) -> Scope:
    if _TESTISH.search(path):
        return Scope.TEST
    return Scope.DEV if _DEVISH.search(path) else Scope.RUNTIME


def parse_requirement(text: str) -> tuple[str, str | None, str | None] | None:
    """PEP 508 line -> (name, pinned version, spec). None for options, URLs and blanks."""
    body = text.split(" #", 1)[0].split(";", 1)[0].strip()
    if not body or body.startswith(("#", "-")) or "://" in body.split("@", 1)[0]:
        return None
    match = _REQ.match(body)
    if match is None:
        return None
    spec = match.group(3).strip()
    if spec.startswith("@"):
        return match.group(1), None, scrub_spec(spec)
    spec = spec.strip("() ")
    pin = _PIN.match(spec)
    return match.group(1), pin.group(1) if pin else None, spec or None


def parse_requirements(path: str, text: str) -> list[Dep]:
    scope = _file_scope(path)
    lines = text.splitlines()
    out = []
    joined: list[tuple[int, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(lines, 1):
        if not buffer:
            start = number
        if raw.rstrip().endswith("\\"):
            buffer += raw.rstrip()[:-1] + " "
            continue
        joined.append((start, buffer + raw))
        buffer = ""
    for index, (number, raw) in enumerate(joined):
        parsed = parse_requirement(raw.split(" --hash", 1)[0])
        if parsed is None:
            continue
        name, version, spec = parsed
        # pip-compile annotates each pin with "# via ..."; "-r"/"(pyproject)" mean direct.
        via = []
        for _, follow in joined[index + 1 :]:
            stripped = follow.strip()
            if not stripped.startswith("#"):
                break
            via.append(stripped.lstrip("# ").removeprefix("via").strip())
        via = [v for v in via if v]
        direct = not via or any(v.startswith(("-r", "-c", "(")) or "(" in v for v in via)
        out.append(Dep("pypi", normalise_pypi(name), version, spec, direct, scope, path, number))
    return out


def _load(path: str, text: str) -> dict[str, Any]:
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise ManifestError(f"{path}: invalid TOML") from exc


def _req_deps(path: str, text: str, reqs: Any, scope: Scope) -> list[Dep]:
    out = []
    for item in reqs if isinstance(reqs, list) else []:
        parsed = parse_requirement(item) if isinstance(item, str) else None
        if parsed is None:
            continue
        name, _, spec = parsed
        line = find_line(text, rf"""["']{re.escape(name)}\b""")
        out.append(Dep("pypi", normalise_pypi(name), None, spec, True, scope, path, line))
    return out


def parse_pyproject(path: str, text: str) -> list[Dep]:
    data = _load(path, text)
    out: list[Dep] = []
    project = data.get("project") or {}
    out += _req_deps(path, text, project.get("dependencies"), Scope.RUNTIME)
    for reqs in (project.get("optional-dependencies") or {}).values():
        out += _req_deps(path, text, reqs, Scope.RUNTIME)
    for group, reqs in (data.get("dependency-groups") or {}).items():
        out += _req_deps(path, text, reqs, group_scope(group))
    tool = data.get("tool") or {}
    out += _req_deps(path, text, (tool.get("uv") or {}).get("dev-dependencies"), Scope.DEV)
    poetry = tool.get("poetry") or {}
    tables: list[tuple[Any, Scope]] = [
        (poetry.get("dependencies"), Scope.RUNTIME),
        (poetry.get("dev-dependencies"), Scope.DEV),
    ]
    for group, body in (poetry.get("group") or {}).items():
        tables.append(((body or {}).get("dependencies"), group_scope(group)))
    for table, scope in tables:
        for name, value in (table or {}).items():
            if name.lower() == "python":
                continue
            raw = value if isinstance(value, str) else (value or {}).get("version")
            spec = scrub_spec(raw) if isinstance(raw, str) else None
            line = find_line(text, rf"^\s*[\"']?{re.escape(name)}[\"']?\s*=")
            out.append(Dep("pypi", normalise_pypi(name), None, spec, True, scope, path, line))
    return out


def _names(items: Any) -> list[str]:
    return [
        normalise_pypi(i["name"])
        for i in (items if isinstance(items, list) else [])
        if isinstance(i, dict) and isinstance(i.get("name"), str)
    ]


def parse_uv_lock(path: str, text: str) -> list[Dep]:
    packages = [p for p in _load(path, text).get("package") or [] if isinstance(p, dict)]
    graph: dict[str, list[str]] = {}
    runtime_roots: list[str] = []
    dev_roots: list[str] = []
    test_roots: list[str] = []
    locals_: set[str] = set()
    for package in packages:
        name = normalise_pypi(str(package.get("name", "")))
        deps = _names(package.get("dependencies"))
        for extra in (package.get("optional-dependencies") or {}).values():
            deps += _names(extra)
        graph[name] = deps
        source = package.get("source") or {}
        if any(k in source for k in ("virtual", "editable", "directory")):
            locals_.add(name)
            runtime_roots += deps
            for group, items in (package.get("dev-dependencies") or {}).items():
                (test_roots if group_scope(group) is Scope.TEST else dev_roots).extend(
                    _names(items)
                )
    runtime = reachable(graph, runtime_roots)
    test = reachable(graph, test_roots)
    dev = reachable(graph, dev_roots)
    direct = set(runtime_roots) | set(dev_roots) | set(test_roots)
    out = []
    for package in packages:
        name = normalise_pypi(str(package.get("name", "")))
        version = package.get("version")
        if not name or name in locals_ or not isinstance(version, str):
            continue
        scope = scope_by_reachability(name, runtime, test, Scope.TEST)
        if scope is Scope.UNKNOWN:
            scope = scope_by_reachability(name, runtime, dev)
        line = find_line(text, rf'^name = "{re.escape(str(package["name"]))}"')
        out.append(Dep("pypi", name, version, None, name in direct, scope, path, line))
    return out


def parse_poetry_lock(path: str, text: str, declared: list[Dep] | None) -> list[Dep]:
    packages = [p for p in _load(path, text).get("package") or [] if isinstance(p, dict)]
    graph = {
        normalise_pypi(str(p.get("name", ""))): [
            normalise_pypi(d) for d in (p.get("dependencies") or {})
        ]
        for p in packages
    }
    known = declared is not None
    by_scope: dict[Scope, list[str]] = {s: [] for s in Scope}
    for dep in declared or []:
        by_scope[dep.scope].append(dep.name)
    runtime = reachable(graph, by_scope[Scope.RUNTIME])
    test = reachable(graph, by_scope[Scope.TEST])
    dev = reachable(graph, by_scope[Scope.DEV])
    direct = {d.name for d in declared or []}
    out = []
    for package in packages:
        name = normalise_pypi(str(package.get("name", "")))
        version = package.get("version")
        if not name or not isinstance(version, str):
            continue
        groups = package.get("groups")
        category = package.get("category")
        if isinstance(groups, list) and groups:
            scope = Scope.RUNTIME if "main" in groups else group_scope(" ".join(map(str, groups)))
        elif isinstance(category, str):
            scope = Scope.RUNTIME if category == "main" else Scope.DEV
        elif known:
            scope = scope_by_reachability(name, runtime, test, Scope.TEST)
            if scope is Scope.UNKNOWN:
                scope = scope_by_reachability(name, runtime, dev)
        else:
            scope = Scope.UNKNOWN
        line = find_line(text, rf'^name = "{re.escape(str(package["name"]))}"')
        note = None if known else "no pyproject.toml beside the lockfile; direct/transitive unknown"
        out.append(Dep("pypi", name, version, None, name in direct, scope, path, line, note=note))
    return out
