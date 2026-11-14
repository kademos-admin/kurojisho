"""JavaScript manifests: package.json, package-lock.json / npm-shrinkwrap.json, pnpm-lock.yaml."""

from __future__ import annotations

import json
import re
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from kurojisho.ingest.deps.base import (
    Dep,
    ManifestError,
    find_line,
    reachable,
    scope_by_reachability,
    scrub_spec,
)
from kurojisho.model import Scope

_SECTIONS = {
    "dependencies": Scope.RUNTIME,
    "optionalDependencies": Scope.RUNTIME,
    "peerDependencies": Scope.RUNTIME,
    "devDependencies": Scope.DEV,
}


def _json(path: str, text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ManifestError(f"{path}: invalid JSON") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{path}: expected a JSON object")
    return data


def _key_line(text: str, name: str) -> int | None:
    return find_line(text, rf'"{re.escape(name)}"\s*:')


def parse_package_json(path: str, text: str) -> list[Dep]:
    data = _json(path, text)
    out: dict[str, Dep] = {}
    for section, scope in _SECTIONS.items():
        table = data.get(section)
        for name, spec in table.items() if isinstance(table, dict) else []:
            if name in out and out[name].scope is Scope.RUNTIME:
                continue
            out[name] = Dep(
                "npm", name, None, scrub_spec(str(spec)), True, scope, path, _key_line(text, name)
            )
    return list(out.values())


def _lock_scope(entry: dict[str, Any]) -> Scope:
    if entry.get("dev") is True:
        return Scope.DEV
    if entry.get("devOptional") is True:
        return Scope.UNKNOWN  # dev of one thing, optional of another: cannot tell
    return Scope.RUNTIME


def parse_package_lock(path: str, text: str, declared: list[Dep] | None) -> list[Dep]:
    data = _json(path, text)
    direct = {d.name for d in declared or []}
    out: list[Dep] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2 / v3
        root_entry = packages.get("")
        root: dict[str, Any] = root_entry if isinstance(root_entry, dict) else {}
        if declared is None:
            for section in _SECTIONS:
                direct |= set(root.get(section) or {})
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict) or entry.get("link") is True:
                continue
            marker = "node_modules/"
            if marker not in key:
                continue  # a workspace member, not an installed package
            name = entry.get("name") or key.rsplit(marker, 1)[1]
            version = entry.get("version")
            if not isinstance(version, str):
                continue
            top_level = key == marker + name
            out.append(
                Dep(
                    "npm",
                    name,
                    version,
                    None,
                    top_level and name in direct,
                    _lock_scope(entry),
                    path,
                    _key_line(text, key),
                )
            )
        return out
    stack: list[tuple[dict[str, Any], bool]] = [(data.get("dependencies") or {}, True)]
    while stack:  # lockfile v1: nested "dependencies"
        table, top_level = stack.pop()
        for name, entry in table.items() if isinstance(table, dict) else []:
            if not isinstance(entry, dict) or not isinstance(entry.get("version"), str):
                continue
            out.append(
                Dep(
                    "npm",
                    name,
                    entry["version"],
                    None,
                    top_level and name in direct,
                    _lock_scope(entry),
                    path,
                    _key_line(text, name),
                )
            )
            stack.append((entry.get("dependencies") or {}, False))
    return out


def _pnpm_key(key: str) -> tuple[str, str] | None:
    """``/@scope/name@1.2.3(peer@1)`` or ``name@1.2.3`` -> (name, version)."""
    body = key.lstrip("/").split("(", 1)[0]
    at = body.rfind("@")
    if at <= 0:
        slash = body.rfind("/")  # pnpm v5: /name/1.2.3
        return (body[:slash], body[slash + 1 :].split("_", 1)[0]) if slash > 0 else None
    return body[:at], body[at + 1 :]


def _pnpm_ref(name: str, value: Any) -> str | None:
    version = value.get("version") if isinstance(value, dict) else value
    if not isinstance(version, str) or version.startswith(("link:", "file:", "workspace:")):
        return None
    return f"{name}@{version.split('(', 1)[0]}"


def parse_pnpm_lock(path: str, text: str) -> list[Dep]:
    try:
        data = YAML(typ="safe").load(text)
    except (YAMLError, RecursionError) as exc:
        raise ManifestError(f"{path}: invalid YAML") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{path}: expected a YAML mapping")
    importers = data.get("importers")
    if not isinstance(importers, dict):
        importers = {".": data}
    roots: dict[Scope, set[str]] = {Scope.RUNTIME: set(), Scope.DEV: set()}
    for importer in importers.values():
        for section, scope in _SECTIONS.items():
            table = importer.get(section) if isinstance(importer, dict) else None
            for name, value in table.items() if isinstance(table, dict) else []:
                ref = _pnpm_ref(str(name), value)
                if ref:
                    roots[scope].add(ref)
    graph: dict[str, list[str]] = {}
    for section in ("snapshots", "packages"):
        table = data.get(section)
        for key, entry in table.items() if isinstance(table, dict) else []:
            parsed = _pnpm_key(str(key))
            if parsed is None or not isinstance(entry, dict):
                continue
            edges = graph.setdefault("@".join(parsed), [])
            for dep_section in ("dependencies", "optionalDependencies"):
                deps = entry.get(dep_section)
                for name, value in deps.items() if isinstance(deps, dict) else []:
                    ref = _pnpm_ref(str(name), value)
                    if ref:
                        edges.append(ref)
    runtime = reachable(graph, roots[Scope.RUNTIME])
    dev = reachable(graph, roots[Scope.DEV])
    direct = roots[Scope.RUNTIME] | roots[Scope.DEV]
    packages = data.get("packages")
    out = []
    for key, entry in packages.items() if isinstance(packages, dict) else []:
        parsed = _pnpm_key(str(key))
        if parsed is None:
            continue
        name, version = parsed
        ref = f"{name}@{version}"
        if isinstance(entry, dict) and isinstance(entry.get("dev"), bool):
            scope = Scope.DEV if entry["dev"] else Scope.RUNTIME
        else:
            scope = scope_by_reachability(ref, runtime, dev)
        line = find_line(text, rf"^\s*['\"]?{re.escape(str(key))}['\"]?:")
        out.append(Dep("npm", name, version, None, ref in direct, scope, path, line))
    return out
