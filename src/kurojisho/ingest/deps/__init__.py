"""Native manifest and lockfile parsing: Package facts without running any package manager."""

from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from kurojisho.ingest.deps import go, java, javascript, python
from kurojisho.ingest.deps.base import Dep, ManifestError

MAX_MANIFEST_BYTES = 20 * 1024 * 1024
_REQUIREMENTS = re.compile(r"(^|[-_.])requirements([-_.].*)?\.txt$", re.I)
SUPPORTED = {
    "pyproject.toml",
    "uv.lock",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "pom.xml",
}
#: Recognised dependency files with no parser yet. Flagged on the File node so the gap shows.
UNSUPPORTED = {  # TODO(M2): parse these, or cover them through Syft.
    "yarn.lock",
    "Pipfile",
    "Pipfile.lock",
    "setup.py",
    "setup.cfg",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
}
_PYTHON_ROOT_MARKERS = {"pyproject.toml", "setup.py", "setup.cfg"}


def manifest_kind(path: str) -> str | None:
    """ "supported", "unsupported" or None for a repo-relative path."""
    name = posixpath.basename(path)
    if name in SUPPORTED or is_requirements(path):
        return "supported"
    return "unsupported" if name in UNSUPPORTED else None


def is_requirements(path: str) -> bool:
    name = posixpath.basename(path)
    in_dir = posixpath.basename(posixpath.dirname(path)) == "requirements"
    return bool(_REQUIREMENTS.search(name)) or (in_dir and name.endswith(".txt"))


@dataclass
class ManifestResult:
    deps: list[Dep] = field(default_factory=list)
    go_modules: dict[str, str] = field(default_factory=dict)
    python_roots: list[str] = field(default_factory=list)
    notes: dict[str, list[str]] = field(default_factory=dict)


class _Parser:
    def __init__(self, read: Callable[[str], str | None], result: ManifestResult) -> None:
        self.read = read
        self.result = result

    def note(self, path: str, note: str) -> None:
        self.result.notes.setdefault(path, []).append(note)

    def text(self, path: str) -> str | None:
        text = self.read(path)
        if text is None:
            self.note(path, "manifest_unreadable_or_too_large")
        return text

    def parse(self, path: str | None, parser: Callable[[str, str], list[Dep]]) -> list[Dep] | None:
        """Parsed records, or None when the file is absent, unreadable or broken."""
        text = self.text(path) if path is not None else None
        if path is None or text is None:
            return None
        try:
            return parser(path, text)
        except ManifestError:
            self.note(path, "manifest_parse_error")
            return None

    def directory(self, directory: str, names: dict[str, str], requirements: list[str]) -> None:
        found: list[Dep] = []
        for path in requirements:
            found += self.parse(path, python.parse_requirements) or []

        declared = self.parse(names.get("pyproject.toml"), python.parse_pyproject)
        locked = self.parse(names.get("uv.lock"), python.parse_uv_lock) or []
        locked += (
            self.parse(
                names.get("poetry.lock"), lambda p, t: python.parse_poetry_lock(p, t, declared)
            )
            or []
        )
        found += _merge_declared(declared, locked)

        manifest = self.parse(names.get("package.json"), javascript.parse_package_json)
        locked = []
        for lock in ("package-lock.json", "npm-shrinkwrap.json"):
            locked += (
                self.parse(
                    names.get(lock), lambda p, t: javascript.parse_package_lock(p, t, manifest)
                )
                or []
            )
        locked += self.parse(names.get("pnpm-lock.yaml"), javascript.parse_pnpm_lock) or []
        found += _merge_declared(manifest, locked)

        known: set[str] = set()
        complete = False
        mod_text = self.text(names["go.mod"]) if "go.mod" in names else None
        if mod_text is not None:
            module = go.module_path(mod_text)
            if module:
                self.result.go_modules[directory] = module
            mod_deps = go.parse_go_mod(names["go.mod"], mod_text)
            found += mod_deps
            known = {d.name for d in mod_deps}
            complete = go.lists_all_modules(mod_text)
        if not complete:
            found += (
                self.parse(names.get("go.sum"), lambda p, t: go.parse_go_sum(p, t, known)) or []
            )

        if "pom.xml" in names:
            found += self.parse(names["pom.xml"], self._pom) or []
        self.result.deps += found

    def _pom(self, path: str, text: str) -> list[Dep]:
        deps, notes = java.parse_pom(path, text)
        for note in notes:
            self.note(path, note)
        return deps


def parse_manifests(paths: list[str], read: Callable[[str], str | None]) -> ManifestResult:
    """Parse every supported manifest in ``paths``. ``read`` returns text, or None if the
    file is unreadable or too large. A broken manifest yields a note, never an exception."""
    result = ManifestResult()
    parser = _Parser(read, result)
    by_dir: dict[str, dict[str, str]] = defaultdict(dict)
    requirements: dict[str, list[str]] = defaultdict(list)
    for path in sorted(paths):
        name = posixpath.basename(path)
        directory = posixpath.dirname(path)
        if name in _PYTHON_ROOT_MARKERS:
            result.python_roots += [directory, posixpath.join(directory, "src")]
        kind = manifest_kind(path)
        if kind == "unsupported":
            parser.note(path, "manifest_format_not_supported")
        elif kind == "supported" and is_requirements(path):
            requirements[directory].append(path)
            by_dir.setdefault(directory, {})
        elif kind == "supported":
            by_dir[directory][name] = path
    result.python_roots = sorted(set(result.python_roots) - {""})
    for directory in sorted(by_dir):
        parser.directory(directory, by_dir[directory], requirements[directory])
    result.deps.sort(key=lambda d: (d.manifest, d.ecosystem, d.name, d.version or "", d.line or 0))
    for notes in result.notes.values():
        notes.sort()
    return result


def _merge_declared(declared: list[Dep] | None, locked: list[Dep]) -> list[Dep]:
    """A lockfile gives exact versions, so version-less manifest records for the same
    package are redundant. Declared packages missing from the lock are kept."""
    locked_names = {d.name for d in locked}
    return [d for d in declared or [] if d.name not in locked_names] + locked
