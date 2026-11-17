"""Cross-file resolution of imports, base classes and calls, from cached facts only.

tree-sitter gives syntax, not types, so every answer here is one of:

* ``exact``            the name is bound by local scope or an import to one definition;
* ``name_match``       only the name matched; every candidate is returned;
* ``dynamic_unknown``  the callee is computed at runtime and cannot be known statically;
* unresolved           nothing in the repo matches (typically the standard library or a
                       third-party package). Recorded on the caller, never dropped.
"""

from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass

from kurojisho.ingest.code.extract import Call, Def, FileFacts, Import
from kurojisho.model import Resolution

FAMILY = {
    "python": "python",
    "javascript": "js",
    "typescript": "js",
    "tsx": "js",
    "go": "go",
    "java": "java",
}
CONSTRUCTOR = {"python": "__init__", "js": "constructor", "java": "<init>"}
SELF_NAMES = {"python": {"self", "cls"}, "js": {"this"}, "java": {"this"}, "go": set[str]()}
_JS_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_JS_TO_TS = {".js": (".ts", ".tsx"), ".mjs": (".mts",), ".cjs": (".cts",), ".jsx": (".tsx",)}
_GO_VERSION_SEGMENT = re.compile(r"^v\d+$")
_ORDINAL = re.compile(r"#\d+$")


@dataclass(frozen=True, order=True)
class Target:
    path: str
    qualname: str


@dataclass(frozen=True)
class Binding:
    """What a local name refers to after an import."""

    kind: str  # "module" | "symbol"
    scopes: tuple[str, ...] = ()  # scope keys (file path, or package directory for Go)
    parent: str | None = None  # for symbols: enclosing class qualname, if any
    name: str = ""
    external: bool = False
    label: str = ""


@dataclass(frozen=True)
class ResolvedImport:
    imp: Import
    files: tuple[str, ...] = ()  # internal file targets
    directory: str | None = None  # internal package directory (Go)
    confidence: float = 1.0

    @property
    def internal(self) -> bool:
        return bool(self.files) or self.directory is not None


@dataclass(frozen=True)
class Resolved:
    resolution: Resolution | None
    targets: tuple[Target, ...] = ()
    label: str = ""
    reason: str = ""


class Resolver:
    def __init__(
        self,
        facts: dict[str, FileFacts],
        go_modules: dict[str, str] | None = None,
        python_roots: list[str] | None = None,
    ) -> None:
        self.facts = facts
        self.paths = set(facts)
        self.go_modules = go_modules or {}
        self.python_roots = list(dict.fromkeys(["", "src", *(python_roots or [])]))
        self.defs: dict[Target, Def] = {}
        self.members: dict[tuple[str, str | None, str], list[Target]] = defaultdict(list)
        self.functions: dict[tuple[str, str], list[Target]] = defaultdict(list)
        self.methods: dict[tuple[str, str], list[Target]] = defaultdict(list)
        self.classes: dict[tuple[str, str], list[Target]] = defaultdict(list)
        self.go_dirs: dict[str, list[str]] = defaultdict(list)
        self.java_packages: dict[str, dict[str, Target]] = defaultdict(dict)
        self.imports: dict[str, list[ResolvedImport]] = {}
        self.bindings: dict[str, dict[str, Binding]] = {}
        self.stars: dict[str, list[Binding]] = {}
        self._bases: dict[Target, tuple[Target, ...]] = {}
        self._name_matches: dict[tuple[int, str, str], tuple[Target, ...]] = {}
        self._index()
        for path in sorted(facts):
            self._bind(path)

    # -- indexing -----------------------------------------------------------------------
    def family(self, path: str) -> str:
        return FAMILY[self.facts[path].lang]

    def scope_key(self, path: str) -> str:
        """Go resolves names per package directory; everything else per file."""
        return "dir:" + posixpath.dirname(path) if self.family(path) == "go" else path

    def _index(self) -> None:
        for path in sorted(self.facts):
            facts = self.facts[path]
            family = FAMILY[facts.lang]
            scope = self.scope_key(path)
            if family == "go":
                self.go_dirs[posixpath.dirname(path)].append(path)
            for definition in facts.defs:
                target = Target(path, definition.qualname)
                self.defs[target] = definition
                self.members[(scope, definition.parent, definition.name)].append(target)
                if definition.kind == "class":
                    self.classes[(family, definition.name)].append(target)
                    if family == "java" and definition.parent is None:
                        self.java_packages[facts.package].setdefault(definition.name, target)
                elif definition.is_method:
                    self.methods[(family, definition.name)].append(target)
                else:
                    self.functions[(family, definition.name)].append(target)

    # -- imports ------------------------------------------------------------------------
    def _bind(self, path: str) -> None:
        family = self.family(path)
        bindings: dict[str, Binding] = {}
        stars: list[Binding] = []
        resolved: list[ResolvedImport] = []
        if family == "java":
            package = self.facts[path].package
            for name, target in sorted(self.java_packages.get(package, {}).items()):
                bindings[name] = Binding("symbol", (target.path,), None, name)
        binder = {
            "python": self._bind_python,
            "js": self._bind_js,
            "go": self._bind_go,
            "java": self._bind_java,
        }[family]
        # Wildcards first so that explicit imports override them.
        ordered = sorted(self.facts[path].imports, key=lambda i: (i.name != "*", i.line))
        for imp in ordered:
            resolved.append(binder(path, imp, bindings, stars))
        self.bindings[path] = bindings
        self.stars[path] = stars
        self.imports[path] = resolved

    def _python_module(self, importer: str, module: str, level: int) -> str | None:
        parts = [p for p in module.split(".") if p]
        if level:
            base = posixpath.dirname(importer)
            for _ in range(level - 1):
                if not base:
                    return None
                base = posixpath.dirname(base)
            bases = [base]
        else:
            bases = [*self.python_roots, posixpath.dirname(importer)]
        for base in bases:
            stem = "/".join([p for p in [base, *parts] if p])
            candidates = [f"{stem}.py", f"{stem}/__init__.py"] if stem else ["__init__.py"]
            for candidate in candidates:
                if candidate in self.paths and (parts or level):
                    return candidate
        return None

    def _bind_python(
        self, path: str, imp: Import, bindings: dict[str, Binding], stars: list[Binding]
    ) -> ResolvedImport:
        confidence = 1.0 if imp.level else 0.9
        dots = "." * imp.level
        if imp.name is None:
            target = self._python_module(path, imp.module, 0)
            key = imp.alias or imp.module
            bindings[key] = _module_binding(target, imp.module)
            return ResolvedImport(imp, (target,) if target else (), confidence=confidence)
        if imp.name == "*":
            target = self._python_module(path, imp.module, imp.level)
            stars.append(_module_binding(target, dots + imp.module))
            return ResolvedImport(imp, (target,) if target else (), confidence=confidence)
        joined = f"{imp.module}.{imp.name}" if imp.module else imp.name
        submodule = self._python_module(path, joined, imp.level)
        if submodule is not None:
            bindings[imp.alias] = Binding("module", (submodule,))
            return ResolvedImport(imp, (submodule,), confidence=confidence)
        target = self._python_module(path, imp.module, imp.level)
        if target is None:
            bindings[imp.alias] = Binding("symbol", external=True, label=dots + joined)
            return ResolvedImport(imp)
        bindings[imp.alias] = Binding("symbol", (target,), None, imp.name)
        return ResolvedImport(imp, (target,), confidence=confidence)

    def _js_path(self, importer: str, spec: str) -> str | None:
        if not spec.startswith("."):
            return None
        stem = posixpath.normpath(posixpath.join(posixpath.dirname(importer), spec))
        if stem.startswith(".."):
            return None
        candidates = [stem, *(stem + s for s in _JS_SUFFIXES)]
        root, ext = posixpath.splitext(stem)
        candidates += [root + s for s in _JS_TO_TS.get(ext, ())]
        candidates += [f"{stem}/index{s}" for s in _JS_SUFFIXES]
        return next((c for c in candidates if c in self.paths and c != importer), None)

    def _bind_js(
        self, path: str, imp: Import, bindings: dict[str, Binding], stars: list[Binding]
    ) -> ResolvedImport:
        target = self._js_path(path, imp.module)
        if imp.alias:
            if imp.name is None:
                bindings[imp.alias] = _module_binding(target, imp.module)
            elif target is None:
                label = f"{imp.module}#{imp.name}"
                bindings[imp.alias] = Binding("symbol", external=True, label=label)
            else:
                # A default export has no name of its own; the local alias is the only hint.
                name = imp.alias if imp.name == "default" else imp.name
                kind = "default" if imp.name == "default" else "symbol"
                bindings[imp.alias] = Binding(kind, (target,), None, name)
        return ResolvedImport(imp, (target,) if target else ())

    def _go_package_dir(self, importer: str, import_path: str) -> str | None:
        current = posixpath.dirname(importer)
        while True:
            module = self.go_modules.get(current)
            if module is not None:
                if import_path == module:
                    return current
                if import_path.startswith(module + "/"):
                    rel = import_path[len(module) + 1 :]
                    directory = posixpath.join(current, rel) if current else rel
                    return directory if directory in self.go_dirs else None
                return None
            if not current:
                return None
            current = posixpath.dirname(current)

    def _bind_go(
        self, path: str, imp: Import, bindings: dict[str, Binding], stars: list[Binding]
    ) -> ResolvedImport:
        directory = self._go_package_dir(path, imp.module)
        if directory is None:
            binding = Binding("module", external=True, label=imp.module)
            segments = imp.module.split("/")
            default = segments[-1]
            if _GO_VERSION_SEGMENT.match(default) and len(segments) > 1:
                default = segments[-2]
        else:
            binding = Binding("module", ("dir:" + directory,))
            packages = sorted(
                self.facts[f].package
                for f in self.go_dirs[directory]
                if not self.facts[f].package.endswith("_test")
            )
            default = packages[0] if packages else posixpath.basename(directory)
        if imp.name == "*":
            stars.append(binding)
        elif imp.alias != "_":
            bindings[imp.alias or default] = binding
        return ResolvedImport(imp, directory=directory)

    def _bind_java(
        self, path: str, imp: Import, bindings: dict[str, Binding], stars: list[Binding]
    ) -> ResolvedImport:
        if imp.name == "*":
            if imp.kind == "static":
                owner = self._java_class(imp.module)
                if owner is None:
                    stars.append(Binding("module", external=True, label=imp.module))
                    return ResolvedImport(imp)
                stars.append(Binding("symbol", (owner.path,), owner.qualname, "*"))
                return ResolvedImport(imp, (owner.path,))
            classes = self.java_packages.get(imp.module, {})
            for name, target in sorted(classes.items()):
                bindings[name] = Binding("symbol", (target.path,), None, name)
            files = tuple(sorted({t.path for t in classes.values()} - {path}))
            return ResolvedImport(imp, files)
        assert imp.name is not None
        direct = self.java_packages.get(imp.module, {}).get(imp.name)
        if direct is not None:
            bindings[imp.alias] = Binding("symbol", (direct.path,), None, imp.name)
            return ResolvedImport(imp, (direct.path,))
        owner = self._java_class(imp.module)  # static member or nested class
        if owner is not None:
            bindings[imp.alias] = Binding("symbol", (owner.path,), owner.qualname, imp.name)
            return ResolvedImport(imp, (owner.path,))
        label = f"{imp.module}.{imp.name}"
        bindings[imp.alias] = Binding("symbol", external=True, label=label)
        return ResolvedImport(imp)

    def _java_class(self, qualified: str) -> Target | None:
        package, _, name = qualified.rpartition(".")
        return self.java_packages.get(package, {}).get(name)

    # -- scope helpers ------------------------------------------------------------------
    def _chain(self, path: str, qualname: str | None) -> Iterator[str | None]:
        """``qualname`` and its enclosing definitions, innermost first, then module level."""
        seen = 0
        while qualname is not None and seen < 64:
            yield qualname
            definition = self.defs.get(Target(path, qualname))
            qualname = definition.parent if definition is not None else None
            seen += 1
        yield None

    def _members(self, scope: str, parent: str | None, name: str) -> list[Target]:
        return self.members.get((scope, parent, name), [])

    def _from_binding(self, binding: Binding, name: str | None = None) -> list[Target]:
        """Definitions a binding points at. For module bindings, ``name`` is the attribute."""
        if binding.external:
            return []
        if binding.kind == "module":
            return [t for s in binding.scopes for t in self._members(s, None, name or "")]
        return [t for s in binding.scopes for t in self._members(s, binding.parent, binding.name)]

    def enclosing_class(self, path: str, qualname: str | None) -> Target | None:
        for scope in self._chain(path, qualname):
            target = Target(path, scope or "")
            if scope is not None and target in self.defs and self.defs[target].kind == "class":
                return target
        return None

    def resolve_class(
        self, path: str, expr: str, scope: str | None
    ) -> tuple[tuple[Target, ...], Resolution | None]:
        """Resolve a class reference such as ``Base`` or ``module.Base``."""
        head, _, last = expr.rpartition(".")
        key = self.scope_key(path)
        hits: list[Target] = []
        external = False
        if not head:
            for level in self._chain(path, scope):
                hits = self._only_classes(self._members(key, level, last))
                if hits:
                    break
            binding = self.bindings[path].get(last)
            if not hits and binding is not None:
                external = binding.external
                if binding.kind != "module":
                    hits = self._only_classes(self._from_binding(binding))
            if not hits and binding is None:
                for star in self.stars[path]:
                    if star.external:
                        continue
                    parent = None if star.kind == "module" else star.parent
                    found = [t for s in star.scopes for t in self._members(s, parent, last)]
                    hits = self._only_classes(found)
                    if hits:
                        break
        else:
            binding = self.bindings[path].get(head)
            if binding is not None:
                external = binding.external
                if binding.kind == "module":
                    hits = self._only_classes(self._from_binding(binding, last))
            else:
                outers, how = self.resolve_class(path, head, scope)
                if how is Resolution.EXACT:
                    hits = self._only_classes(
                        [
                            t
                            for o in outers
                            for t in self._members(self.scope_key(o.path), o.qualname, last)
                        ]
                    )
        if hits:
            return tuple(sorted(set(hits))), Resolution.EXACT
        if external:
            return (), None
        candidates = self.classes.get((self.family(path), last), [])
        return (tuple(sorted(candidates)), Resolution.NAME_MATCH) if candidates else ((), None)

    def _only_classes(self, targets: list[Target]) -> list[Target]:
        return [t for t in targets if self.defs[t].kind == "class"]

    def exact_bases(self, cls: Target) -> tuple[Target, ...]:
        if cls not in self._bases:
            self._bases[cls] = ()  # guards against inheritance cycles
            found: list[Target] = []
            definition = self.defs[cls]
            for base in definition.bases:
                targets, how = self.resolve_class(cls.path, base, definition.parent)
                if how is Resolution.EXACT:
                    found += [t for t in targets if t != cls]
            self._bases[cls] = tuple(dict.fromkeys(found))
        return self._bases[cls]

    def class_method(
        self, scope: str, cls_name: str, cls: Target | None, name: str, argc: int
    ) -> list[Target]:
        """Method ``name`` on a class, searching exactly-resolved base classes if needed."""
        seen: set[Target] = set()
        queue: list[tuple[str, str, Target | None]] = [(scope, cls_name, cls)]
        while queue:
            current_scope, current_name, current = queue.pop(0)
            hits = [
                t
                for t in self._members(current_scope, current_name, name)
                if self.defs[t].kind == "function"
            ]
            if hits:
                return self._by_arity(hits, argc)
            if current is None:
                found = self._only_classes(self._members(current_scope, None, current_name))
                current = found[0] if found else None
            if current is None or current in seen:
                continue
            seen.add(current)
            queue += [(self.scope_key(b.path), b.qualname, b) for b in self.exact_bases(current)]
        return []

    def _by_arity(self, hits: list[Target], argc: int) -> list[Target]:
        if len(hits) < 2 or argc < 0:
            return hits
        matching = []
        for target in hits:
            params = self.defs[target].params
            count = len(params) - (1 if params[:1] in (["self"], ["cls"]) else 0)
            if count == argc:
                matching.append(target)
        return matching or hits

    # -- calls --------------------------------------------------------------------------
    def resolve_call(self, path: str, call: Call) -> Resolved:
        if call.kind == "dynamic":
            return Resolved(Resolution.DYNAMIC_UNKNOWN, reason=call.reason or call.name)
        if call.kind == "new":
            return self._resolve_new(path, call)
        if call.kind == "name":
            return self._resolve_name(path, call)
        return self._resolve_attr(path, call)

    def _finish(self, path: str, hits: list[Target], call: Call, label: str) -> Resolved | None:
        """Turn definitions into call targets; a class means "call its constructor"."""
        if not hits:
            return None
        family = self.family(path)
        targets: list[Target] = []
        for hit in hits:
            if self.defs[hit].kind == "class":
                ctor = CONSTRUCTOR.get(family)
                if ctor:
                    targets += self.class_method(
                        self.scope_key(hit.path), hit.qualname, hit, ctor, call.argc
                    )
            else:
                targets.append(hit)
        unique = tuple(sorted(set(targets)))
        if not unique:
            return Resolved(None, label=f"{label} (no explicit constructor)")
        how = Resolution.EXACT if len(unique) == 1 else Resolution.NAME_MATCH
        return Resolved(how, unique)

    def _name_match(
        self, path: str, index: dict[tuple[str, str], list[Target]], call: Call, label: str
    ) -> Resolved:
        key = (id(index), self.family(path), call.name)
        cached = self._name_matches.get(key)
        if cached is None:
            # Sorting thousands of same-named candidates once per call site is the single
            # most expensive thing a scan of a large repo does; the answer never changes.
            cached = tuple(sorted(set(index.get((self.family(path), call.name), []))))
            self._name_matches[key] = cached
        if not cached:
            return Resolved(None, label=label)
        return Resolved(Resolution.NAME_MATCH, cached)

    def _resolve_name(self, path: str, call: Call) -> Resolved:
        family = self.family(path)
        key = self.scope_key(path)
        name = call.name
        for level in self._chain(path, call.caller):
            owner = self.defs.get(Target(path, level)) if level is not None else None
            if owner is not None and owner.kind == "class":
                if family != "java":
                    continue  # class bodies are not an enclosing scope for bare names
                hits = self.class_method(
                    key, owner.qualname, Target(path, level or ""), name, call.argc
                )
            else:
                hits = self._by_arity(self._members(key, level, name), call.argc)
            done = self._finish(path, hits, call, name)
            if done is not None:
                return done
            if (
                owner is not None
                and family != "java"
                and (name in owner.params or name in owner.local_names)
            ):
                reason = "parameter" if name in owner.params else "local_variable"
                return Resolved(Resolution.DYNAMIC_UNKNOWN, reason=reason)
        binding = self.bindings[path].get(name)
        if binding is not None:
            if binding.external:
                return Resolved(None, label=binding.label or name)
            if binding.kind == "symbol":
                done = self._finish(path, self._from_binding(binding), call, name)
                if done is not None:
                    return done
            else:
                # Module object or default export called directly: only the alias to go on.
                hits = self._from_binding(Binding("module", binding.scopes), name)
                done = self._finish(path, hits, call, name)
                if done is not None:
                    return Resolved(Resolution.NAME_MATCH, done.targets) if done.targets else done
                return Resolved(None, label=f"{name} (import target not found)")
        unknown_star = False
        for star in self.stars[path]:
            if star.external:
                unknown_star = True
                continue
            if star.kind == "module":
                hits = self._from_binding(star, name)
            else:
                hits = [t for s in star.scopes for t in self._members(s, star.parent, name)]
            done = self._finish(path, hits, call, name)
            if done is not None:
                return done
        index = self.methods if family == "java" else self.functions
        label = f"{name} (possibly from a wildcard import)" if unknown_star else name
        return self._name_match(path, index, call, label)

    def _resolve_attr(self, path: str, call: Call) -> Resolved:
        family = self.family(path)
        key = self.scope_key(path)
        receiver, name = call.receiver, call.name
        label = f"{receiver}.{name}" if receiver else f"<expr>.{name}"
        caller = self.defs.get(Target(path, call.caller or ""))
        go_self = (
            family == "go" and caller is not None and bool(receiver) and receiver == caller.receiver
        )
        if go_self and caller is not None and caller.parent:
            hits = self.class_method(key, caller.parent, None, name, call.argc)
            return self._finish(path, hits, call, label) or self._name_match(
                path, self.methods, call, label
            )
        if receiver in SELF_NAMES[family] or receiver == "super":
            cls = self.enclosing_class(path, call.caller)
            if cls is not None:
                if receiver == "super":
                    hits = []
                    for base in self.exact_bases(cls):
                        hits += self.class_method(
                            self.scope_key(base.path), base.qualname, base, name, call.argc
                        )
                else:
                    hits = self.class_method(key, cls.qualname, cls, name, call.argc)
                done = self._finish(path, hits, call, label)
                if done is not None:
                    return done
            return self._name_match(path, self.methods, call, label)
        binding = self.bindings[path].get(receiver) if receiver else None
        if binding is not None:
            if binding.external:
                return Resolved(None, label=f"{binding.label or receiver}.{name}")
            if binding.kind == "module":
                done = self._finish(path, self._from_binding(binding, name), call, label)
                if done is not None:
                    return done
            else:
                done = self._static_call(path, self._from_binding(binding), call, label)
                if done is not None:
                    return done
            return self._name_match(path, self.methods, call, label)
        if receiver and "." not in receiver:
            classes, how = self.resolve_class(path, receiver, call.caller)
            if how is Resolution.EXACT:
                done = self._static_call(path, list(classes), call, label)
                if done is not None:
                    return done
        elif receiver:
            classes, how = self.resolve_class(path, receiver, call.caller)
            if how is Resolution.EXACT:
                done = self._static_call(path, list(classes), call, label)
                if done is not None:
                    return done
            head = receiver.split(".", 1)[0]
            outer = self.bindings[path].get(head)
            if outer is not None and outer.external:
                return Resolved(
                    None, label=f"{outer.label or head}.{receiver.split('.', 1)[1]}.{name}"
                )
        return self._name_match(path, self.methods, call, label)

    def _static_call(
        self, path: str, owners: list[Target], call: Call, label: str
    ) -> Resolved | None:
        hits: list[Target] = []
        for owner in self._only_classes(owners):
            hits += self.class_method(
                self.scope_key(owner.path), owner.qualname, owner, call.name, call.argc
            )
        return self._finish(path, hits, call, label)

    def _resolve_new(self, path: str, call: Call) -> Resolved:
        expr = f"{call.receiver}.{call.name}" if call.receiver else call.name
        classes, how = self.resolve_class(path, expr, call.caller)
        if how is None:
            return Resolved(None, label=f"new {expr}")
        done = self._finish(path, list(classes), call, f"new {expr}")
        if done is None or done.resolution is None:
            return done or Resolved(None, label=f"new {expr}")
        if how is Resolution.NAME_MATCH:
            return Resolved(Resolution.NAME_MATCH, done.targets)
        return done


def _module_binding(target: str | None, label: str) -> Binding:
    if target is None:
        return Binding("module", external=True, label=label)
    return Binding("module", (target,))


def base_qualname(qualname: str) -> str:
    return _ORDINAL.sub("", qualname)
