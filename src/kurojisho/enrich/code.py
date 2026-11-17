"""What every enrichment pass needs to know about the code graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property

from kurojisho.enrich.catalogue import Catalogue, alias_map, load_catalogues, qualify
from kurojisho.ingest.code.build import MODULE_BODY, def_key, synthetic_key
from kurojisho.ingest.code.extract import Call, Def, FileFacts
from kurojisho.ingest.code.resolve import FAMILY, Resolved, Resolver, Target
from kurojisho.ingest.keys import file_id
from kurojisho.model import RESOLUTION_CONFIDENCE, Evidence, Resolution, node_id

#: (file path, function qualname or None for module-level statements)
FuncKey = tuple[str, str | None]
MAX_CANDIDATES = 20


@dataclass
class Code:
    facts: dict[str, FileFacts]
    hashes: dict[str, str]
    resolver: Resolver
    known: set[str]  # ids of the nodes the code graph already holds
    _aliases: dict[str, dict[str, str]] = field(default_factory=dict)
    _resolved: dict[tuple[str, str], Resolved] = field(default_factory=dict)

    @cached_property
    def catalogues(self) -> dict[str, Catalogue]:
        return load_catalogues()

    def family(self, path: str) -> str:
        return FAMILY[self.facts[path].lang]

    def catalogue(self, path: str) -> Catalogue | None:
        return self.catalogues.get(self.family(path))

    def aliases(self, path: str) -> dict[str, str]:
        if path not in self._aliases:
            self._aliases[path] = alias_map(self.facts[path], self.family(path))
        return self._aliases[path]

    def qualify(self, path: str, name: str) -> str | None:
        return qualify(name, self.aliases(path), self.family(path))

    def definition(self, key: FuncKey) -> Def | None:
        return self.resolver.defs.get(Target(key[0], key[1])) if key[1] else None

    def func_id(self, key: FuncKey) -> str:
        """Node that stands for a function; module-level code falls back to the File."""
        path, qualname = key
        if qualname is not None:
            definition = self.definition(key)
            if definition is not None:
                return node_id(def_key(path, definition))
        module = node_id(synthetic_key(path, MODULE_BODY))
        return module if module in self.known else file_id(path)

    def resolve(self, path: str, call: Call) -> tuple[tuple[Target, ...], float]:
        """First-party functions a call may reach, with the confidence of that link."""
        cache_key = (path, call.ref or f"{call.line}:{call.kind}:{call.receiver}:{call.name}")
        result = self._resolved.get(cache_key)
        if result is None:
            result = self.resolver.resolve_call(path, call)
            self._resolved[cache_key] = result
        if result.resolution not in (Resolution.EXACT, Resolution.NAME_MATCH):
            return (), 0.0
        if len(result.targets) > MAX_CANDIDATES:
            return (), 0.0
        return result.targets, RESOLUTION_CONFIDENCE[result.resolution]

    def ev(self, path: str, start: int | None, end: int | None = None, note: str = "") -> Evidence:
        return Evidence(
            path=path,
            source="enrich:catalogue",
            start_line=start,
            end_line=(end or start) if start is not None else None,
            content_hash=self.hashes[path],
            note=note or None,
        )
