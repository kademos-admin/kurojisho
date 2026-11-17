"""Catalogues of sources, sinks, sanitizers, controls and entry points (data, not code)."""

from __future__ import annotations

import hashlib
from fnmatch import fnmatchcase
from functools import cache
from importlib import resources
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator
from ruamel.yaml import YAML

from kurojisho.ingest.code.extract import FileFacts

#: Confidence of a match. Only ``EXACT`` reaches the 0.8 needed to lower a severity.
EXACT = 0.9
NAME_ONLY = 0.5

_JAVA_LANG = {"Integer", "Long", "Double", "Float", "Boolean", "String", "Runtime", "System"}
ControlKind = Literal["authn", "authz", "csrf", "rate_limit", "anonymous"]


class CatalogueError(ValueError):
    """A catalogue file is malformed. Nothing is guessed from a broken catalogue."""


class _Spec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    api: str | None = None
    name: str | None = None
    builtin: str | None = None

    @property
    def label(self) -> str:
        return self.api or self.name or self.builtin or ""


class _OneMatcher(_Spec):
    @model_validator(mode="after")
    def _exactly_one(self) -> _OneMatcher:
        if sum(v is not None for v in (self.api, self.name, self.builtin)) != 1:
            raise ValueError("give exactly one of api, name, builtin")
        return self


class SourceSpec(_OneMatcher):
    kind: str
    call: bool = False  # the name is a method whose result is untrusted


class SinkSpec(_OneMatcher):
    cwe: str
    args: tuple[int, ...] | None = None  # None = any argument
    receiver: bool = False  # the object the method is called on carries the danger


class SanitizerSpec(_OneMatcher):
    protects: tuple[str, ...]
    strength: Literal["strong", "partial"]


class ControlSpec(_Spec):
    kind: ControlKind
    signature: str | None = None

    @model_validator(mode="after")
    def _one(self) -> ControlSpec:
        if sum(v is not None for v in (self.api, self.name, self.signature)) != 1:
            raise ValueError("give exactly one of api, name, signature")
        return self

    @property
    def label(self) -> str:
        return self.api or self.name or self.signature or ""


class EntrySpec(_Spec):
    kind: Literal["cli", "queue_consumer", "cron", "webhook", "grpc"]
    function: str | None = None
    signature: str | None = None
    package: str | None = None


class Catalogue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    families: tuple[str, ...]
    ignore_params: tuple[str, ...] = ()
    sources: tuple[SourceSpec, ...] = ()
    sinks: tuple[SinkSpec, ...] = ()
    sanitizers: tuple[SanitizerSpec, ...] = ()
    controls: tuple[ControlSpec, ...] = ()
    entrypoints: tuple[EntrySpec, ...] = ()


def parse_catalogue(text: str, label: str) -> Catalogue:
    try:
        return Catalogue.model_validate(YAML(typ="safe").load(text))
    except Exception as exc:  # pydantic and YAML errors alike: the file is unusable
        raise CatalogueError(f"{label}: {exc}") from exc


@cache
def load_catalogues() -> dict[str, Catalogue]:
    """Catalogue per language family (``python``, ``js``, ``go``, ``java``)."""
    out: dict[str, Catalogue] = {}
    folder = resources.files("kurojisho.enrich").joinpath("catalogue")
    for entry in sorted(folder.iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".yaml"):
            catalogue = parse_catalogue(entry.read_text("utf-8"), entry.name)
            for family in catalogue.families:
                out[family] = catalogue
    return out


def catalogue_version() -> str:
    """Hash of the shipped catalogues, recorded so a change is visible in scan metadata."""
    digest = hashlib.sha256()
    folder = resources.files("kurojisho.enrich").joinpath("catalogue")
    for entry in sorted(folder.iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".yaml"):
            digest.update(entry.name.encode() + b"\0" + entry.read_bytes())
    return digest.hexdigest()[:16]


# -- names ------------------------------------------------------------------------------
def alias_map(facts: FileFacts, family: str) -> dict[str, str]:
    """Local name -> what an import bound it to, for third-party and standard modules."""
    out: dict[str, str] = {}
    for imp in facts.imports:
        if imp.level or imp.name == "*":
            continue
        if family == "go":
            if imp.alias in ("_", "."):
                continue
            parts = [p for p in imp.module.split("/") if p]
            last = parts[-1] if parts else ""
            if len(parts) > 1 and last[:1] == "v" and last[1:].isdigit():
                last = parts[-2]
            out[imp.alias or last] = imp.module
        elif imp.name is None or (family == "js" and imp.name == "default"):
            if imp.alias:
                out[imp.alias] = imp.module
            elif family == "python":
                head = imp.module.split(".")[0]
                out[head] = head
        elif imp.alias:
            out[imp.alias] = f"{imp.module}.{imp.name}"
    return out


def qualify(name: str, aliases: dict[str, str], family: str) -> str | None:
    """Fully qualified form of a dotted name, or None when its head is not an import."""
    head, dot, rest = name.partition(".")
    if head in aliases:
        return aliases[head] + dot + rest
    if family == "java" and head in _JAVA_LANG:
        return "java.lang." + name
    return None


def glob(pattern: str, value: str) -> bool:
    return fnmatchcase(value.lower(), pattern.lower())
