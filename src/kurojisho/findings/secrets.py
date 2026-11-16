"""Secret hygiene: raw values are hashed on sight and scrubbed from everything stored.

Only a salted SHA-256 fingerprint and a four-character preview ever leave this module.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from typing import Any

from kurojisho.model import Edge, Node, canonical_json
from kurojisho.store import Store

SALT_ENV = "KUROJISHO_SECRET_SALT"
SALT_META = "secret_salt"
PREVIEW_MIN_LENGTH = 12
SCRUB_MIN_LENGTH = 8
ELLIPSIS = "…"


def load_salt(store: Store) -> bytes:
    """Per-database random salt, created on first use. ``KUROJISHO_SECRET_SALT`` overrides
    it so that CI runs can be reproducible."""
    override = os.environ.get(SALT_ENV)
    if override:
        return override.encode("utf-8")
    salt = store.get_meta(SALT_META)
    if salt is None:
        salt = secrets.token_hex(32)
        store.set_meta(SALT_META, salt)
    return salt.encode("utf-8")


class SecretHasher:
    def __init__(self, salt: bytes) -> None:
        if not salt:
            raise ValueError("a salt is required")
        self._salt = salt

    def fingerprint(self, value: str) -> str:
        return hashlib.sha256(self._salt + b"\0" + value.encode("utf-8")).hexdigest()

    @staticmethod
    def preview(value: str) -> str:
        """First four characters, and only for values long enough that four reveal little."""
        return value[:4] + ELLIPSIS if len(value) >= PREVIEW_MIN_LENGTH else ELLIPSIS


class Scrubber:
    """Removes known raw secret values from anything about to be persisted or printed."""

    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def add(self, value: str, fingerprint: str) -> None:
        marker = f"[REDACTED:{fingerprint[:8]}]"
        for part in {value, *value.splitlines()}:
            part = part.strip()
            if len(part) >= SCRUB_MIN_LENGTH:
                self._values[part] = marker

    def __bool__(self) -> bool:
        return bool(self._values)

    def text(self, value: str) -> str:
        # Longest first, so a secret containing another is removed whole.
        for raw in sorted(self._values, key=len, reverse=True):
            if raw in value:
                value = value.replace(raw, self._values[raw])
        return value

    def bytes(self, value: bytes) -> bytes:
        return self.text(value.decode("utf-8", "replace")).encode("utf-8")

    def _walk(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list | tuple):
            return [self._walk(v) for v in value]
        if isinstance(value, dict):
            return {self.text(k): self._walk(v) for k, v in value.items()}
        return value

    def _dirty(self, item: Node | Edge) -> bool:
        blob = canonical_json(item.content())
        return any(raw in blob for raw in self._values)

    def node(self, node: Node) -> Node:
        if not self._values or not self._dirty(node):
            return node
        data = node.model_dump()
        # The key (and so the id) is scrubbed too; callers must remap edges to the new id.
        data["key"] = self.text(node.key)
        data["name"] = self.text(node.name)
        data["props"] = self._walk(node.props)
        data["evidence"] = self._walk(data["evidence"])
        return Node.model_validate(data)

    def edge(self, edge: Edge) -> Edge:
        if not self._values or not self._dirty(edge):
            return edge
        data = edge.model_dump()
        data["props"] = self._walk(edge.props)
        data["evidence"] = self._walk(data["evidence"])
        return Edge.model_validate(data)
