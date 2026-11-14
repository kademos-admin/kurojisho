"""Node keys shared by the ingest stages."""

from __future__ import annotations

from kurojisho.model import NodeType, node_id, node_key

REPO_KEY = node_key(NodeType.REPO, ".")


def file_key(path: str) -> str:
    return node_key(NodeType.FILE, path)


def container_key(directory: str) -> str:
    """Key of the node that stands for a directory: the Repo at the root, else a Module."""
    return REPO_KEY if directory in ("", ".") else node_key(NodeType.MODULE, directory)


def file_id(path: str) -> str:
    return node_id(file_key(path))


def container_id(directory: str) -> str:
    return node_id(container_key(directory))
