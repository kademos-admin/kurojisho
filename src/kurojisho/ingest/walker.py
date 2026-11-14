"""File discovery. Reads bytes only: nothing in the target is ever executed or followed out."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

#: Directories that hold tool state or third-party installs, never first-party source.
#: Everything skipped is recorded on the Repo node so the gap is visible.
IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".kurojisho",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)

LANG_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".java": "java",
}

_HEX = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
_CHUNK = 1 << 20


@dataclass(frozen=True)
class FileEntry:
    path: str  # repo-relative POSIX path
    abs_path: Path
    size: int
    content_hash: str
    lang: str | None


@dataclass
class WalkResult:
    files: list[FileEntry] = field(default_factory=list)
    skipped_dirs: list[str] = field(default_factory=list)
    skipped_links: list[str] = field(default_factory=list)
    skipped_special: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)

    def tree_hash(self) -> str:
        digest = hashlib.sha256()
        for entry in self.files:
            digest.update(f"{entry.path}\0{entry.content_hash}\n".encode())
        return digest.hexdigest()


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def walk(root: Path) -> WalkResult:
    """Walk ``root`` in sorted order. Symlinks and special files are recorded, not followed."""
    result = WalkResult()
    root = root.resolve()
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(current)
        rel_dir = base.relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else rel_dir + "/"
        keep = []
        for name in sorted(dirnames):
            if (base / name).is_symlink():
                result.skipped_links.append(prefix + name)
            elif name in IGNORED_DIRS:
                result.skipped_dirs.append(prefix + name)
            else:
                keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            full = base / name
            rel = prefix + name
            try:
                info = full.lstat()
                if stat.S_ISLNK(info.st_mode):
                    result.skipped_links.append(rel)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    result.skipped_special.append(rel)
                    continue
                digest = hash_file(full)
            except OSError:
                result.unreadable.append(rel)
                continue
            result.files.append(
                FileEntry(rel, full, info.st_size, digest, LANG_BY_SUFFIX.get(full.suffix.lower()))
            )
    result.files.sort(key=lambda f: f.path)
    for bucket in (
        result.skipped_dirs,
        result.skipped_links,
        result.skipped_special,
        result.unreadable,
    ):
        bucket.sort()
    return result


def read_git_head(root: Path) -> str | None:
    """Commit SHA of ``root``'s checkout, read straight from ``.git`` files.

    Git itself is never invoked: repository config can make it run arbitrary commands.
    Returns None when ``root`` is not the top of a work tree or HEAD cannot be resolved.
    """
    try:
        git_dir = root / ".git"
        if git_dir.is_file():
            text = git_dir.read_text("utf-8", "replace").strip()
            if not text.startswith("gitdir:"):
                return None
            git_dir = (root / text[len("gitdir:") :].strip()).resolve()
        if not git_dir.is_dir():
            return None
        common = git_dir
        marker = git_dir / "commondir"
        if marker.is_file():
            common = (git_dir / marker.read_text("utf-8", "replace").strip()).resolve()
        head = (git_dir / "HEAD").read_text("utf-8", "replace").strip()
        if not head.startswith("ref:"):
            return head if _HEX.match(head) else None
        ref = head[4:].strip()
        if not ref.startswith("refs/") or ".." in ref.split("/"):
            return None
        for base in (git_dir, common):
            loose = base / ref
            if loose.is_file():
                value = loose.read_text("utf-8", "replace").strip()
                return value if _HEX.match(value) else None
        packed = common / "packed-refs"
        if packed.is_file():
            for line in packed.read_text("utf-8", "replace").splitlines():
                sha, _, name = line.partition(" ")
                if name.strip() == ref and _HEX.match(sha):
                    return sha
    except OSError:
        return None
    return None
