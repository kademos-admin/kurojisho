"""M1-AC9 and walker behaviour: nothing is followed, executed or silently dropped."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from kurojisho.ingest.walker import read_git_head, walk

SHA = "a" * 40


def test_walk_is_sorted_hashes_and_classifies(tmp_path: Path) -> None:
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "z.TS").write_text("let a;")
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "README").write_bytes(b"\x00\x01")
    for ignored in ("node_modules/p", ".git", ".kurojisho", "b/__pycache__"):
        (tmp_path / ignored).mkdir(parents=True)
        (tmp_path / ignored / "f.py").write_text("x")
    result = walk(tmp_path)
    assert [(f.path, f.lang) for f in result.files] == [
        ("README", None),
        ("a.py", "python"),
        ("b/z.TS", "typescript"),
    ]
    assert result.skipped_dirs == [".git", ".kurojisho", "b/__pycache__", "node_modules"]
    assert len({f.content_hash for f in result.files}) == 3
    before = result.tree_hash()
    (tmp_path / "a.py").write_text("x = 2\n")
    assert walk(tmp_path).tree_hash() != before


def test_symlinks_and_special_files_are_recorded_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("x")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ok.py").write_text("x")
    (repo / "link.py").symlink_to(outside / "secret.py")
    (repo / "linkdir").symlink_to(outside, target_is_directory=True)
    os.mkfifo(repo / "pipe")  # opening a FIFO for reading would block forever
    result = walk(repo)
    assert [f.path for f in result.files] == ["ok.py"]
    assert result.skipped_links == ["link.py", "linkdir"]
    assert result.skipped_special == ["pipe"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_unreadable_files_are_reported(tmp_path: Path) -> None:
    locked = tmp_path / "locked.py"
    locked.write_text("x")
    locked.chmod(0)
    try:
        result = walk(tmp_path)
    finally:
        locked.chmod(0o600)
    assert result.unreadable == ["locked.py"] and result.files == []


def test_git_head_is_read_without_running_git(tmp_path: Path) -> None:
    assert read_git_head(tmp_path) is None
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    assert read_git_head(tmp_path) is None  # unborn branch
    (git / "refs" / "heads" / "main").write_text(SHA + "\n")
    assert read_git_head(tmp_path) == SHA
    (git / "refs" / "heads" / "main").unlink()
    (git / "packed-refs").write_text(f"# pack-refs\n{'b' * 40} refs/heads/main\n")
    assert read_git_head(tmp_path) == "b" * 40
    (git / "HEAD").write_text(SHA)
    assert read_git_head(tmp_path) == SHA
    for hostile in ("ref: ../../etc/passwd", "ref: refs/../../x", "not-a-sha"):
        (git / "HEAD").write_text(hostile)
        assert read_git_head(tmp_path) is None


def test_git_worktree_pointer_file(tmp_path: Path) -> None:
    main = tmp_path / "main" / ".git"
    wt_meta = main / "worktrees" / "wt"
    wt_meta.mkdir(parents=True)
    (main / "refs" / "heads").mkdir(parents=True)
    (main / "refs" / "heads" / "feature").write_text(SHA)
    (wt_meta / "HEAD").write_text("ref: refs/heads/feature")
    (wt_meta / "commondir").write_text("../..")
    work = tmp_path / "wt"
    work.mkdir()
    (work / ".git").write_text(f"gitdir: {wt_meta}\n")
    assert read_git_head(work) == SHA
    (work / ".git").write_text("garbage")
    assert read_git_head(work) is None
