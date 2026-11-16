"""Real containers (``-m needs_tools``): proves the sandbox and the two first adapters
against the actual pinned images. Skipped when Docker/Podman or an image is missing."""

from __future__ import annotations

import random
import string
import subprocess
from pathlib import Path

import pytest

from kurojisho.scanner import scan_with_tools
from kurojisho.store import Store
from kurojisho.store import queries as q
from kurojisho.store.graph import canonical_export
from kurojisho.tools.lock import load_lock
from kurojisho.tools.runners import ScanOptions
from kurojisho.tools.runtime import ContainerRuntime, detect_runtime
from kurojisho.tools.sandbox import OUT, SRC, Mount, RunSpec
from tests.conftest import CLOCK, copy_fixture

pytestmark = [pytest.mark.needs_tools, pytest.mark.slow]
PINS = load_lock()


@pytest.fixture(scope="module")
def runtime() -> ContainerRuntime:
    found = detect_runtime()
    if found is None:
        pytest.skip("no container runtime")
    for tool in ("semgrep", "gitleaks"):
        if not found.image_present(PINS[tool].ref):
            pytest.skip(f"{tool} image not installed (run `kurojisho tools install`)")
    return found


def shell(runtime: ContainerRuntime, root: Path, out: Path, script: str, **kwargs: object):  # type: ignore[no-untyped-def]
    spec = RunSpec(
        image=PINS["semgrep"].ref,  # any pinned image with a shell
        args=("-c", script),
        entrypoint="/bin/sh",
        mounts=(Mount(root, SRC), Mount(out, OUT, read_only=False)),
        timeout_s=60,
        **kwargs,  # type: ignore[arg-type]
    )
    return runtime.run(spec)


def test_sandbox_blocks_writes_network_and_root(runtime: ContainerRuntime, tmp_path: Path) -> None:
    root, out = tmp_path / "src", tmp_path / "out"
    root.mkdir()
    out.mkdir()
    (root / "file.txt").write_text("original")
    script = (
        "id -u > /out/uid; "
        "(echo hacked > /src/file.txt) 2>/dev/null && echo yes > /out/wrote_src; "
        "(touch /src/new) 2>/dev/null && echo yes > /out/created_src; "
        "(touch /etc/x) 2>/dev/null && echo yes > /out/wrote_root; "
        "(python3 -c \"import socket; socket.create_connection(('1.1.1.1', 53), 3)\") 2>/dev/null "
        "&& echo yes > /out/network; "
        "ls /sys/class/net > /out/ifaces; echo done > /out/done"
    )
    result = shell(runtime, root, out, script)
    assert result.exit_code == 0 and (out / "done").exists()
    assert (root / "file.txt").read_text() == "original" and not (root / "new").exists()
    for forbidden in ("wrote_src", "created_src", "wrote_root", "network"):
        assert not (out / forbidden).exists(), forbidden
    assert (out / "uid").read_text().strip() != "0"
    assert (out / "ifaces").read_text().split() == ["lo"]


def test_sandbox_enforces_the_time_limit(runtime: ContainerRuntime, tmp_path: Path) -> None:
    (tmp_path / "out").mkdir()
    spec = RunSpec(
        image=PINS["semgrep"].ref,
        args=("-c", "sleep 60"),
        entrypoint="/bin/sh",
        mounts=(Mount(tmp_path, SRC), Mount(tmp_path / "out", OUT, read_only=False)),
        timeout_s=2,
    )
    result = runtime.run(spec)
    assert result.timed_out and result.exit_code is None and result.duration_ms < 30_000


def test_real_semgrep_and_gitleaks_end_to_end(
    runtime: ContainerRuntime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KUROJISHO_SECRET_SALT", "salt")
    rng = random.Random(5)
    pat = "ghp_" + "".join(rng.choices(string.ascii_letters + string.digits, k=36))
    slack = "xoxb-{}-{}-{}".format(
        rng.randint(10**11, 10**12), rng.randint(10**11, 10**12),
        "".join(rng.choices(string.ascii_letters, k=24)),
    )  # fmt: skip
    root = copy_fixture("vuln_app", tmp_path)
    (root / "old.env").write_text(f"SLACK={slack}\n")
    (root / "api" / "settings.py").write_text(f'GITHUB_TOKEN = "{pat}"\n')

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
            cwd=root, check=True, capture_output=True,
        )  # fmt: skip

    git("init", "-q")
    git("add", "-A")
    git("commit", "-q", "-m", "one")
    git("rm", "-q", "old.env")
    git("commit", "-q", "-m", "two")

    state = tmp_path / "state"
    store = Store(state / "graph.db")
    from kurojisho.tools.runners import RUNNERS

    two = {name: RUNNERS[name] for name in ("semgrep", "gitleaks")}
    _, outcomes = scan_with_tools(root, store, CLOCK, runtime=runtime, runners=two)
    assert {o.tool: o.status for o in outcomes} == {"gitleaks": "ok", "semgrep": "ok"}
    findings = q.find_nodes(store, node_type="Finding")
    assert sum(1 for f in findings if f["props"]["tool"] == "semgrep") == 19
    secrets = {
        (f["name"], f["props"]["location"]) for f in findings if f["props"]["category"] == "secret"
    }
    assert secrets == {("github-pat", "file"), ("slack-bot-token", "history")}
    assert {n["props"]["preview"] for n in q.find_nodes(store, node_type="Secret")} == {
        "ghp_…",
        "xoxb…",
    }

    store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    stored = b"".join(p.read_bytes() for p in state.rglob("*") if p.is_file())
    stored += canonical_export(store).encode()
    assert pat.encode() not in stored and slack.encode() not in stored
    assert list((state / "work").iterdir()) == []


def test_real_full_offline_scan_with_every_tool(
    runtime: ContainerRuntime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every pinned scanner, for real, with ``--offline``: needs `kurojisho tools install`
    and `kurojisho intel refresh` to have been run on this machine."""
    from kurojisho.intel.cache import IntelCache
    from kurojisho.tools.manager import ToolManager
    from kurojisho.tools.runners import RUNNERS

    real_cache = Path.home() / ".cache" / "kurojisho"
    monkeypatch.setenv("KUROJISHO_CACHE_DIR", str(real_cache))
    monkeypatch.setenv("KUROJISHO_SECRET_SALT", "salt")
    intel = IntelCache(real_cache / "intel")
    manager = ToolManager(runtime)
    needed = [
        "trivy-db",
        "grype-db",
        "govulndb",
        "kev",
        "epss",
        "osv:PyPI",
        "osv:npm",
        "osv:Go",
        "osv:Maven",
    ]
    if not all(intel.has(s) for s in needed):
        pytest.skip("intel cache not populated (run `kurojisho intel refresh`)")
    missing = [n for n in manager.pins if not manager.installed(n)]
    if missing:
        pytest.skip(f"tools not installed: {missing}")

    root = copy_fixture("vuln_app", tmp_path)
    store = Store(tmp_path / "state" / "graph.db")
    _, outcomes = scan_with_tools(
        root, store, CLOCK, runtime=runtime, options=ScanOptions(offline=True), intel=intel,
        manager=manager,
    )  # fmt: skip
    statuses = {o.tool: o.status for o in outcomes}
    assert set(statuses) == set(RUNNERS) - {"codeql"}
    assert set(statuses.values()) == {"ok"}, statuses
    stats = q.stats(store)["nodes"]
    assert stats["Finding"] > 200 and stats["Advisory"] >= 40
    log4shell = q.find_nodes(store, node_type="Advisory", name="CVE-2021-44228")[0]
    assert log4shell["provenance"] == "INTEL" and log4shell["props"]["kev"] is True
    assert log4shell["props"]["epss"] > 0.9
    assert sorted(log4shell["props"]["reported_by"]) == ["grype", "osv-scanner", "trivy"]
    semgrep = [
        f for f in q.find_nodes(store, node_type="Finding") if f["props"]["tool"] == "semgrep"
    ]
    assert len(semgrep) == 19
