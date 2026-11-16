"""M2-AC1 / M2-AC2: pinned tool lock, tool manager and sandbox command construction."""

from __future__ import annotations

from pathlib import Path

import pytest

from kurojisho.tools.lock import LockError, load_lock, parse_lock
from kurojisho.tools.manager import ToolManager
from kurojisho.tools.runtime import ContainerRuntime, RunResult, RuntimeUnavailable, detect_runtime
from kurojisho.tools.sandbox import OUT, SRC, Mount, RunSpec, SandboxError, build_command

DIGEST = "sha256:" + "a" * 64
ENTRY = (
    f'[[tool]]\nname = "t"\nversion = "1"\nimage = "org/t"\ndigest = "{DIGEST}"\nlicence = "MIT"\n'
)


def test_shipped_lock_pins_every_tool_by_digest_with_a_licence() -> None:
    pins = load_lock()
    assert {"semgrep", "gitleaks", "trivy", "grype", "syft", "osv-scanner", "bandit", "gosec",
            "trufflehog", "checkov"} <= set(pins)  # fmt: skip
    for pin in pins.values():
        assert pin.digest.startswith("sha256:") and len(pin.digest) == 71
        assert pin.version and pin.licence and ":" not in pin.image
        assert pin.ref == f"{pin.image}@{pin.digest}"
    # only TruffleHog may ever be granted network access
    assert [name for name, pin in pins.items() if pin.network] == ["trufflehog"]


@pytest.mark.parametrize(
    "text",
    [
        "not toml [",
        "schema = 2\n",
        "schema = 1\n" + ENTRY.replace(f'digest = "{DIGEST}"\n', ""),
        "schema = 1\n" + ENTRY.replace(DIGEST, "latest"),
        "schema = 1\n" + ENTRY.replace(DIGEST, "sha256:abc"),
        "schema = 1\n" + ENTRY.replace('licence = "MIT"\n', ""),
        "schema = 1\n" + ENTRY.replace("org/t", "org/t:latest"),
        "schema = 1\n" + ENTRY.replace('name = "t"', 'name = "--privileged"'),
        "schema = 1\n" + ENTRY + 'tag = "latest"\n',
        "schema = 1\n" + ENTRY + ENTRY,
    ],
)
def test_loose_or_malformed_pins_are_rejected(text: str) -> None:
    with pytest.raises(LockError):
        parse_lock(text)


def test_minimal_lock_parses() -> None:
    pin = parse_lock("schema = 1\n" + ENTRY)["t"]
    assert (pin.name, pin.network, pin.ref) == ("t", False, f"org/t@{DIGEST}")
    assert parse_lock("schema = 1\n") == {}


def spec(tmp_path: Path, **kwargs: object) -> RunSpec:
    base: dict[str, object] = {
        "image": f"org/t@{DIGEST}",
        "args": ("scan", "--json"),
        "mounts": (Mount(tmp_path, SRC), Mount(tmp_path / "out", OUT, read_only=False)),
    }
    return RunSpec(**{**base, **kwargs})  # type: ignore[arg-type]


def test_every_run_is_locked_down(tmp_path: Path) -> None:
    cmd = build_command("docker", spec(tmp_path), name="n", uid=1000, gid=1000)
    assert cmd[:2] == ["docker", "run"]
    for flag in (
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=1000:1000",
        "--pids-limit=512",
        "--memory=4096m",
        "--memory-swap=4096m",
        "--cpus=2.0",
        "--tmpfs=/tmp:rw,nosuid,nodev,size=1g,noexec",
        "--env=HOME=/tmp",
        f"--mount=type=bind,source={tmp_path},target=/src,readonly",
        f"--mount=type=bind,source={tmp_path}/out,target=/out",
    ):
        assert flag in cmd, flag
    assert cmd[-3:] == [f"org/t@{DIGEST}", "scan", "--json"]
    assert "--privileged" not in cmd and not any(a.startswith("-v") for a in cmd)
    # host environment never leaks in: only HOME and the adapter's allowlist are set
    assert [a for a in cmd if a.startswith("--env=")] == ["--env=HOME=/tmp"]


def test_network_needs_both_the_adapter_and_the_caller(tmp_path: Path) -> None:
    def net(**kwargs: object) -> str:
        allow = bool(kwargs.pop("allow", False))
        cmd = build_command(
            "docker", spec(tmp_path, **kwargs), name="n", uid=1, gid=1, allow_network=allow
        )
        return next(a for a in cmd if a.startswith("--network="))

    assert net() == "--network=none"
    assert net(allow=True) == "--network=none"  # adapter did not ask
    assert net(network=True) == "--network=none"  # user did not allow
    assert net(network=True, allow=True) == "--network=bridge"


def test_adapter_options_are_applied(tmp_path: Path) -> None:
    cmd = build_command(
        "podman",
        spec(tmp_path, env={"B": "2", "A_1": "x"}, entrypoint="/bin/tool", tmp_exec=True,
             memory_mb=512, cpus=1.0, pids=64, workdir="/out"),
        name="n", uid=1, gid=2,
    )  # fmt: skip
    assert cmd[0] == "podman"
    assert cmd.index("--env=A_1=x") < cmd.index("--env=B=2")
    assert "--entrypoint=/bin/tool" in cmd and "--workdir=/out" in cmd
    assert "--tmpfs=/tmp:rw,nosuid,nodev,size=1g" in cmd and "--memory=512m" in cmd


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"image": "org/t:latest"}, "pinned by digest"),
        ({"image": f"--privileged@{DIGEST}"}, "pinned by digest"),
        ({"env": {"BAD-NAME": "x"}}, "environment"),
        ({"env": {"HOME": "/root"}}, "environment"),
        ({"mounts": (Mount(Path("/x"), OUT, read_only=False),)}, "read-only at /src"),
        ({"mounts": (Mount(Path("/x"), SRC, read_only=False),)}, "read-only at /src"),
        ({"mounts": (Mount(Path("relative"), SRC),)}, "unsafe mount"),
        ({"mounts": (Mount(Path("/a,readonly=false"), SRC),)}, "unsafe mount"),
        ({"mounts": (Mount(Path("/a"), SRC), Mount(Path("/b"), "out"))}, "mount target"),
    ],
)
def test_unsafe_requests_are_refused_not_weakened(
    tmp_path: Path, kwargs: dict[str, object], match: str
) -> None:
    with pytest.raises(SandboxError, match=match):
        build_command("docker", spec(tmp_path, **kwargs), name="n", uid=1000, gid=1000)


def test_root_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SandboxError, match="root"):
        build_command("docker", spec(tmp_path), name="n", uid=0, gid=0)


class StubRuntime:
    name = "stub"

    def __init__(self, present: set[str] | None = None) -> None:
        self.present = present or set()
        self.pulled: list[str] = []

    def image_present(self, ref: str) -> bool:
        return ref in self.present

    def pull(self, ref: str) -> None:
        self.pulled.append(ref)
        self.present.add(ref)

    def run(self, spec: RunSpec, *, allow_network: bool = False) -> RunResult:
        return RunResult(0)


def test_manager_installs_only_what_is_missing_and_matches_digest() -> None:
    pins = parse_lock(
        "schema = 1\n" + ENTRY + ENTRY.replace('"t"', '"u"').replace("org/t", "org/u")
    )
    runtime = StubRuntime({f"org/t@{DIGEST}", "org/u@sha256:" + "b" * 64})  # u: wrong digest
    manager = ToolManager(runtime, pins)
    assert manager.installed("t") and not manager.installed("u")
    assert [s.installed for s in manager.status()] == [True, False]
    assert manager.install() == ["u"] and runtime.pulled == [f"org/u@{DIGEST}"]
    assert manager.install() == [] and manager.pin("u").licence == "MIT"
    assert "not verified" in manager.status()[0].verification


def test_manager_without_a_runtime() -> None:
    manager = ToolManager(None, parse_lock("schema = 1\n" + ENTRY))
    assert not manager.installed("t")
    assert manager.status()[0].verification == "not installed"
    with pytest.raises(RuntimeUnavailable):
        manager.install()


def test_runtime_refuses_unpinned_pulls_and_detection_is_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(RuntimeUnavailable, match="unpinned"):
        ContainerRuntime("docker").pull("org/t:latest")
    monkeypatch.setattr("kurojisho.tools.runtime.shutil.which", lambda _b: None)
    assert detect_runtime() is None and detect_runtime("docker") is None
    assert detect_runtime("sh") is None  # only docker/podman are ever executed
    missing = ContainerRuntime("kurojisho-no-such-binary")
    assert not missing.usable() and not missing.image_present("x")
