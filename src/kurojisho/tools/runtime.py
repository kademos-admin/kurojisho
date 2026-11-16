"""Container runtimes. The host process only ever executes ``docker``/``podman`` itself;
target code runs nowhere, and scanners run only inside the sandbox."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Protocol

from kurojisho.tools.sandbox import RunSpec, build_command

MAX_CAPTURE = 4 * 1024 * 1024


class RuntimeUnavailable(RuntimeError):
    """No container runtime is usable."""


@dataclass
class RunResult:
    exit_code: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    duration_ms: int = 0


class Runtime(Protocol):
    name: str

    def image_present(self, ref: str) -> bool: ...
    def pull(self, ref: str) -> None: ...
    def run(self, spec: RunSpec, *, allow_network: bool = False) -> RunResult: ...


class ContainerRuntime:
    """Docker or Podman, driven through its CLI with argument lists (never a shell)."""

    def __init__(self, binary: str) -> None:
        self.name = binary
        self.binary = binary

    def _call(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603 - fixed binary, argument list, no shell
            [self.binary, *args], capture_output=True, timeout=timeout, check=False, env=_ENV
        )

    def usable(self) -> bool:
        try:
            return self._call("version", "--format", "{{.Server.Version}}").returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def image_present(self, ref: str) -> bool:
        try:
            return self._call("image", "inspect", "--format", "{{.Id}}", ref).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def pull(self, ref: str) -> None:
        if "@sha256:" not in ref:
            raise RuntimeUnavailable(f"refusing to pull an unpinned image: {ref}")
        done = self._call("pull", "--quiet", ref, timeout=1800)
        if done.returncode != 0:
            raise RuntimeUnavailable(f"could not pull {ref} (exit {done.returncode})")

    def run(self, spec: RunSpec, *, allow_network: bool = False) -> RunResult:
        name = "kurojisho-" + secrets.token_hex(8)
        command = build_command(
            self.binary,
            spec,
            name=name,
            uid=os.getuid() or 65534,
            gid=os.getgid() or 65534,
            allow_network=allow_network,
        )
        started = time.monotonic()
        try:
            done = subprocess.run(  # noqa: S603 - see build_command
                command, capture_output=True, timeout=spec.timeout_s, check=False, env=_ENV
            )
        except subprocess.TimeoutExpired as exc:
            self._call("kill", name)
            return RunResult(
                None,
                (exc.stdout or b"")[:MAX_CAPTURE],
                (exc.stderr or b"")[:MAX_CAPTURE],
                timed_out=True,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        return RunResult(
            done.returncode,
            done.stdout[:MAX_CAPTURE],
            done.stderr[:MAX_CAPTURE],
            duration_ms=int((time.monotonic() - started) * 1000),
        )


#: Environment for the runtime CLI itself: enough to find the daemon, nothing else.
_ENV = {
    k: v
    for k, v in os.environ.items()
    if k in {"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "XDG_RUNTIME_DIR", "CONTAINER_HOST"}
}


def detect_runtime(preferred: str | None = None) -> ContainerRuntime | None:
    """First usable runtime: Docker, then Podman. None when neither works."""
    for binary in [preferred] if preferred else ["docker", "podman"]:
        if binary in ("docker", "podman") and shutil.which(binary):
            runtime = ContainerRuntime(binary)
            if runtime.usable():
                return runtime
    return None
