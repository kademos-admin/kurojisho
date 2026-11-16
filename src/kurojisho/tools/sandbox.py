"""The sandbox: the only place a scanner command line is built.

Every scanner runs in a container with the target mounted read-only, no network, a
non-root user, no capabilities, a read-only root filesystem and CPU, memory, process and
time limits. Nothing from the host environment is passed through.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TIMEOUT_S = 900
DEFAULT_MEMORY_MB = 4096
DEFAULT_CPUS = 2.0
DEFAULT_PIDS = 512
SRC = "/src"
OUT = "/out"


class SandboxError(ValueError):
    """The requested run cannot be made safe. It is refused, not weakened."""


@dataclass(frozen=True)
class Mount:
    source: Path
    target: str
    read_only: bool = True


@dataclass(frozen=True)
class RunSpec:
    image: str  # must be an immutable ``name@sha256:...`` reference
    args: tuple[str, ...]
    mounts: tuple[Mount, ...]
    env: dict[str, str] = field(default_factory=dict)
    entrypoint: str | None = None
    workdir: str = SRC
    #: Requested by the adapter. Granted only if the tool's pin and the user both allow it.
    network: bool = False
    timeout_s: int = DEFAULT_TIMEOUT_S
    memory_mb: int = DEFAULT_MEMORY_MB
    cpus: float = DEFAULT_CPUS
    pids: int = DEFAULT_PIDS
    #: Some tools unpack helpers into /tmp and execute them.
    tmp_exec: bool = False
    tmp_size: str = "1g"


def _check_path(path: Path) -> str:
    text = str(path)
    if not path.is_absolute() or any(c in text for c in ',\n\r\0"'):
        raise SandboxError(f"unsafe mount path: {text!r}")
    return text


def build_command(
    binary: str, spec: RunSpec, *, name: str, uid: int, gid: int, allow_network: bool = False
) -> list[str]:
    """Container command line for ``spec``. Pure: it runs nothing."""
    if "@sha256:" not in spec.image or spec.image.startswith("-"):
        raise SandboxError(f"image must be pinned by digest: {spec.image!r}")
    if uid == 0:
        raise SandboxError("refusing to run a scanner as root")
    if not any(m.target == SRC and m.read_only for m in spec.mounts):
        raise SandboxError("the target must be mounted read-only at /src")
    network = "bridge" if (spec.network and allow_network) else "none"
    tmp = f"rw,nosuid,nodev,size={spec.tmp_size}" + ("" if spec.tmp_exec else ",noexec")
    command = [
        binary,
        "run",
        "--rm",
        "--pull=never",  # installing is a separate, explicit step
        f"--name={name}",
        f"--network={network}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--user={uid}:{gid}",
        f"--pids-limit={spec.pids}",
        f"--memory={spec.memory_mb}m",
        f"--memory-swap={spec.memory_mb}m",
        f"--cpus={spec.cpus}",
        f"--tmpfs=/tmp:{tmp}",
        f"--workdir={spec.workdir}",
        "--env=HOME=/tmp",
    ]
    for key in sorted(spec.env):
        if not key.replace("_", "").isalnum() or key == "HOME":
            raise SandboxError(f"invalid environment variable name: {key!r}")
        command.append(f"--env={key}={spec.env[key]}")
    for mount in spec.mounts:
        if not mount.target.startswith("/") or "," in mount.target:
            raise SandboxError(f"invalid mount target: {mount.target!r}")
        option = f"type=bind,source={_check_path(mount.source)},target={mount.target}"
        command.append("--mount=" + option + (",readonly" if mount.read_only else ""))
    if spec.entrypoint is not None:
        command.append(f"--entrypoint={spec.entrypoint}")
    return [*command, spec.image, *spec.args]
