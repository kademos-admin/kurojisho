"""Install, verify and list the pinned scanners."""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from kurojisho.intel.cache import cache_root
from kurojisho.tools.lock import ToolPin, load_lock
from kurojisho.tools.runtime import Runtime, RuntimeUnavailable
from kurojisho.tools.sandbox import OUT, SRC, Mount, RunSpec


@dataclass(frozen=True)
class ToolStatus:
    pin: ToolPin
    installed: bool
    #: What was actually checked. Publisher signatures are not, and this says so.
    verification: str


class ToolManager:
    def __init__(
        self,
        runtime: Runtime | None,
        pins: dict[str, ToolPin] | None = None,
        tools_dir: Path | None = None,
    ) -> None:
        self.runtime = runtime
        self.pins = load_lock() if pins is None else pins
        self.tools_dir = tools_dir or cache_root() / "tools"

    def pin(self, name: str) -> ToolPin:
        return self.pins[name]

    def binary_dir(self, name: str) -> Path:
        """Host directory holding a built tool's binary (mounted read-only at /tools)."""
        pin = self.pins[name]
        return self.tools_dir / f"{pin.name}-{pin.version}"

    def _binary_ok(self, pin: ToolPin) -> bool:
        binary = self.binary_dir(pin.name) / pin.name
        try:
            return hashlib.sha256(binary.read_bytes()).hexdigest() == pin.binary_sha256
        except OSError:
            return False

    def installed(self, name: str) -> bool:
        """True when the exact pinned digest is present locally (and, for built tools, the
        binary matches its checksum). A same-named image with another digest does not count."""
        pin = self.pins[name]
        if self.runtime is None or not self.runtime.image_present(pin.ref):
            return False
        return self._binary_ok(pin) if pin.build else True

    def install(self, names: list[str] | None = None) -> list[str]:
        """Pull missing tools by digest and build the ones that need it (network). Returns
        the names newly installed."""
        if self.runtime is None:
            raise RuntimeUnavailable("no container runtime (docker or podman) is available")
        done = []
        for name in sorted(names or self.pins):
            if self.installed(name):
                continue
            pin = self.pins[name]
            if not self.runtime.image_present(pin.ref):
                self.runtime.pull(pin.ref)
            if pin.build:
                self._build(pin)
            done.append(name)
        return done

    def _build(self, pin: ToolPin) -> None:
        """``go install`` the pinned module version inside the pinned Go image. Go verifies
        module content against its checksum database; the binary must then match ours."""
        if self.runtime is None:  # pragma: no cover - install() checks first
            raise RuntimeUnavailable("no container runtime")
        target = self.binary_dir(pin.name)
        target.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="kurojisho-build-") as work:
            empty, out = Path(work) / "src", Path(work) / "out"
            empty.mkdir()
            out.mkdir()
            env = {
                "GOBIN": OUT,
                "GOPATH": "/tmp/go",  # noqa: S108 - the container's private tmpfs
                "GOCACHE": "/tmp/cache",  # noqa: S108
                "CGO_ENABLED": "0",
                "GOFLAGS": "-trimpath",
                "GOTOOLCHAIN": "local",
            }
            spec = RunSpec(
                image=pin.ref,
                args=("install", pin.build),
                entrypoint="go",
                mounts=(Mount(empty, SRC), Mount(out, OUT, read_only=False)),
                env=env,
                network=True,
                tmp_exec=True,
                tmp_size="3g",
                timeout_s=900,
            )
            # Network is granted here because this is an install step; scans never get it.
            result = self.runtime.run(spec, allow_network=True)
            built = out / pin.name
            if result.exit_code != 0 or not built.is_file():
                raise RuntimeUnavailable(f"could not build {pin.name} {pin.version}")
            digest = hashlib.sha256(built.read_bytes()).hexdigest()
            if digest != pin.binary_sha256:
                raise RuntimeUnavailable(
                    f"{pin.name} {pin.version} built to {digest[:16]}…, expected "
                    f"{pin.binary_sha256[:16]}…; refusing to install it"
                )
            shutil.copyfile(built, target / pin.name)
            (target / pin.name).chmod(0o755)

    def status(self) -> list[ToolStatus]:
        out = []
        for name, pin in sorted(self.pins.items()):
            if not self.installed(name):
                note = "not installed"
            elif pin.build:
                note = "image digest + binary checksum (signature not verified)"
            else:
                # Pulling by digest verifies content. Publisher signatures are a separate
                # claim, reported honestly as unchecked until cosign identities are pinned.
                note = "digest only (signature not verified)"
            out.append(ToolStatus(pin, self.installed(name), note))
        return out
