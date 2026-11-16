"""Scanner adapter interface. An adapter says how to run one tool and how to read it."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from kurojisho.findings.model import RawFinding
from kurojisho.findings.sbom import SbomPackage
from kurojisho.tools.lock import ToolPin
from kurojisho.tools.sandbox import OUT, SRC, Mount, RunSpec

CODE_LANGUAGES = frozenset({"python", "javascript", "typescript", "tsx", "go", "java"})


@dataclass(frozen=True)
class RepoProfile:
    """What ingest learned about the target, used to choose tools."""

    languages: frozenset[str]
    files: frozenset[str]
    has_git: bool = False
    git_head: str | None = None

    def has_name(self, *names: str) -> bool:
        return any(f.rsplit("/", 1)[-1] in names for f in self.files)

    def has_suffix(self, *suffixes: str) -> bool:
        return any(f.lower().endswith(suffixes) for f in self.files)

    def dirs_with(self, name: str) -> list[str]:
        """Sorted directories ("" = root) that directly contain a file called ``name``."""
        return sorted(f.rpartition("/")[0] for f in self.files if f.rsplit("/", 1)[-1] == name)


@dataclass(frozen=True)
class ScanOptions:
    tools: bool = True
    only: frozenset[str] | None = None
    skip: frozenset[str] = frozenset()
    enable: frozenset[str] = frozenset()
    offline: bool = False
    verify_secrets: bool = False


@dataclass
class RunContext:
    root: Path
    out: Path  # host directory mounted at /out for this tool only
    pin: ToolPin
    profile: RepoProfile
    options: ScanOptions
    extra_mounts: tuple[Mount, ...] = ()
    #: Host directory with this tool's built binary, for tools without an image of their own.
    tools_dir: Path | None = None
    #: Root of the intel cache on the host, when one is available.
    intel: Path | None = None

    def intel_mount(self, subdir: str, target: str = "/intel") -> None:
        """Expose one directory of the intel cache to the tool, read-only."""
        if self.intel is None:
            raise RuntimeError("intel cache requested but not available")
        self.extra_mounts = (*self.extra_mounts, Mount(self.intel / subdir, target))

    def spec(self, *args: str, **kwargs: object) -> RunSpec:
        mounts = (Mount(self.root, SRC), Mount(self.out, OUT, read_only=False), *self.extra_mounts)
        return RunSpec(image=self.pin.ref, args=tuple(args), mounts=mounts, **kwargs)  # type: ignore[arg-type]


@dataclass(frozen=True)
class Step:
    name: str
    spec: RunSpec
    output: str  # file the tool writes under /out; "" means the report is its stdout
    ok_exit: frozenset[int] = field(default_factory=lambda: frozenset({0}))


class Runner:
    name: ClassVar[str]
    category: ClassVar[str]  # sast | sca | secret | iac | sbom
    #: Output contains raw secret values: wiped after parsing, never cached or logged.
    sensitive: ClassVar[bool] = False
    #: Off unless the user passes ``--enable <name>``.
    opt_in: ClassVar[bool] = False
    #: Files in the target that can change what this tool reports (ignore lists, configs).
    #: Their presence is flagged: the scanned code must not silently scope its own scan.
    target_config: ClassVar[tuple[str, ...]] = ()
    #: Licence terms the user must accept before this tool may run ("" = no gate).
    licence_terms: ClassVar[str] = ""
    #: Entry in tools.lock, when several adapters share one image.
    pin_name: ClassVar[str] = ""

    @property
    def pin_key(self) -> str:
        return self.pin_name or self.name

    def intel_sources(self, profile: RepoProfile) -> list[str]:
        """Intel cache sources this tool cannot work without, for this repository."""
        return []

    def applicable(self, profile: RepoProfile) -> bool:
        raise NotImplementedError

    def steps(self, ctx: RunContext) -> list[Step]:
        raise NotImplementedError

    def parse(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[RawFinding]:
        raise NotImplementedError

    def packages(self, ctx: RunContext, outputs: dict[str, bytes]) -> list[SbomPackage]:
        """Software components the tool identified (SBOM tools only)."""
        return []

    def cache_inputs(self) -> str:
        """Anything besides the tool digest and the tree that changes the result."""
        return ""
