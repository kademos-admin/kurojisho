"""Registry of scanner adapters."""

from __future__ import annotations

from kurojisho.tools.runners.bandit import BanditRunner
from kurojisho.tools.runners.base import RepoProfile, RunContext, Runner, ScanOptions, Step
from kurojisho.tools.runners.checkov import CheckovRunner
from kurojisho.tools.runners.codeql import CodeqlRunner
from kurojisho.tools.runners.gitleaks import GitleaksRunner
from kurojisho.tools.runners.gosec import GosecRunner
from kurojisho.tools.runners.govulncheck import GovulncheckRunner
from kurojisho.tools.runners.sca import (
    GrypeRunner,
    OsvScannerRunner,
    TrivyConfigRunner,
    TrivyRunner,
)
from kurojisho.tools.runners.semgrep import SemgrepRunner
from kurojisho.tools.runners.syft import SyftRunner
from kurojisho.tools.runners.trufflehog import TrufflehogRunner

RUNNERS: dict[str, Runner] = {
    r.name: r
    for r in (
        SemgrepRunner(),
        BanditRunner(),
        GosecRunner(),
        CheckovRunner(),
        GitleaksRunner(),
        TrufflehogRunner(),
        SyftRunner(),
        OsvScannerRunner(),
        TrivyRunner(),
        TrivyConfigRunner(),
        GrypeRunner(),
        GovulncheckRunner(),
        CodeqlRunner(),
    )
}

__all__ = ["RUNNERS", "RepoProfile", "RunContext", "Runner", "ScanOptions", "Step"]
