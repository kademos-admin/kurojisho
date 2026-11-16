# KuroJisho

A local, deterministic security knowledge graph for a codebase.

KuroJisho parses a repository with tree-sitter and stores what it finds in SQLite as a graph
in which every node and edge records where it came from (provenance), how sure the tool is
(confidence) and the file and lines that prove it (evidence). Later milestones add scanner
orchestration, reachability-based triage, threat models and standards mapping on top.

Status: See `CHANGELOG.md`.

## Install

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run kurojisho --help
```

## Use

```sh
kurojisho init path/to/repo          # create .kurojisho/ and a starter context file
kurojisho scan path/to/repo          # build the graph and run the scanners
kurojisho scan path/to/repo --offline    # never touch the network
kurojisho scan path/to/repo --no-tools   # code graph only
kurojisho query stats --repo path/to/repo
kurojisho query nodes --type Finding --repo path/to/repo
kurojisho query callers some_function --repo path/to/repo
kurojisho query export --repo path/to/repo -o graph.json
```

Requires Docker or Podman for the scanners. The first scan pulls the pinned scanner images
and vulnerability data (several GB) and says so; `--offline` forbids that and records what
could not run as coverage gaps.

```sh
kurojisho tools list | install | verify    # pinned scanners (by image digest)
kurojisho intel refresh | status           # vulnerability data cache
kurojisho import-sarif report.sarif --tool NAME --repo path/to/repo   # optional CI mode
```

### What a scan does and does not do

- Target code is parsed, never executed: no install scripts, builds or tests, and git is
  never invoked.
- Each scanner runs in a container with the target mounted read-only, no network, a
  non-root user, no capabilities and CPU/memory/time limits. Images are referenced by
  digest from `src/kurojisho/tools/tools.lock`.
- Network is used only to pull missing images and refresh vulnerability data (by the
  host process, before scanners start), and for `--verify-secrets` (TruffleHog only).
- Secrets are stored as a salted SHA-256 fingerprint plus a four-character preview. Raw
  values are scrubbed from everything written.
- A scanner that is missing, fails or times out becomes a `CoverageGap` node. No findings
  from a gap means nothing.

### Scanners

| Kind | Tools |
|---|---|
| SAST | Semgrep CE (KuroJisho's own rules), Bandit, gosec; CodeQL is off by default behind a licence gate |
| Dependencies | OSV-Scanner, Trivy, Grype, govulncheck; Syft for the SBOM |
| Secrets | Gitleaks, TruffleHog |
| IaC | Checkov, Trivy config |

CodeQL is free only for open-source code and academic research. It needs `--enable codeql`
and `kurojisho tools accept-licence codeql --yes`; this build pins no CodeQL bundle yet.

## What the graph contains

| Layer | Nodes | Edges |
|---|---|---|
| Code (Python, JavaScript/TypeScript, Go, Java) | Repo, Module, File, Class, Function, Route | CONTAINS, DEFINES, IMPORTS, INHERITS, CALLS |
| Dependencies (pypi, npm, Go modules, Maven) | Package | DEPENDS_ON (direct/transitive, scope) |
| Business context (`kurojisho.context.yaml`) | Asset | BELONGS_TO |
| Findings | Finding, Secret, Advisory, CoverageGap | LOCATED_IN, DUPLICATE_OF, AFFECTED_BY |

### How far to trust a CALLS edge

tree-sitter sees syntax, not types, so each call is labelled with how it was resolved:

| `resolution` | Meaning | Confidence |
|---|---|---|
| `exact` | The name is bound by local scope or an import to one definition | 0.9 |
| `name_match` | Only the name matched; one edge per candidate | 0.5 |
| `dynamic_unknown` | Target is computed at runtime (`getattr`, `eval`, reflection, callbacks) | 0.1 |

Calls into the standard library or third-party packages have no edge; they are listed in the
caller's `calls_unresolved` property. Unknown never means safe: gaps (syntax errors,
oversized or unreadable files, unsupported manifests, skipped directories) are recorded on
the File and Repo nodes rather than dropped.

## Development

```sh
uv run ruff check . && uv run ruff format --check . && uv run mypy src
uv run pytest -m "not slow"     # fast suite, hermetic (no Docker, no network)
uv run pytest                   # everything, including real containers when installed
```

`tests/fixtures/` holds small target repos with hand-labelled `expected.yaml` ground truth.
They are scan targets and are never imported or executed.
