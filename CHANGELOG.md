# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (milestone 2: scanner orchestration and normalisation)

- `tools.lock`: eleven scanners pinned by image digest with version and licence;
  govulncheck is built at install time and must match a pinned binary checksum.
  `kurojisho tools list | install | verify | accept-licence`.
- Sandbox runner (Docker or Podman): target read-only, no network, non-root, no
  capabilities, read-only root filesystem, CPU/memory/process/time limits, private output
  directory.
- Adapters: Semgrep CE with an original 20-rule pack, Bandit, gosec, Checkov, Trivy (fs and
  config), OSV-Scanner, Grype, Syft, govulncheck, Gitleaks, TruffleHog. CodeQL adapter
  behind `--enable codeql` and a recorded licence acceptance (no bundle pinned yet).
- Tools are selected from the languages, manifests and IaC files found in the repository.
- Finding, Secret, Advisory and CoverageGap nodes; LOCATED_IN (file and enclosing
  function), DUPLICATE_OF (cross-tool dedupe) and AFFECTED_BY edges.
- Intel cache refreshed by the host process: OSV, Trivy DB, Grype DB, Go vulnerability DB,
  CISA KEV, EPSS, and NVD per CVE on request. `kurojisho intel refresh | status`.
- `kurojisho scan` flags: `--no-tools`, `--tools`, `--skip`, `--enable`, `--offline`,
  `--verify-secrets`, `--runtime`. `kurojisho import-sarif` for results produced elsewhere.
- Syft SBOM fills package licences and adds packages the native parsers missed.

### Changed

- `kurojisho scan` now runs scanners by default; use `--no-tools` for the code graph only.
- Store schema v2 (additive): `tool_runs` and `tool_cache` tables.

### Security

- Raw secret values never reach the database, WAL, logs, caches or exports: they are
  fingerprinted in memory (salted SHA-256, per-database salt) and scrubbed from every
  stored string; scanner output containing them is overwritten and deleted.
- Suppressions controlled by the scanned repository (`nosemgrep`, `#nosec`,
  `.gitleaksignore`, `.trivyignore`) are disabled, and config files that cannot be
  disabled are reported as coverage gaps.
- Downloads are HTTPS only and checked against a digest or checksum where the source
  publishes one (Trivy DB, Grype DB, scanner images).

### Added (milestone 1: graph core and code ingest)

- `kurojisho init`, `kurojisho scan <path>` and `kurojisho query`
  (`stats`, `nodes`, `show`, `callers`, `callees`, `path`, `export`).
- SQLite graph store (WAL) with provenance, confidence and evidence on every node and edge,
  first/last seen tracked per scan, recursive-CTE path queries and a NetworkX loader.
- tree-sitter extraction for Python, JavaScript, TypeScript/TSX, Go and Java: Repo, Module,
  File, Class, Function and Route nodes; CONTAINS, DEFINES, IMPORTS, INHERITS and CALLS
  edges, with calls resolved as `exact`, `name_match` or `dynamic_unknown`.
- Native manifest and lockfile parsing to Package nodes and DEPENDS_ON edges with
  direct/transitive and scope: `requirements*.txt`, `pyproject.toml`, `uv.lock`,
  `poetry.lock`, `package.json`, `package-lock.json`, `npm-shrinkwrap.json`,
  `pnpm-lock.yaml`, `go.mod`, `go.sum`, `pom.xml`.
- `kurojisho.context.yaml` loader (JSON Schema validated) producing ASSERTED Asset nodes and
  BELONGS_TO edges by path glob.
- Incremental scans: files are hashed, only changed files are re-parsed, and the store is
  updated by diff, so an unchanged tree writes no graph rows.
- Deterministic canonical export of the graph.

### Security

- Scans read files only: no target code, install script, build step or git command is run,
  and no network call is made.
- String literals are blanked in stored signatures and decorators, and credentials are
  stripped from dependency URLs, so hard-coded secrets do not reach the database.
- XML manifests are parsed with defusedxml; symlinks and special files are recorded, not
  followed.
