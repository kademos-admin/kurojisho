# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
