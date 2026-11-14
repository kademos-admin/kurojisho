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
kurojisho scan path/to/repo          # build or update the graph
kurojisho query stats --repo path/to/repo
kurojisho query callers some_function --repo path/to/repo
kurojisho query path handler sink --repo path/to/repo
kurojisho query export --repo path/to/repo -o graph.json
```

A scan only reads files. It never runs target code, install scripts or build steps, never
invokes git, and makes no network calls. Re-scanning parses only files whose content changed.

## What the graph contains

| Layer | Nodes | Edges |
|---|---|---|
| Code (Python, JavaScript/TypeScript, Go, Java) | Repo, Module, File, Class, Function, Route | CONTAINS, DEFINES, IMPORTS, INHERITS, CALLS |
| Dependencies (pypi, npm, Go modules, Maven) | Package | DEPENDS_ON (direct/transitive, scope) |
| Business context (`kurojisho.context.yaml`) | Asset | BELONGS_TO |

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
uv run pytest -m "not slow"     # fast suite
uv run pytest                   # everything
```

`tests/fixtures/` holds small target repos with hand-labelled `expected.yaml` ground truth.
They are scan targets and are never imported or executed.
