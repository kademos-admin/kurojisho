-- KuroJisho graph store, schema version 2. Every statement is idempotent, so applying
-- this file to an older database upgrades it in place (additive changes only).
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

-- One row per scan. first_seen / last_seen on nodes and edges point here, which is how
-- every row gets a commit SHA and a timestamp without being rewritten on each scan.
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    commit_sha   TEXT,
    tree_hash    TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    stats        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS nodes (
    id              TEXT PRIMARY KEY,
    type            TEXT NOT NULL,
    key             TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    owner_file      TEXT,
    props           TEXT NOT NULL,
    provenance      TEXT NOT NULL CHECK (provenance IN
                      ('EXTRACTED','INFERRED','TOOL','INTEL','ASSERTED','LLM_SUGGESTED')),
    confidence      REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    evidence        TEXT NOT NULL CHECK (json_array_length(evidence) > 0),
    row_hash        TEXT NOT NULL,
    first_seen_scan INTEGER NOT NULL REFERENCES scans(id),
    -- NULL while the row is live (last seen = latest scan); set when it is retired.
    last_seen_scan  INTEGER REFERENCES scans(id),
    retired         INTEGER NOT NULL DEFAULT 0 CHECK (retired IN (0, 1))
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nodes_type ON nodes(type, name);
CREATE INDEX IF NOT EXISTS nodes_owner ON nodes(owner_file);

CREATE TABLE IF NOT EXISTS edges (
    id              TEXT PRIMARY KEY,
    type            TEXT NOT NULL,
    src             TEXT NOT NULL REFERENCES nodes(id),
    dst             TEXT NOT NULL REFERENCES nodes(id),
    discriminator   TEXT NOT NULL DEFAULT '',
    owner_file      TEXT,
    props           TEXT NOT NULL,
    provenance      TEXT NOT NULL CHECK (provenance IN
                      ('EXTRACTED','INFERRED','TOOL','INTEL','ASSERTED','LLM_SUGGESTED')),
    confidence      REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    evidence        TEXT NOT NULL CHECK (json_array_length(evidence) > 0),
    row_hash        TEXT NOT NULL,
    first_seen_scan INTEGER NOT NULL REFERENCES scans(id),
    last_seen_scan  INTEGER REFERENCES scans(id),
    retired         INTEGER NOT NULL DEFAULT 0 CHECK (retired IN (0, 1))
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS edges_src ON edges(src, type);
CREATE INDEX IF NOT EXISTS edges_dst ON edges(dst, type);
CREATE INDEX IF NOT EXISTS edges_owner ON edges(owner_file);

-- Per-file extraction cache: lets an incremental scan skip parsing unchanged files.
CREATE TABLE IF NOT EXISTS files (
    path         TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    facts        TEXT NOT NULL
) WITHOUT ROWID;

-- One row per scanner invocation (or decision not to invoke) in a scan.
CREATE TABLE IF NOT EXISTS tool_runs (
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    tool        TEXT NOT NULL,
    version     TEXT NOT NULL,
    digest      TEXT NOT NULL,
    status      TEXT NOT NULL,  -- ok | cached | failed | timeout | invalid_output | ...
    exit_code   INTEGER,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    findings    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, tool)
) WITHOUT ROWID;

-- Normalised results of tools whose inputs have not changed. Never holds secret findings.
CREATE TABLE IF NOT EXISTS tool_cache (
    tool      TEXT PRIMARY KEY,
    cache_key TEXT NOT NULL,
    payload   TEXT NOT NULL
) WITHOUT ROWID;

CREATE VIEW IF NOT EXISTS nodes_seen AS
SELECT n.*,
       fs.commit_sha AS first_seen_commit, fs.started_at AS first_seen_at,
       ls.commit_sha AS last_seen_commit,  ls.started_at AS last_seen_at
FROM nodes n
JOIN scans fs ON fs.id = n.first_seen_scan
JOIN scans ls ON ls.id = COALESCE(n.last_seen_scan, (SELECT MAX(id) FROM scans));

CREATE VIEW IF NOT EXISTS edges_seen AS
SELECT e.*,
       fs.commit_sha AS first_seen_commit, fs.started_at AS first_seen_at,
       ls.commit_sha AS last_seen_commit,  ls.started_at AS last_seen_at
FROM edges e
JOIN scans fs ON fs.id = e.first_seen_scan
JOIN scans ls ON ls.id = COALESCE(e.last_seen_scan, (SELECT MAX(id) FROM scans));
