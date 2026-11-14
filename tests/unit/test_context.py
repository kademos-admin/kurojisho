"""M1-AC7: business context loading, validation and glob matching."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from kurojisho.config.context import ContextError, glob_match, load_context
from kurojisho.ingest.assets import build_assets

SPEC_EXAMPLE = """
assets:
  - id: payments-api
    paths: ["services/payments/**"]
    tier: 1
    data_classes: [PCI, PII]
    exposure: internet
    asvs_level: 3
    regulatory: [PCI-DSS]
  - id: admin-portal
    paths: ["apps/admin/**"]
    tier: 2
    data_classes: [PII]
    exposure: internal
    asvs_level: 2
defaults: { asvs_level: 2, tier: 3 }
ai:
  llm_features:
    - id: support-copilot
      tools_allowed: [kb_search, ticket_read]
      human_approval_required: [ticket_update]
"""


def test_spec_example_loads() -> None:
    ctx = load_context(SPEC_EXAMPLE)
    payments, admin = ctx.assets
    assert (payments.id, payments.tier, payments.asvs_level) == ("payments-api", 1, 3)
    assert payments.data_classes == ("PCI", "PII") and payments.exposure == "internet"
    assert payments.line == 3 and admin.line == 10
    assert payments.matches("services/payments/api/handler.py")
    assert not payments.matches("services/billing/x.py")
    assert ctx.defaults == {"asvs_level": 2, "tier": 3}
    assert ctx.ai["llm_features"][0]["id"] == "support-copilot"


def test_empty_file_and_builtin_defaults() -> None:
    assert load_context("").assets == ()
    assert load_context("# only comments\n").defaults == {"asvs_level": 2, "tier": 3}
    asset = load_context("assets: [{id: a, paths: ['x']}]").assets[0]
    assert (asset.tier, asset.asvs_level, asset.exposure) == (3, 2, None)
    assert asset.defaulted == ("asvs_level", "tier")
    custom = load_context("assets: [{id: a, paths: ['x'], tier: 2}]\ndefaults: {asvs_level: 3}")
    assert (custom.assets[0].tier, custom.assets[0].asvs_level) == (2, 3)
    assert custom.assets[0].defaulted == ("asvs_level",)


@pytest.mark.parametrize(
    "text",
    [
        "assets: [{id: a}]",  # paths missing
        "assets: [{id: a, paths: []}]",
        "assets: [{id: a, paths: ['x'], tier: 9}]",
        "assets: [{id: a, paths: ['x'], asvs_level: 1}]",
        "assets: [{id: a, paths: ['x'], exposure: public}]",
        "assets: [{id: a, paths: ['x'], data_classes: [SECRET]}]",
        "assets: [{id: a, paths: ['x'], severity_override: low}]",  # unknown keys rejected
        "assets: [{id: a, paths: ['x']}, {id: a, paths: ['y']}]",  # duplicate id
        "assetz: []",
        "- just\n- a list",
        "assets: [unclosed",
    ],
)
def test_invalid_context_is_rejected(text: str) -> None:
    with pytest.raises(ContextError):
        load_context(text)


@pytest.mark.parametrize(
    ("pattern", "path", "want"),
    [
        ("services/payments/**", "services/payments/a/b.py", True),
        ("services/payments/**", "services/payments", False),
        ("services/payments", "services/payments/a.py", True),  # a directory covers its tree
        ("services/payments/", "services/payments/a.py", True),
        ("services/pay", "services/payments/a.py", False),  # no prefix matching
        ("*.py", "a.py", True),
        ("*.py", "pkg/a.py", False),
        ("**/*.py", "a.py", True),
        ("**/*.py", "pkg/deep/a.py", True),
        ("src/*/api.?s", "src/x/api.ts", True),
        ("src/*/api.?s", "src/x/y/api.ts", False),
        ("./apps/admin/**", "apps/admin/x.js", True),
        ("a.b", "aXb", False),  # regex metacharacters are literal
        ("**", "anything/at/all", True),
    ],
)
def test_glob_semantics(pattern: str, path: str, want: bool) -> None:
    assert glob_match(pattern, path) is want


@given(st.from_regex(r"[a-z0-9_]{1,6}(/[a-z0-9_.]{1,6}){0,4}", fullmatch=True))
def test_glob_literal_and_directory_invariants(path: str) -> None:
    assert glob_match(path, path)
    assert glob_match("**", path)
    assert glob_match(path.split("/")[0], path)
    assert not glob_match(path + "x", path)


def test_assets_become_asserted_nodes_and_edges() -> None:
    ctx = load_context(SPEC_EXAMPLE)
    files = ["apps/admin/ui.ts", "services/payments/pay.py", "README.md"]
    nodes, edges = build_assets(ctx, "kurojisho.context.yaml", "hash", files)
    assert [n.name for n in nodes] == ["payments-api", "admin-portal"]
    assert all(n.provenance.value == "ASSERTED" and n.evidence[0].content_hash for n in nodes)
    assert len(edges) == 2
    assert {e.props["matched"][0] for e in edges} == {"apps/admin/**", "services/payments/**"}
    assert build_assets(load_context(""), "", "", files) == ([], [])
