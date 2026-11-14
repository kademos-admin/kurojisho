"""M1-AC6: manifests and lockfiles -> package facts with direct/transitive and scope."""

from __future__ import annotations

import json

from kurojisho.ingest.deps import manifest_kind, parse_manifests
from kurojisho.ingest.deps.base import Dep, purl, worst_scope
from kurojisho.ingest.deps.python import parse_requirement
from kurojisho.model import Scope


def run(files: dict[str, str | None]):  # type: ignore[no-untyped-def]
    return parse_manifests(list(files), files.get)


def table(deps: list[Dep]) -> dict[str, tuple[str | None, bool, str]]:
    return {d.name: (d.version, d.direct, d.scope.value) for d in deps}


def test_purls() -> None:
    assert purl("pypi", "Flask_SQLAlchemy", "3.0") == "pkg:pypi/flask-sqlalchemy@3.0"
    assert purl("npm", "@scope/pkg", "1.0.0") == "pkg:npm/%40scope/pkg@1.0.0"
    assert purl("golang", "github.com/a/b", "v1.2.3") == "pkg:golang/github.com/a/b@v1.2.3"
    assert purl("maven", "org.x:lib", None) == "pkg:maven/org.x/lib"
    assert worst_scope([Scope.DEV, Scope.UNKNOWN, Scope.TEST]) is Scope.UNKNOWN
    assert worst_scope([Scope.DEV, Scope.RUNTIME]) is Scope.RUNTIME


def test_requirement_lines() -> None:
    assert parse_requirement("Flask==2.0.1 ; python_version > '3'") == ("Flask", "2.0.1", "==2.0.1")
    assert parse_requirement("requests[socks]>=2,<3  # c") == ("requests", None, ">=2,<3")
    assert parse_requirement("pkg @ https://x/y.whl") == ("pkg", None, "@ https://x/y.whl")
    assert parse_requirement("bare") == ("bare", None, None)
    for skipped in ("", "# c", "-r other.txt", "--index-url https://x", "https://x/y.whl", "!!"):
        assert parse_requirement(skipped) is None


def test_requirements_files_and_scopes() -> None:
    result = run(
        {
            "requirements.txt": "flask==2.0.1 \\\n  --hash=sha256:abc\nJinja2>=3\n-r base.txt\n",
            "requirements-dev.txt": "black==24.1.0\n",
            "requirements/test.txt": "pytest==8.0.0\n",
            "compiled/requirements.txt": (
                "click==8.1.7\n    # via flask\nflask==3.0.0\n    # via -r requirements.in\n"
            ),
        }
    )
    by_file = {(d.manifest, d.name): d for d in result.deps}
    flask = by_file[("requirements.txt", "flask")]
    assert (flask.version, flask.direct, flask.scope, flask.line) == (
        "2.0.1",
        True,
        Scope.RUNTIME,
        1,
    )
    assert by_file[("requirements.txt", "jinja2")].version is None
    assert by_file[("requirements.txt", "jinja2")].spec == ">=3"
    assert by_file[("requirements-dev.txt", "black")].scope is Scope.DEV
    assert by_file[("requirements/test.txt", "pytest")].scope is Scope.TEST
    assert by_file[("compiled/requirements.txt", "click")].direct is False
    assert by_file[("compiled/requirements.txt", "flask")].direct is True


PYPROJECT = """
[project]
name = "demo"
dependencies = ["flask>=2", "requests"]
[project.optional-dependencies]
extra = ["rich"]
[dependency-groups]
test = ["pytest"]
dev = ["ruff"]
[tool.poetry.dependencies]
python = "^3.12"
django = "^4"
orm = { version = "1.0" }
[tool.poetry.group.dev.dependencies]
mypy = "*"
"""

UV_LOCK = """
[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "flask" }]
[package.dev-dependencies]
dev = [{ name = "ruff" }]
test = [{ name = "pytest" }]

[[package]]
name = "flask"
version = "3.0.0"
dependencies = [{ name = "Werkzeug" }]
[[package]]
name = "werkzeug"
version = "3.0.1"
[[package]]
name = "ruff"
version = "0.6.0"
[[package]]
name = "pytest"
version = "8.0.0"
dependencies = [{ name = "pluggy" }]
[[package]]
name = "pluggy"
version = "1.5.0"
[[package]]
name = "orphan"
version = "1.0.0"
"""


def test_pyproject_alone_gives_ranges_only() -> None:
    result = run({"svc/pyproject.toml": PYPROJECT})
    got = table(result.deps)
    assert got["flask"] == (None, True, "runtime")
    assert got["rich"] == (None, True, "runtime")
    assert got["pytest"] == (None, True, "test")
    assert got["ruff"] == (None, True, "dev")
    assert got["django"] == (None, True, "runtime")
    assert got["mypy"] == (None, True, "dev")
    assert "python" not in got
    assert next(d for d in result.deps if d.name == "orm").spec == "1.0"
    assert result.python_roots == ["svc", "svc/src"]


def test_uv_lock_scopes_by_reachability() -> None:
    result = run({"pyproject.toml": PYPROJECT, "uv.lock": UV_LOCK})
    locked = table([d for d in result.deps if d.manifest == "uv.lock"])
    assert locked == {
        "flask": ("3.0.0", True, "runtime"),
        "werkzeug": ("3.0.1", False, "runtime"),
        "ruff": ("0.6.0", True, "dev"),
        "pytest": ("8.0.0", True, "test"),
        "pluggy": ("1.5.0", False, "test"),
        "orphan": ("1.0.0", False, "unknown"),  # unreachable: never assumed dev-only
    }
    declared = {d.name for d in result.deps if d.manifest == "pyproject.toml"}
    assert "flask" not in declared and "requests" in declared  # kept: missing from the lock


def test_poetry_lock_variants() -> None:
    lock = (
        '[[package]]\nname = "django"\nversion = "4.2"\ncategory = "main"\n'
        '[package.dependencies]\nsqlparse = "*"\n'
        '[[package]]\nname = "sqlparse"\nversion = "0.5"\n'
        '[[package]]\nname = "mypy"\nversion = "1.0"\ngroups = ["dev"]\n'
        '[[package]]\nname = "both"\nversion = "1.0"\ngroups = ["main", "dev"]\n'
    )
    with_manifest = table(
        [d for d in run({"pyproject.toml": PYPROJECT, "poetry.lock": lock}).deps if d.version]
    )
    assert with_manifest["django"] == ("4.2", True, "runtime")
    assert with_manifest["sqlparse"] == ("0.5", False, "runtime")
    assert with_manifest["mypy"] == ("1.0", True, "dev")
    assert with_manifest["both"] == ("1.0", False, "runtime")
    alone = run({"poetry.lock": lock})
    assert table(alone.deps)["sqlparse"] == ("0.5", False, "unknown")
    assert all(d.note for d in alone.deps)


PACKAGE_JSON = json.dumps(
    {
        "dependencies": {"express": "^4.18.0", "@scope/lib": "1.x"},
        "devDependencies": {"jest": "^29"},
        "peerDependencies": {"react": "*"},
    },
    indent=1,
)


def test_package_json_and_lock_v3() -> None:
    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"express": "^4.18.0"}},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/@scope/lib": {"version": "1.2.0"},
                "node_modules/body-parser": {"version": "1.20.1"},
                "node_modules/jest": {"version": "29.7.0", "dev": True},
                "node_modules/jest/node_modules/express": {"version": "3.0.0", "dev": True},
                "node_modules/maybe": {"version": "1.0.0", "devOptional": True},
                "node_modules/linked": {"link": True},
                "packages/workspace-a": {"version": "0.0.1"},
            },
        },
        indent=1,
    )
    result = run({"package.json": PACKAGE_JSON, "package-lock.json": lock})
    rows = {(d.name, d.version): (d.direct, d.scope.value) for d in result.deps}
    assert rows == {
        ("express", "4.18.2"): (True, "runtime"),
        ("@scope/lib", "1.2.0"): (True, "runtime"),
        ("body-parser", "1.20.1"): (False, "runtime"),
        ("jest", "29.7.0"): (True, "dev"),
        ("express", "3.0.0"): (False, "dev"),  # nested copy is transitive
        ("maybe", "1.0.0"): (False, "unknown"),
        ("react", None): (True, "runtime"),  # declared, absent from the lock
    }
    assert next(d for d in result.deps if d.name == "body-parser").line == 15


def test_package_lock_v1_and_manifest_only() -> None:
    lock = json.dumps(
        {
            "dependencies": {
                "express": {"version": "4.0.0", "dependencies": {"qs": {"version": "6.0.0"}}},
                "jest": {"version": "29.0.0", "dev": True},
            }
        }
    )
    got = table(run({"package.json": PACKAGE_JSON, "npm-shrinkwrap.json": lock}).deps)
    assert got["express"] == ("4.0.0", True, "runtime")
    assert got["qs"] == ("6.0.0", False, "runtime")
    assert got["jest"] == ("29.0.0", True, "dev")
    only = table(run({"web/package.json": PACKAGE_JSON}).deps)
    assert only["express"] == (None, True, "runtime") and only["jest"] == (None, True, "dev")


def test_pnpm_lock_v9_and_v6() -> None:
    v9 = """
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      express: {specifier: ^4, version: 4.18.2}
      local: {specifier: 'workspace:*', version: link:../local}
    devDependencies:
      vitest: {specifier: ^1, version: 1.0.0(peer@1.0.0)}
packages:
  express@4.18.2: {}
  qs@6.11.0: {}
  vitest@1.0.0: {}
  '@scope/tool@2.0.0': {}
  stray@1.0.0: {}
snapshots:
  express@4.18.2:
    dependencies: {qs: 6.11.0}
  vitest@1.0.0(peer@1.0.0):
    dependencies: {'@scope/tool': 2.0.0}
"""
    assert table(run({"pnpm-lock.yaml": v9}).deps) == {
        "express": ("4.18.2", True, "runtime"),
        "qs": ("6.11.0", False, "runtime"),
        "vitest": ("1.0.0", True, "dev"),
        "@scope/tool": ("2.0.0", False, "dev"),
        "stray": ("1.0.0", False, "unknown"),
    }
    v6 = """
lockfileVersion: '6.0'
dependencies:
  express: {specifier: ^4, version: 4.18.2}
packages:
  /express@4.18.2: {dev: false}
  /@types/node@20.0.0: {dev: true}
"""
    assert table(run({"pnpm-lock.yaml": v6}).deps) == {
        "express": ("4.18.2", True, "runtime"),
        "@types/node": ("20.0.0", False, "dev"),
    }


GO_MOD = """module example.com/app

go 1.22

require github.com/single/dep v0.1.0
require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgolang.org/x/sys v0.15.0 // indirect
)
replace github.com/x => ../x
"""
GO_SUM = (
    "github.com/gin-gonic/gin v1.9.1 h1:a=\n"
    "github.com/gin-gonic/gin v1.9.1/go.mod h1:b=\n"
    "github.com/old/only-in-sum v0.0.1 h1:c=\n"
)


def test_go_mod_and_sum() -> None:
    result = run({"go.mod": GO_MOD, "go.sum": GO_SUM, "tools/go.mod": "module example.com/tools\n"})
    assert table(result.deps) == {
        "github.com/single/dep": ("v0.1.0", True, "runtime"),
        "github.com/gin-gonic/gin": ("v1.9.1", True, "runtime"),
        "golang.org/x/sys": ("v0.15.0", False, "runtime"),
    }
    assert result.go_modules == {"": "example.com/app", "tools": "example.com/tools"}
    # before Go 1.17 go.mod is incomplete, so go.sum-only modules are kept at low confidence
    old = run({"go.mod": GO_MOD.replace("go 1.22", "go 1.15"), "go.sum": GO_SUM})
    extra = next(d for d in old.deps if d.name == "github.com/old/only-in-sum")
    assert (extra.direct, extra.confidence, extra.manifest) == (False, 0.6, "go.sum")
    assert extra.note
    orphan = run({"go.sum": GO_SUM})
    assert {d.name for d in orphan.deps} == {
        "github.com/gin-gonic/gin",
        "github.com/old/only-in-sum",
    }


POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>org.demo</groupId><artifactId>parent</artifactId><version>1</version></parent>
  <version>2.0</version>
  <properties><spring.version>6.1.0</spring.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.managed</groupId><artifactId>lib</artifactId><version>9.9</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-web</artifactId>
      <version>${spring.version}</version></dependency>
    <dependency><groupId>com.managed</groupId><artifactId>lib</artifactId></dependency>
    <dependency><groupId>${project.groupId}</groupId><artifactId>sibling</artifactId>
      <version>${project.version}</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version>
      <scope>test</scope></dependency>
    <dependency><groupId>x</groupId><artifactId>unknown</artifactId><version>${nope}</version></dependency>
    <dependency><groupId>x</groupId><artifactId>inherited</artifactId></dependency>
  </dependencies>
</project>
"""


def test_pom() -> None:
    result = run({"pom.xml": POM})
    assert table(result.deps) == {
        "org.springframework:spring-web": ("6.1.0", True, "runtime"),
        "com.managed:lib": ("9.9", True, "runtime"),
        "org.demo:sibling": ("2.0", True, "runtime"),
        "junit:junit": ("4.13", True, "test"),
        "x:unknown": (None, True, "runtime"),
        "x:inherited": (None, True, "runtime"),
    }
    assert result.notes["pom.xml"] == [
        "parent_pom_not_resolved",
        "version_not_resolved:x:inherited",
        "version_not_resolved:x:unknown",
    ]
    assert next(d for d in result.deps if d.name == "x:unknown").spec == "${nope}"


def test_broken_unreadable_and_unsupported_manifests_become_notes() -> None:
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;">]><project>&lol2;</project>'
    )
    result = run(
        {
            "package.json": "{not json",
            "a/package.json": "[]",
            "a/package-lock.json": "{",
            "pyproject.toml": "= broken",
            "uv.lock": "[[",
            "pnpm-lock.yaml": "a: [",
            "b/pnpm-lock.yaml": "- list",
            "pom.xml": bomb,
            "c/pom.xml": "<project",
            "go.mod": None,
            "yarn.lock": "",
            "build.gradle": "",
        }
    )
    assert result.deps == []
    assert {p: n[0] for p, n in result.notes.items()} == {
        "package.json": "manifest_parse_error",
        "a/package.json": "manifest_parse_error",
        "a/package-lock.json": "manifest_parse_error",
        "pyproject.toml": "manifest_parse_error",
        "uv.lock": "manifest_parse_error",
        "pnpm-lock.yaml": "manifest_parse_error",
        "b/pnpm-lock.yaml": "manifest_parse_error",
        "pom.xml": "manifest_parse_error",
        "c/pom.xml": "manifest_parse_error",
        "go.mod": "manifest_unreadable_or_too_large",
        "yarn.lock": "manifest_format_not_supported",
        "build.gradle": "manifest_format_not_supported",
    }
    assert manifest_kind("src/app.py") is None


def test_credentials_in_dependency_urls_are_not_stored() -> None:
    result = run(
        {
            "requirements.txt": "priv @ https://user:s3cr3t-token@host.example/p.whl\n",
            "package.json": json.dumps(
                {"dependencies": {"lib": "git+https://x-token:ghp_abc123@github.com/o/lib.git"}}
            ),
            "pyproject.toml": '[tool.poetry.dependencies]\nq = "https://u:pw-123@h.example/q.whl"\n',
        }
    )
    specs = {d.name: d.spec for d in result.deps}
    assert specs == {
        "priv": "@ https://***@host.example/p.whl",
        "lib": "git+https://***@github.com/o/lib.git",
        "q": "https://***@h.example/q.whl",
    }
