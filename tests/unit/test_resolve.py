"""M1-AC5: import, inheritance and call resolution (exact / name_match / dynamic_unknown)."""

from __future__ import annotations

import pytest

from kurojisho.ingest.code.build import CodeGraph, build_code_graph
from kurojisho.ingest.code.parser import extract
from kurojisho.ingest.keys import container_key, file_key
from kurojisho.ingest.walker import LANG_BY_SUFFIX
from kurojisho.model import EdgeType, Provenance, node_id


class G:
    """Readable view of a CodeGraph: edges as (src key, dst key) -> edge."""

    def __init__(self, sources: dict[str, str], **kwargs: object) -> None:
        facts = {
            p: extract(LANG_BY_SUFFIX["." + p.rsplit(".", 1)[1]], s.encode())
            for p, s in sources.items()
        }
        hashes = dict.fromkeys(sources, "h")
        self.graph: CodeGraph = build_code_graph(hashes, facts, **kwargs)  # type: ignore[arg-type]
        keys = {n.id: n.key for n in self.graph.nodes}
        for path in sources:
            keys[node_id(file_key(path))] = file_key(path)
            parts = path.split("/")
            for i in range(len(parts)):
                directory = "/".join(parts[:i])
                keys[node_id(container_key(directory))] = container_key(directory)
        self.keys = keys
        self.nodes = {n.key: n for n in self.graph.nodes}

    def edges(self, kind: EdgeType) -> dict[tuple[str, str], object]:
        return {
            (self.keys[e.src].split(":", 1)[1], self.keys[e.dst].split(":", 1)[1]): e
            for e in self.graph.edges
            if e.type is kind
        }

    def calls(self) -> dict[tuple[str, str], str]:
        return {k: e.props["resolution"] for k, e in self.edges(EdgeType.CALLS).items()}  # type: ignore[attr-defined]

    def unresolved(self, key: str) -> list[str]:
        return self.nodes[key].props["calls_unresolved"]  # type: ignore[no-any-return]


def test_python_resolution() -> None:
    g = G(
        {
            "app/__init__.py": "",
            "app/util.py": "def helper(): pass\nclass Base:\n    def shared(self): pass\n",
            "app/models.py": (
                "from .util import Base\n"
                "class User(Base):\n"
                "    def __init__(self, n): self.n = n\n"
                "    def save(self): self.shared(); self.missing()\n"
            ),
            "app/views.py": (
                "import os\n"
                "import app.util as u\n"
                "from app import models\n"
                "from .util import helper as h\n"
                "from requests import get\n"
                "def get_local(): pass\n"
                "def view(cb, obj):\n"
                "    h(); u.helper(); models.User(1); obj.save(); cb(); get('u'); os.path.join()\n"
                "    fn = h\n"
                "    fn(); getattr(obj, 'x')(); unknown_fn(); view(cb, obj)\n"
                "    def nested(): pass\n"
                "    nested()\n"
                "view(None, None)\n"
            ),
            "other.py": "class Other:\n    def save(self): pass\n",
        }
    )
    calls = g.calls()
    v = "app/views.py::view"
    assert calls[(v, "app/util.py::helper")] == "exact"
    assert calls[(v, "app/models.py::User.__init__")] == "exact"
    assert calls[(v, "app/views.py::view")] == "exact"
    assert calls[(v, "app/views.py::view.nested")] == "exact"
    # unknown receiver type: every method named save is a candidate
    assert calls[(v, "app/models.py::User.save")] == "name_match"
    assert calls[(v, "other.py::Other.save")] == "name_match"
    assert calls[(v, "app/views.py::<dynamic>")] == "dynamic_unknown"
    assert calls[("app/views.py::<module>", v)] == "exact"
    # self.shared() resolves through the exactly-resolved base class
    assert calls[("app/models.py::User.save", "app/util.py::Base.shared")] == "exact"
    # an external import must never be name-matched onto repo functions
    assert (v, "app/views.py::get_local") not in calls
    assert g.unresolved("Function:" + v) == [
        "getattr",
        "os.path.join",
        "requests.get",
        "unknown_fn",
    ]
    assert g.unresolved("Function:app/models.py::User.save") == ["self.missing"]

    dyn = g.edges(EdgeType.CALLS)[(v, "app/views.py::<dynamic>")]
    assert dyn.props["reasons"] == ["getattr", "local_variable", "parameter"]  # type: ignore[attr-defined]
    assert dyn.confidence == 0.1 and dyn.provenance is Provenance.INFERRED  # type: ignore[attr-defined]
    nm = g.edges(EdgeType.CALLS)[(v, "other.py::Other.save")]
    assert nm.props["candidates"] == 2 and nm.confidence == 0.5  # type: ignore[attr-defined]

    imports = g.edges(EdgeType.IMPORTS)
    assert set(imports) == {
        ("app/models.py", "app/util.py"),
        ("app/views.py", "app/util.py"),
        ("app/views.py", "app/models.py"),
    }
    assert imports[("app/models.py", "app/util.py")].confidence == 1.0  # type: ignore[attr-defined]
    assert imports[("app/views.py", "app/models.py")].confidence == 0.9  # type: ignore[attr-defined]
    assert g.graph.file_props["app/views.py"]["imports_external"] == ["os", "requests"]
    inherits = g.edges(EdgeType.INHERITS)
    assert set(inherits) == {("app/models.py::User", "app/util.py::Base")}
    assert inherits[("app/models.py::User", "app/util.py::Base")].provenance is Provenance.EXTRACTED  # type: ignore[attr-defined]
    defines = g.edges(EdgeType.DEFINES)
    assert ("app/models.py::User", "app/models.py::User.save") in defines
    assert ("app/views.py::view", "app/views.py::view.nested") in defines
    assert ("app/views.py", "app/views.py::view") in defines


def test_python_star_import_src_root_and_name_matched_base() -> None:
    g = G(
        {
            "src/pkg/__init__.py": "",
            "src/pkg/a.py": "def star_fn(): pass\nclass Mixin: pass\n",
            "src/pkg/b.py": (
                "from pkg.a import *\n"
                "from thirdparty import *\n"
                "import pkg.a\n"
                "class K(Mixin, External): pass\n"
                "def f(): star_fn(); pkg.a.star_fn(); mystery()\n"
            ),
            "scripts/run.py": "import helper\nclass M(Mixin): pass\nhelper.go()\n",
            "scripts/helper.py": "def go(): pass\n",
        }
    )
    calls = g.calls()
    assert calls[("src/pkg/b.py::f", "src/pkg/a.py::star_fn")] == "exact"
    assert g.unresolved("Function:src/pkg/b.py::f") == ["mystery (possibly from a wildcard import)"]
    assert calls[("scripts/run.py::<module>", "scripts/helper.py::go")] == "exact"
    inherits = g.edges(EdgeType.INHERITS)
    assert inherits[("src/pkg/b.py::K", "src/pkg/a.py::Mixin")].props["resolution"] == "exact"  # type: ignore[attr-defined]
    loose = inherits[("scripts/run.py::M", "src/pkg/a.py::Mixin")]
    assert loose.props["resolution"] == "name_match"  # type: ignore[attr-defined]
    assert loose.provenance is Provenance.INFERRED and loose.confidence == 0.5  # type: ignore[attr-defined]
    assert g.nodes["Class:src/pkg/b.py::K"].props["bases_unresolved"] == ["External"]


def test_javascript_resolution() -> None:
    g = G(
        {
            "src/db.ts": (
                "export class Repo { save(x) {} static make() { return new Repo(); } }\n"
                "export class Sub extends Repo { constructor() { super(); } run() { this.save(1);"
                " super.save(2); } }\n"
                "export function connect() {}\n"
                "export default function main() {}\n"
            ),
            "src/index.ts": (
                "import main, { connect as c, Repo } from './db';\n"
                "import * as db from './db.js';\n"
                "import axios from 'axios';\n"
                "const legacy = require('./legacy');\n"
                "export function start(cb, svc) {\n"
                "  c(); db.connect(); Repo.make(); new db.Sub(); svc.save(1); cb(); main();\n"
                "  axios.get('/x'); legacy.run(); handlers[cb](); new Missing(); new Repo();\n"
                "}\n"
            ),
            "src/legacy/index.js": "exports.run = function () {};\n",
        }
    )
    calls = g.calls()
    s = "src/index.ts::start"
    assert calls[(s, "src/db.ts::connect")] == "exact"
    assert calls[(s, "src/db.ts::Repo.make")] == "exact"
    assert calls[(s, "src/db.ts::Sub.constructor")] == "exact"
    assert calls[(s, "src/db.ts::Repo.save")] == "name_match"
    assert calls[(s, "src/db.ts::main")] == "name_match"  # default import: alias is a hint only
    assert calls[(s, "src/legacy/index.js::run")] == "exact"
    assert calls[(s, "src/index.ts::<dynamic>")] == "dynamic_unknown"
    assert calls[("src/db.ts::Sub.run", "src/db.ts::Repo.save")] == "exact"
    assert g.unresolved("Function:" + s) == [
        "axios#default.get",
        "new Missing",
        "new Repo (no explicit constructor)",
    ]
    assert set(g.edges(EdgeType.IMPORTS)) == {
        ("src/index.ts", "src/db.ts"),
        ("src/index.ts", "src/legacy/index.js"),
    }
    assert g.graph.file_props["src/index.ts"]["imports_external"] == ["axios"]
    assert ("src/db.ts::Sub", "src/db.ts::Repo") in g.edges(EdgeType.INHERITS)


def test_go_resolution() -> None:
    g = G(
        {
            "main.go": (
                'package main\nimport ( "fmt"; "example.com/app/store"\n'
                'st "example.com/app/store" )\n'
                "func main() { helper(); store.Open(); st.Open(); fmt.Println()\n"
                "s := &Svc{}; s.Run() }\n"
            ),
            "util.go": (
                "package main\ntype Base struct{}\nfunc (b *Base) Log() {}\n"
                "type Svc struct{ Base }\nfunc helper() {}\n"
            ),
            "svc.go": "package main\nfunc (s *Svc) Run() { s.step(); s.Log(); s.gone() }\n"
            "func (s *Svc) step() {}\n",
            "store/store.go": "package store\nfunc Open() {}\n",
            "vendor/x/x.go": "package x\nfunc (t T) Run() {}\n",
        },
        go_modules={"": "example.com/app"},
    )
    calls = g.calls()
    assert calls[("main.go::main", "util.go::helper")] == "exact"  # same package, other file
    assert calls[("main.go::main", "store/store.go::Open")] == "exact"
    assert calls[("main.go::main", "svc.go::Svc.Run")] == "name_match"
    assert calls[("main.go::main", "vendor/x/x.go::T.Run")] == "name_match"
    assert calls[("svc.go::Svc.Run", "svc.go::Svc.step")] == "exact"
    assert calls[("svc.go::Svc.Run", "util.go::Base.Log")] == "exact"  # promoted via embedding
    assert g.unresolved("Function:main.go::main") == ["fmt.Println"]
    assert g.unresolved("Function:svc.go::Svc.Run") == ["s.gone"]
    assert set(g.edges(EdgeType.IMPORTS)) == {("main.go", "store")}  # Go imports a package dir
    assert g.graph.file_props["main.go"]["imports_external"] == ["fmt"]
    # a method defined in another file of the package hangs off its receiver type
    assert ("util.go::Svc", "svc.go::Svc.Run") in g.edges(EdgeType.DEFINES)
    assert ("vendor/x/x.go", "vendor/x/x.go::T.Run") in g.edges(EdgeType.DEFINES)
    assert ("util.go::Svc", "util.go::Base") in g.edges(EdgeType.INHERITS)


def test_java_resolution() -> None:
    g = G(
        {
            "src/com/x/A.java": (
                "package com.x;\nimport com.y.Foo;\nimport static com.y.Foo.util;\n"
                "import org.ext.Lib;\n"
                "public class A extends Base {\n"
                "  A() {}\n  A(int n) {}\n"
                "  void m(Other o) { helper(); inherited(); this.helper(); Foo.s(); new Foo(1);"
                " util(); o.run(); Lib.call(); new A(1); Peer.go(); }\n"
                "  void helper() {}\n  void helper(int n) {}\n}\n"
            ),
            "src/com/x/Base.java": "package com.x;\nclass Base { void inherited() {} }\n",
            "src/com/x/Peer.java": "package com.x;\nclass Peer { static void go() {} }\n",
            "src/com/y/Foo.java": (
                "package com.y;\npublic class Foo { public Foo(int n) {} public static void s() {}"
                " public static void util() {} public void run() {} }\n"
            ),
        }
    )
    calls = g.calls()
    m = "src/com/x/A.java::A.m"
    assert calls[(m, "src/com/x/A.java::A.helper")] == "exact"  # arity picks the overload
    assert (m, "src/com/x/A.java::A.helper#2") not in calls
    assert calls[(m, "src/com/x/Base.java::Base.inherited")] == "exact"
    assert calls[(m, "src/com/y/Foo.java::Foo.s")] == "exact"
    assert calls[(m, "src/com/y/Foo.java::Foo.<init>")] == "exact"
    assert calls[(m, "src/com/y/Foo.java::Foo.util")] == "exact"  # static import
    assert calls[(m, "src/com/y/Foo.java::Foo.run")] == "name_match"
    assert calls[(m, "src/com/x/A.java::A.<init>#2")] == "exact"
    assert calls[(m, "src/com/x/Peer.java::Peer.go")] == "exact"  # same package, no import
    assert g.unresolved("Function:" + m) == ["org.ext.Lib.call"]
    assert set(g.edges(EdgeType.IMPORTS)) == {("src/com/x/A.java", "src/com/y/Foo.java")}
    assert ("src/com/x/A.java::A", "src/com/x/Base.java::Base") in g.edges(EdgeType.INHERITS)


def test_routes_become_nodes_with_evidence() -> None:
    g = G(
        {
            "app.py": (
                "from flask import Flask\napp = Flask(__name__)\n"
                "@app.route('/a')\ndef a(): pass\n@app.route('/a')\ndef a2(): pass\n"
            )
        }
    )
    first = g.nodes["Route:app.py::GET /a"]
    second = g.nodes["Route:app.py::GET /a#2"]
    assert first.props["handler"] == "a" and second.props["handler"] == "a2"
    assert first.props["framework"] == "flask" and first.provenance is Provenance.EXTRACTED
    assert first.evidence[0].start_line == 3
    assert ("app.py", "app.py::GET /a") in g.edges(EdgeType.DEFINES)


@pytest.mark.parametrize("order", [1, -1])
def test_output_does_not_depend_on_input_order(order: int) -> None:
    sources = {
        "a.py": "from b import f\ndef g(): f(); x.f()\n",
        "b.py": "def f(): pass\nclass C:\n    def f(self): pass\n",
        "c.py": "class D:\n    def f(self): pass\n",
    }
    ordered = dict(sorted(sources.items(), reverse=order < 0))
    g = G(ordered)
    reference = G(sources)
    assert [n.row_hash() for n in g.graph.nodes] == [n.row_hash() for n in reference.graph.nodes]
    assert [e.row_hash() for e in g.graph.edges] == [e.row_hash() for e in reference.graph.edges]


def test_inheritance_cycles_terminate() -> None:
    g = G({"a.py": "class A(B):\n    def m(self): self.nope()\nclass B(A): pass\n"})
    assert g.unresolved("Function:a.py::A.m") == ["self.nope"]


def test_very_common_names_become_dynamic_instead_of_fanning_out() -> None:
    sources = {f"m{i}.py": f"class C{i}:\n    def step(self): pass\n" for i in range(21)}
    sources["main.py"] = "def go(x):\n    x.step()\n"
    sources["sub.py"] = "class K(Shared): pass\n"
    sources.update({f"s{i}.py": "class Shared: pass\n" for i in range(21)})
    g = G(sources)
    assert g.calls() == {("main.py::go", "main.py::<dynamic>"): "dynamic_unknown"}
    edge = g.edges(EdgeType.CALLS)[("main.py::go", "main.py::<dynamic>")]
    assert edge.props["reasons"] == ["too_many_candidates"]  # type: ignore[attr-defined]
    assert g.unresolved("Function:main.py::go") == ["step (21 candidates)"]
    assert g.edges(EdgeType.INHERITS) == {}
    assert g.nodes["Class:sub.py::K"].props["bases_unresolved"] == ["Shared (21 candidates)"]


def test_java_wildcard_static_and_nested_imports() -> None:
    g = G(
        {
            "a/com/x/Main.java": (
                "package com.x;\nimport com.y.*;\nimport static com.y.Util.*;\n"
                "import com.y.Outer.Inner;\nimport static org.ext.Lib.*;\n"
                "class Main { void m() { Helper.run(); twice(); Inner.go(); new Outer.Inner();"
                " mystery(); } }\n"
            ),
            "a/com/y/Helper.java": "package com.y;\npublic class Helper { static void run() {} }\n",
            "a/com/y/Util.java": "package com.y;\npublic class Util { static void twice() {} }\n",
            "a/com/y/Outer.java": (
                "package com.y;\npublic class Outer { public static class Inner {"
                " Inner() {} static void go() {} } }\n"
            ),
        }
    )
    calls = g.calls()
    m = "a/com/x/Main.java::Main.m"
    assert calls[(m, "a/com/y/Helper.java::Helper.run")] == "exact"
    assert calls[(m, "a/com/y/Util.java::Util.twice")] == "exact"
    assert calls[(m, "a/com/y/Outer.java::Outer.Inner.go")] == "exact"
    assert calls[(m, "a/com/y/Outer.java::Outer.Inner.<init>")] == "exact"
    assert g.unresolved("Function:" + m) == ["mystery (possibly from a wildcard import)"]
    assert {dst for _, dst in g.edges(EdgeType.IMPORTS)} == {
        "a/com/y/Helper.java",
        "a/com/y/Outer.java",
        "a/com/y/Util.java",
    }


def test_imports_that_escape_the_repo_or_miss_are_external() -> None:
    g = G(
        {
            "pkg/a.py": "from ... import nothing\nfrom .missing import x\nfrom . import sibling\n"
            "import pkg\nx(); nothing(); sibling.f(); pkg.top()\n",
            "pkg/__init__.py": "def top(): pass\n",
            "pkg/sibling.py": "def f(): pass\n",
            "web/a.ts": "import { up } from '../../outside';\nimport json from './data.json';\n"
            "import self from './a';\nup(); json(); self();\n",
        }
    )
    calls = g.calls()
    assert calls == {
        ("pkg/a.py::<module>", "pkg/sibling.py::f"): "exact",
        ("pkg/a.py::<module>", "pkg/__init__.py::top"): "exact",
    }
    assert g.graph.file_props["pkg/a.py"]["imports_external"] == ["...", ".missing"]
    assert g.graph.file_props["pkg/a.py"]["calls_unresolved"] == ["...nothing", ".missing.x"]
    assert g.graph.file_props["web/a.ts"]["imports_external"] == [
        "../../outside",
        "./a",
        "./data.json",
    ]
    assert set(g.edges(EdgeType.IMPORTS)) == {
        ("pkg/a.py", "pkg/sibling.py"),
        ("pkg/a.py", "pkg/__init__.py"),
    }
