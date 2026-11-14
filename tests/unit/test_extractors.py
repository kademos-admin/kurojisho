"""M1-AC5: per-language extraction of definitions, imports, calls and routes."""

from __future__ import annotations

from kurojisho.ingest.code.extract import FileFacts
from kurojisho.ingest.code.parser import extract

PY = b"""
import os, importlib
import x.y as z
from flask import Flask
from .a import b as c, d
from .. import pkg
from m import *
app = Flask(__name__)
class A(B, m.C, metaclass=M):
    def __init__(self, v: int = 1): self.v = v
    @app.route("/x/<id>", methods=["post", "GET"])
    async def f(self, a, *b, k=1, **kw) -> int:
        h = pick()
        getattr(self, a)(1); self.g(); z.h(); c(); h(); a(); handlers[a](); eval("1")
        importlib.import_module(a)
        def inner(q: int): return d(q)
        return inner
    @app.get(f"/dyn/{x}")
    def _g(self): pass
    @app.route("/m", methods=METHODS)
    def m(self): pass
def top(cb): return [cb(i) for i in A().f()]
"""

TS = b"""
import d, { a as b } from './m';
import * as ns from "../n";
import express from 'express';
import './side';
const r = require('./r'); const { q, w: ww } = require('x');
export class A extends ns.B implements I<J> {
  private m(x: number, cb): void { this.k(); obj[k](); new C(1); ns.f(); cb();
    const loc = pick(); loc(); b(); super.m(); f.call(this); new ns.D(); }
  static s() {} #p() {} h = (e?: E) => { q(e); }
  constructor(private x: X) { super(); }
  [computed]() {}
}
export const f = async (a, cb) => { cb(); [1].map(v => g(v)); };
function g() { (function(){ inner(); })(); eval("1"); require(name); import(name);
  new Function("x"); import('./lazy'); mk()(); }
exports.foo = function (a) {};
const o = { k: function() {}, m2() {}, n: async () => {} };
app.get('/x', auth, handler); router.post(`/y`, ctrl.create); m.get('key');
app.all('/z', (req, res) => { res.send(render(req)); });
export default function h() {}
export { x } from './re';
interface K extends L {}
"""

GO = b"""package main
import ( "net/http"; u "example.com/m/util"; . "example.com/m/dot"; _ "embed"; "reflect" )
type S struct { Base; *pkg.Other; n int }
type I interface { M(); io.Reader }
type Alias = int
func (s *S) M(a int, cb func()) error { u.F(); s.h(); helper(); cb(); x := mk(); x()
  reflect.ValueOf(s).MethodByName("M").Call(nil); handlers["a"](); func(){ deep() }(); return nil }
func main() { http.HandleFunc("/x", h); http.HandleFunc("POST /p", srv.Create); r.GET("/y", h2)
  mux.Handle("/s", http.FileServer(d)); m.Get("k"); var v = 1 }
"""

JAVA = b"""package com.x;
import com.y.Foo; import static com.y.U.util; import com.z.*; import java.lang.reflect.Method;
import org.springframework.web.bind.annotation.GetMapping;
@RestController @RequestMapping("/api")
public class A extends B<T> implements C, com.q.D {
  public A(int x) { this(); }
  A() {}
  @GetMapping("/x") public String m(int a, String... rest) { this.k(); Foo.s(); new Foo(1);
    helper(a); list.forEach(this::k); mth.invoke(o); Class.forName(n); return o.toString(); }
  @RequestMapping(value = "/y", method = RequestMethod.POST) void n() { Runnable r = () -> k(); }
  @PostMapping private void p() {}
  @GetMapping(PATH) protected void dyn() {}
  static class Inner { void z() {} }
}
interface C { void q(); }
enum E { X; void e() {} }
"""


def defs(f: FileFacts) -> dict[str, tuple[str, str, str | None]]:
    return {d.qualname: (d.subkind, d.visibility, d.parent) for d in f.defs}


def calls(f: FileFacts) -> set[tuple[str | None, str, str, str]]:
    return {(c.caller, c.kind, c.receiver, c.name) for c in f.calls}


def imports(f: FileFacts) -> set[tuple[str, str | None, str, int]]:
    return {(i.module, i.name, i.alias, i.level) for i in f.imports}


def routes(f: FileFacts) -> set[tuple[str, str, str | None]]:
    return {(r.method, r.path, r.handler) for r in f.routes}


def test_python() -> None:
    f = extract("python", PY)
    assert defs(f) == {
        "A": ("class", "public", None),
        "A.__init__": ("constructor", "public", "A"),
        "A.f": ("method", "public", "A"),
        "A.f.inner": ("function", "public", "A.f"),
        "A._g": ("method", "private", "A"),
        "A.m": ("method", "public", "A"),
        "top": ("function", "public", None),
    }
    a_f = next(d for d in f.defs if d.qualname == "A.f")
    assert a_f.params == ["self", "a", "b", "k", "kw"] and a_f.local_names == ["h"]
    assert a_f.signature == "(self, a, *b, k=1, **kw) -> int"
    assert (a_f.start_line, a_f.end_line) == (11, 17)  # span includes the decorator
    assert next(d for d in f.defs if d.qualname == "A").bases == ["B", "m.C"]
    assert imports(f) >= {
        ("os", None, "", 0),
        ("x.y", None, "z", 0),
        ("a", "b", "c", 1),
        ("a", "d", "d", 1),
        ("", "pkg", "pkg", 2),
        ("m", "*", "", 0),
    }
    got = calls(f)
    assert {
        ("A.f", "attr", "self", "g"),
        ("A.f", "attr", "z", "h"),
        ("A.f", "name", "", "c"),
        ("A.f", "dynamic", "", "getattr"),
        ("A.f", "dynamic", "", "subscript"),
        ("A.f", "dynamic", "", "eval"),
        ("A.f", "dynamic", "", "import_module"),
        ("A.f.inner", "name", "", "d"),
        ("top", "name", "", "cb"),
        ("top", "attr", "", "f"),
        (None, "name", "", "Flask"),
    } <= got
    assert routes(f) == {
        ("GET", "/x/<id>", "A.f"),
        ("POST", "/x/<id>", "A.f"),
        ("ANY", "/m", "A.m"),
    }
    assert f.framework == "flask"
    assert f.notes == ["route_methods_not_literal:20", "route_path_not_literal:18"]
    assert f.parse_error_lines == []


def test_typescript() -> None:
    f = extract("typescript", TS)
    got = defs(f)
    assert got["A"] == ("class", "public", None)
    assert got["A.m"] == ("method", "private", "A")
    assert got["A.#p"] == ("method", "private", "A")
    assert got["A.h"] == ("method", "public", "A")
    assert got["A.constructor"] == ("constructor", "public", "A")
    assert got["f"] == ("function", "public", None)
    assert got["g"] == ("function", "module", None)
    assert got["foo"] == ("function", "public", None)
    assert got["K"] == ("interface", "module", None)
    assert {"k", "m2", "n", "h"} <= set(got)
    assert next(d for d in f.defs if d.qualname == "A").bases == ["ns.B", "I"]
    a_m = next(d for d in f.defs if d.qualname == "A.m")
    assert a_m.params == ["x", "cb"] and a_m.local_names == ["loc"]
    assert imports(f) >= {
        ("./m", "default", "d", 0),
        ("./m", "a", "b", 0),
        ("../n", None, "ns", 0),
        ("./side", None, "", 0),
        ("./r", None, "r", 0),
        ("x", "w", "ww", 0),
        ("./lazy", None, "", 0),
        ("./re", None, "", 0),
    }
    got_calls = calls(f)
    assert {
        ("A.m", "attr", "this", "k"),
        ("A.m", "dynamic", "", "computed_member"),
        ("A.m", "new", "", "C"),
        ("A.m", "new", "ns", "D"),
        ("A.m", "attr", "super", "m"),
        ("A.m", "name", "", "f"),  # f.call(this)
        ("A.h", "name", "", "q"),
        ("A.constructor", "attr", "super", "constructor"),
        ("f", "name", "", "g"),  # inside an anonymous callback
        ("g", "name", "", "inner"),  # inside an IIFE
        ("g", "dynamic", "", "eval"),
        ("g", "dynamic", "", "require"),
        ("g", "dynamic", "", "import"),
        ("g", "dynamic", "", "Function"),
        ("g", "dynamic", "", "call_result"),
        (None, "name", "", "render"),
    } <= got_calls
    assert routes(f) == {
        ("GET", "/x", "handler"),
        ("POST", "/y", "ctrl.create"),
        ("ANY", "/z", None),
    }
    assert f.framework == "express"
    assert f.notes == ["computed_method_name:12"]


def test_javascript_and_tsx_grammars() -> None:
    js = extract("javascript", b"class A extends B { m() { return <div onClick={() => go()}/>; } }")
    assert defs(js) == {"A": ("class", "module", None), "A.m": ("method", "public", "A")}
    assert ("A.m", "name", "", "go") in calls(js)
    tsx = extract("tsx", b"export const C = (p: P) => <b>{fmt(p)}</b>;")
    assert defs(tsx) == {"C": ("function", "public", None)}
    assert ("C", "name", "", "fmt") in calls(tsx)


def test_go() -> None:
    f = extract("go", GO)
    assert defs(f) == {
        "S": ("struct", "public", None),
        "I": ("interface", "public", None),
        "S.M": ("method", "public", "S"),
        "main": ("function", "package", None),
    }
    assert next(d for d in f.defs if d.qualname == "S").bases == ["Base", "Other"]
    method = next(d for d in f.defs if d.qualname == "S.M")
    assert (method.receiver, method.params, method.local_names) == ("s", ["a", "cb"], ["x"])
    assert next(d for d in f.defs if d.qualname == "main").local_names == ["v"]
    assert imports(f) == {
        ("net/http", None, "", 0),
        ("example.com/m/util", None, "u", 0),
        ("example.com/m/dot", "*", "", 0),
        ("embed", None, "_", 0),
        ("reflect", None, "", 0),
    }
    assert {
        ("S.M", "attr", "u", "F"),
        ("S.M", "attr", "s", "h"),
        ("S.M", "name", "", "helper"),
        ("S.M", "name", "", "deep"),
        ("S.M", "dynamic", "", "MethodByName"),
        ("S.M", "dynamic", "", "Call"),
        ("S.M", "dynamic", "", "index"),
    } <= calls(f)
    assert routes(f) == {
        ("ANY", "/x", "h"),
        ("POST", "/p", "srv.Create"),
        ("GET", "/y", "h2"),
        ("ANY", "/s", None),
    }
    assert (f.package, f.framework) == ("main", "net/http")


def test_java() -> None:
    f = extract("java", JAVA)
    got = defs(f)
    assert got["A"] == ("class", "public", None)
    assert got["A.<init>"] == ("constructor", "public", "A")
    assert got["A.<init>#2"] == ("constructor", "package", "A")  # overloads stay distinct
    assert got["A.m"] == ("method", "public", "A")
    assert got["A.p"] == ("method", "private", "A")
    assert got["A.dyn"] == ("method", "protected", "A")
    assert got["A.Inner.z"] == ("method", "package", "A.Inner")
    assert got["C"] == ("interface", "package", None)
    assert got["C.q"] == ("method", "public", "C")
    assert got["E"] == ("enum", "package", None)
    assert next(d for d in f.defs if d.qualname == "A").bases == ["B", "C", "D"]
    assert next(d for d in f.defs if d.qualname == "A.m").params == ["a", "rest"]
    assert {(i.module, i.name, i.kind) for i in f.imports} >= {
        ("com.y", "Foo", ""),
        ("com.y.U", "util", "static"),
        ("com.z", "*", ""),
    }
    assert {
        ("A.m", "attr", "this", "k"),
        ("A.m", "attr", "Foo", "s"),
        ("A.m", "new", "", "Foo"),
        ("A.m", "name", "", "helper"),
        ("A.m", "dynamic", "", "invoke"),
        ("A.m", "dynamic", "", "forName"),
        ("A.n", "name", "", "k"),  # inside a lambda
    } <= calls(f)
    assert routes(f) == {
        ("GET", "/api/x", "A.m"),
        ("POST", "/api/y", "A.n"),
        ("POST", "/api", "A.p"),
    }
    assert (f.package, f.framework) == ("com.x", "spring")
    assert f.notes == ["route_path_not_literal:12"]


def test_syntax_errors_are_recorded_not_raised() -> None:
    f = extract("python", b"def ok():\n    pass\n\ndef broken(:\n    x = \n")
    assert "ok" in defs(f)
    assert f.parse_error_lines and all(n >= 4 for n in f.parse_error_lines)
    assert extract("go", b"\xff\xfe not go at all {{{").parse_error_lines


def test_deep_nesting_does_not_overflow_the_stack() -> None:
    source = b"x = " + b"(" * 3000 + b"f()" + b")" * 3000 + b"\n"
    f = extract("python", source)
    assert (None, "name", "", "f") in calls(f) or f.parse_error_lines


def test_facts_round_trip_and_are_deterministic() -> None:
    for lang, src in (("python", PY), ("typescript", TS), ("go", GO), ("java", JAVA)):
        first = extract(lang, src)
        assert first.to_json() == extract(lang, src).to_json()
        assert FileFacts.from_json(first.to_json()).to_json() == first.to_json()


def test_string_literals_never_reach_signatures_or_decorators() -> None:
    """Golden rule: raw secret values must not be stored, wherever they are written."""
    secret = "sk_live_51HdeadbeefDEADBEEF"
    sources = {
        "python": f"@auth(key='{secret}')\ndef f(token=\"{secret}\", n=1): pass\n",
        "typescript": f"function f(token = '{secret}', t = `{secret}`) {{}}\n",
        "go": f'package p\nfunc f(a string) string {{ return "{secret}" }}\n',
        "java": f'class A {{ @Auth("{secret}") void f(String t) {{}} }}\n',
    }
    for lang, source in sources.items():
        facts = extract(lang, source.encode())
        stored = [d.signature for d in facts.defs] + [x for d in facts.defs for x in d.decorators]
        assert stored and secret not in facts.to_json(), lang
    py = extract("python", sources["python"].encode()).defs[0]
    assert py.signature == '(token="…", n=1)' and py.decorators == ['auth(key="…")']
