"""M3-AC5: taint from sources to sinks, across calls, with sanitizers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tests.helpers import Graph

FLASK = "from flask import Flask, request\napp = Flask(__name__)\n"


def flows(graph: Graph) -> list[tuple[str, str, dict[str, Any]]]:
    return [
        (src.split("::")[1], dst.split("::")[-1], props)
        for src, dst, props in graph.edges("FLOWS_TO")
    ]


def one(tmp_path: Path, body: str, name: str = "app.py", head: str = FLASK) -> list[Any]:
    return flows(Graph(tmp_path, {name: head + body}))


def test_direct_flow_through_assignments_and_string_building(tmp_path: Path) -> None:
    found = one(
        tmp_path,
        """
import subprocess
@app.route("/ping")
def ping():
    host = request.args["host"]
    cmd = f"ping -c 1 {host}"
    full = cmd + " -W 1"
    return subprocess.run(full, shell=True)
""",
    )
    assert [(f, s, p["cwe"], p["sanitized"]) for f, s, p in found] == [
        ("ping", "subprocess.run", "CWE-78", "none")
    ]
    assert found[0][2]["_provenance"] == "INFERRED" and found[0][2]["_confidence"] == 0.9


def test_constant_arguments_and_parameterised_queries_do_not_flow(tmp_path: Path) -> None:
    found = one(
        tmp_path,
        """
import subprocess
@app.route("/x")
def x():
    name = request.args["name"]
    subprocess.run("uptime", shell=True)
    db.execute("SELECT * FROM t WHERE name = ?", (name,))
    return name
""",
    )
    assert found == []


def test_flow_across_functions_and_files_records_the_route(tmp_path: Path) -> None:
    graph = Graph(
        tmp_path,
        {
            "app.py": FLASK
            + """
from store import lookup
@app.route("/u")
def user():
    return lookup(request.args.get("id"))
""",
            "store.py": """
def lookup(user_id):
    query = "SELECT * FROM u WHERE id = " + user_id
    return run(query)

def run(sql):
    return conn.execute(sql)
""",
        },
    )
    ((func, sink, props),) = flows(graph)
    assert (func, sink) == ("user", "execute")
    assert props["via"] == ["app.py::user", "store.py::lookup", "store.py::run"]
    # The sink is matched by method name only, so the flow is no better than that.
    assert props["_confidence"] == 0.5


def test_value_returned_by_a_helper_is_tainted(tmp_path: Path) -> None:
    found = one(
        tmp_path,
        """
import os
def param():
    return request.args["p"]

@app.route("/x")
def x():
    os.system("ls " + param())
""",
    )
    assert [(f, s) for f, s, _ in found] == [("param", "os.system")]


def test_strong_sanitizer_on_the_only_path(tmp_path: Path) -> None:
    graph = Graph(
        tmp_path,
        {
            "app.py": FLASK
            + """
import os, shlex
@app.route("/x")
def x():
    safe = shlex.quote(request.args["p"])
    os.system("ls " + safe)
"""
        },
    )
    ((_, _, props),) = flows(graph)
    assert props["sanitized"] == "strong" and props["sanitized_by"] == ["shlex.quote"]
    assert props["sanitizer_confidence"] == 0.9
    (sanitizer,) = graph.nodes("Sanitizer").values()
    assert sanitizer["strength"] == "strong" and sanitizer["_provenance"] == "EXTRACTED"


def test_sanitizer_on_one_of_two_paths_is_not_all_paths(tmp_path: Path) -> None:
    found = one(
        tmp_path,
        """
import os, shlex
@app.route("/x")
def x():
    raw = request.args["p"]
    value = shlex.quote(raw)
    if request.args.get("fast"):
        value = raw
    os.system("ls " + value)
""",
    )
    assert {p["sanitized"] for _, _, p in found} == {"partial"}
    assert all(p["sanitizer_confidence"] == 0.0 for _, _, p in found)


def test_sanitizer_for_another_weakness_and_partial_ones_do_not_count(tmp_path: Path) -> None:
    found = one(
        tmp_path,
        """
import html, os
@app.route("/x")
def x():
    os.system("ls " + html.escape(request.args["p"]))
    open(os.path.basename(request.args["f"]))
""",
    )
    by_sink = {s: p for _, s, p in found}
    assert by_sink["os.system"]["sanitized"] == "none"  # html.escape does not stop CWE-78
    assert by_sink["open"]["sanitized"] == "partial"
    assert by_sink["open"]["sanitized_by"] == ["os.path.basename"]


def test_handler_parameters_are_sources_in_every_language(tmp_path: Path) -> None:
    graph = Graph(
        tmp_path,
        {
            "go.mod": "module example.com/m\n",
            "main.go": """package main

import (
	"net/http"
	"os/exec"
	"strconv"
)

func run(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", r.URL.Query().Get("cmd")).Run()
}

func safe(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	exec.Command("sleep", n).Run()
}

func main() {
	http.HandleFunc("/run", run)
	http.HandleFunc("/safe", safe)
}
""",
            "src/main/java/demo/Api.java": """package demo;
import org.springframework.web.bind.annotation.GetMapping;
class Api {
    @GetMapping("/find")
    public Object find(String name) {
        String q = "SELECT * FROM t WHERE n = '" + name + "'";
        return stmt.executeQuery(q);
    }
}
""",
            "server.ts": """import express from "express";
import { exec } from "child_process";
const app = express();
app.post("/run", (req, res) => {
  const { cmd } = req.body;
  exec(cmd);
});
""",
        },
    )
    got = {(f, s): p["sanitized"] for f, s, p in flows(graph)}
    assert got[("run", "os/exec.Command")] == "none"
    assert got[("safe", "os/exec.Command")] == "strong"
    assert got[("Api.find", "executeQuery")] == "none"
    assert got[("<POST /run>", "child_process.exec")] == "none"
    assert not any(s == "Query" for _, s in got)  # r.URL.Query() is not a database call


def test_sinks_are_recorded_even_without_a_flow(tmp_path: Path) -> None:
    graph = Graph(
        tmp_path, {"lib.py": "import pickle\ndef load(blob):\n    return pickle.loads(blob)\n"}
    )
    assert flows(graph) == []
    (sink,) = graph.nodes("Sink").values()
    assert (sink["cwe"], sink["function"], sink["match"]) == ("CWE-502", "load", "exact")


def test_own_function_named_like_a_sink_is_followed_not_guessed(tmp_path: Path) -> None:
    found = one(
        tmp_path,
        """
def execute(text):
    return text.upper()

@app.route("/x")
def x():
    return execute(request.args["q"])
""",
    )
    assert found == []


def test_recursion_and_deep_chains_terminate(tmp_path: Path) -> None:
    chain = "".join(f"def f{i}(v):\n    return f{i + 1}(v)\n" for i in range(30))
    body = (
        chain
        + """
import os
def f30(v):
    os.system(v)
    return f0(v)

@app.route("/x")
def x():
    f25(request.args["q"])
"""
    )
    found = one(tmp_path, body)
    assert [(f, s) for f, s, _ in found] == [("x", "os.system")]
    assert len(found[0][2]["via"]) == 7
