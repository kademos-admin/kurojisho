"""M3-AC4: entry points per framework, their handlers, and the controls that guard them."""

from __future__ import annotations

from pathlib import Path

import pytest

from kurojisho.enrich.catalogue import CatalogueError, alias_map, parse_catalogue, qualify
from kurojisho.ingest.code.parser import extract
from tests.helpers import Graph

FASTAPI = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/items/{item_id}")
def read_item(item_id: str, user=Depends(get_current_user)):
    return item_id

@app.post("/hooks/webhook/stripe")
def stripe(payload: dict):
    return payload
"""

DJANGO_URLS = """
from django.urls import path
from . import views

urlpatterns = [
    path("orders/", views.orders),
    path("reports/", views.Report.as_view()),
]
"""
DJANGO_VIEWS = """
from django.contrib.auth.decorators import login_required
from django.views import View

@login_required
def orders(request):
    return request.GET["q"]

class Report(View):
    def get(self, request):
        return 1
    def helper(self):
        return 2
"""

NEST = """
import { Controller, Get, Post, UseGuards } from "@nestjs/common";
import { Cron } from "@nestjs/schedule";

@Controller("cats")
export class CatsController {
  @Get(":id")
  @UseGuards(AuthGuard)
  one(id) { return id; }

  @Post()
  add(body) { return body; }

  @Cron("0 * * * *")
  sweep() { return 1; }
}
"""

EXPRESS = """
const express = require("express");
const passport = require("passport");
const app = express();
app.get("/open", (req, res) => res.send("x"));
app.get("/me", passport.authenticate("jwt"), (req, res) => res.send("x"));
app.get("/admin", requireAdmin, adminPage);
function adminPage(req, res) { res.send("x"); }
"""

GIN = """package main

import "github.com/gin-gonic/gin"

func list(c *gin.Context) {}

func main() {
	r := gin.Default()
	r.GET("/items", AuthRequired(), list)
	r.Run()
}
"""

SPRING = """
package demo;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import jakarta.annotation.security.PermitAll;

class Api {
    @GetMapping("/secure") @PreAuthorize("hasRole('ADMIN')")
    public String secure() { return "x"; }
    @GetMapping("/open") @PermitAll
    public String open() { return "x"; }
    @KafkaListener(topics = "orders")
    public void consume(String message) {}
    @Scheduled(fixedRate = 5000)
    public void tick() {}
    public static void main(String[] args) {}
}
"""

CELERY = """
import click
from celery import shared_task

@shared_task
def resize(image_id):
    return image_id

@click.command()
def cli(name):
    return name

def plain():
    return 1
"""


def kinds(graph: Graph) -> dict[str, tuple[str, str]]:
    return {
        key.split("::", 1)[1]: (props["kind"], props["auth_required"])
        for key, props in graph.nodes("EntryPoint").items()
    }


def test_fastapi_routes_dependencies_and_webhooks(tmp_path: Path) -> None:
    graph = Graph(tmp_path, {"main.py": FASTAPI})
    assert kinds(graph) == {
        "http GET /items/{item_id}": ("http", "true"),
        "webhook POST /hooks/webhook/stripe": ("webhook", "unknown"),
    }
    guarded = graph.edges("GUARDED_BY")
    # A dependency matched by its name alone is a guess: never enough to lower severity.
    assert [(e[2]["kind"], e[2]["_provenance"], e[2]["_confidence"]) for e in guarded] == [
        ("authn", "INFERRED", 0.5)
    ]


def test_django_url_patterns_resolve_to_views_across_files(tmp_path: Path) -> None:
    graph = Graph(
        tmp_path,
        {"shop/urls.py": DJANGO_URLS, "shop/views.py": DJANGO_VIEWS, "shop/__init__.py": ""},
    )
    handles = {(s.split("::", 1)[1], d) for s, d, _ in graph.edges("HANDLES")}
    assert handles == {
        ("http ANY /orders/", "shop/views.py::orders"),
        ("http ANY /reports/", "shop/views.py::Report.get"),
    }
    entry = graph.nodes("EntryPoint")["shop/urls.py::http ANY /orders/"]
    # The decorator is bound by an import to the real Django one: exact, EXTRACTED.
    assert (entry["auth_required"], entry["auth_confidence"]) == ("true", 0.9)
    control = graph.nodes("Control")["shop/urls.py::authn::login_required"]
    assert control["_provenance"] == "EXTRACTED" and control["match"] == "exact"
    assert (
        graph.nodes("EntryPoint")["shop/urls.py::http ANY /reports/"]["auth_required"] == "unknown"
    )


def test_nestjs_controllers_guards_and_cron(tmp_path: Path) -> None:
    graph = Graph(tmp_path, {"cats.controller.ts": NEST})
    assert kinds(graph) == {
        "http GET /cats/:id": ("http", "true"),
        "http POST /cats": ("http", "unknown"),
        "cron CatsController.sweep": ("cron", "unknown"),
    }
    props = graph.nodes("EntryPoint")
    assert props["cats.controller.ts::http POST /cats"]["external"] is True
    assert props["cats.controller.ts::cron CatsController.sweep"]["external"] is False


def test_express_middleware_exact_and_by_name(tmp_path: Path) -> None:
    graph = Graph(tmp_path, {"server.js": EXPRESS})
    entries = graph.nodes("EntryPoint")
    assert entries["server.js::http GET /open"]["auth_required"] == "unknown"
    assert entries["server.js::http GET /me"]["auth_confidence"] == 0.9
    admin = entries["server.js::http GET /admin"]
    assert (admin["auth_required"], admin["auth_confidence"]) == ("true", 0.5)
    assert admin["controls"] == ["authz"]
    handles = {(s.split("::", 1)[1], d) for s, d, _ in graph.edges("HANDLES")}
    assert ("http GET /admin", "server.js::adminPage") in handles
    assert ("http GET /open", "server.js::<GET /open>") in handles


def test_gin_routes_and_go_main(tmp_path: Path) -> None:
    graph = Graph(tmp_path, {"main.go": GIN, "go.mod": "module example.com/m\n"})
    assert kinds(graph) == {"http GET /items": ("http", "true"), "cli main": ("cli", "unknown")}


def test_spring_annotations_queue_cron_cli_and_explicit_anonymous(tmp_path: Path) -> None:
    graph = Graph(tmp_path, {"src/main/java/demo/Api.java": SPRING})
    assert kinds(graph) == {
        "http GET /secure": ("http", "true"),
        "http GET /open": ("http", "false"),  # only an explicit marker says "no auth"
        "queue_consumer Api.consume": ("queue_consumer", "unknown"),
        "cron Api.tick": ("cron", "unknown"),
        "cli Api.main": ("cli", "unknown"),
    }
    secure = graph.nodes("EntryPoint")["src/main/java/demo/Api.java::http GET /secure"]
    assert secure["auth_confidence"] == 0.9 and secure["controls"] == ["authz"]


def test_celery_tasks_and_click_commands(tmp_path: Path) -> None:
    graph = Graph(tmp_path, {"jobs.py": CELERY})
    assert kinds(graph) == {
        "queue_consumer resize": ("queue_consumer", "unknown"),
        "cli cli": ("cli", "unknown"),
    }
    entry = graph.nodes("EntryPoint")["jobs.py::queue_consumer resize"]
    assert (entry["_provenance"], entry["_confidence"]) == ("INFERRED", 0.9)


def test_every_enrichment_node_and_edge_has_evidence(tmp_path: Path) -> None:
    graph = Graph(tmp_path, {"server.js": EXPRESS, "jobs.py": CELERY})
    for table in ("nodes", "edges"):
        rows = graph.store.conn.execute(
            f"SELECT evidence, provenance, confidence FROM {table}"
        ).fetchall()
        assert rows and all(r["evidence"] != "[]" and r["provenance"] for r in rows)
        assert all(0.0 <= r["confidence"] <= 1.0 for r in rows)


# -- catalogue --------------------------------------------------------------------------
def test_catalogue_rejects_malformed_entries() -> None:
    with pytest.raises(CatalogueError):
        parse_catalogue("families: [python]\nsinks:\n  - {cwe: CWE-89}\n", "bad.yaml")
    with pytest.raises(CatalogueError):
        parse_catalogue("families: [python]\nsinks:\n  - {api: a, name: b, cwe: X}\n", "bad.yaml")
    with pytest.raises(CatalogueError):
        parse_catalogue("families: [python]\nunknown_section: []\n", "bad.yaml")
    with pytest.raises(CatalogueError):
        parse_catalogue(
            "families: [python]\nsanitizers:\n  - {api: a, protects: [X], strength: total}\n", "b"
        )


@pytest.mark.parametrize(
    ("lang", "source", "name", "want"),
    [
        ("python", "import subprocess as sp", "sp.run", "subprocess.run"),
        ("python", "from shlex import quote as q", "q", "shlex.quote"),
        ("python", "import os.path", "os.path.join", "os.path.join"),
        ("python", "from . import views", "views.x", None),
        ("javascript", 'const cp = require("child_process")', "cp.exec", "child_process.exec"),
        ("javascript", 'import { exec } from "child_process"', "exec", "child_process.exec"),
        ("go", 'package m\nimport "os/exec"', "exec.Command", "os/exec.Command"),
        ("go", 'package m\nimport x "os/exec"', "x.Command", "os/exec.Command"),
        (
            "java",
            "import org.owasp.encoder.Encode;",
            "Encode.forHtml",
            "org.owasp.encoder.Encode.forHtml",
        ),
        ("java", "class A {}", "Integer.parseInt", "java.lang.Integer.parseInt"),
        ("python", "x = 1", "quote", None),
    ],
)
def test_names_are_qualified_through_imports(lang: str, source: str, name: str, want: str) -> None:
    family = {"javascript": "js"}.get(lang, lang)
    facts = extract(lang, source.encode())
    assert qualify(name, alias_map(facts, family), family) == want


def test_handler_on_a_runtime_built_object_falls_back_to_the_method_name(tmp_path: Path) -> None:
    """``handlers.update`` where ``handlers = new Handlers(db)``: only the name is known."""
    graph = Graph(
        tmp_path,
        {
            "routes/index.js": """
const Handlers = require("./handlers");
module.exports = (app, db) => {
  const handlers = new Handlers(db);
  app.post("/update", isLoggedIn, handlers.update);
};
""",
            "routes/handlers.js": """
function Handlers(db) {
  this.update = (req, res) => { eval(req.body.value); };
}
module.exports = Handlers;
""",
        },
    )
    ((entry, handler, props),) = graph.edges("HANDLES")
    assert entry.endswith("http POST /update") and handler == "routes/handlers.js::Handlers.update"
    assert (props["_provenance"], props["_confidence"]) == ("INFERRED", 0.5)
    ((_, sink, flow),) = [e for e in graph.edges("FLOWS_TO") if "param:req" in e[0]]
    assert sink.endswith("CWE-95::eval") and flow["_confidence"] == 0.5
