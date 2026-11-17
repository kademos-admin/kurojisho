"""M3-AC7: deploy graph, exposure, runs_as_root, and conflicts with the asserted context."""

from __future__ import annotations

from pathlib import Path

from kurojisho.deploy.parse import classify, parse_deploy, parse_dockerfile
from tests.helpers import Graph

DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: shop}
spec:
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
        - name: api
          image: registry.example.com/team/api:1.2
          securityContext: {runAsNonRoot: true}
---
apiVersion: v1
kind: Service
metadata: {name: api, namespace: shop}
spec: {selector: {app: api}, ports: [{port: 80}]}
"""
INGRESS = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: public, namespace: shop}
spec:
  rules:
    - http:
        paths:
          - path: /
            backend: {service: {name: api, port: {number: 80}}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny, namespace: shop}
spec: {podSelector: {matchLabels: {app: api}}, policyTypes: [Ingress]}
"""
CONTEXT = """
assets:
  - {id: shop-api, paths: ["api/**"], tier: 1, exposure: %s}
"""
DOCKERFILE = "FROM python:3.12-slim\nCOPY . /app\nUSER app\nEXPOSE 8000\n"
CODE = "def f():\n    return 1\n"


def test_dockerfile_user_ports_and_stages() -> None:
    multi = parse_dockerfile(
        "Dockerfile",
        "FROM golang:1.22 AS build\nUSER nobody\nCOPY . .\n"
        "FROM scratch\nCOPY --from=build /bin/app /app\nADD https://x.example/f /f\n",
    )
    assert multi.base_images == ["golang:1.22", "scratch"] and multi.copies == ["."]
    assert multi.runs_as_root == "unknown"  # the final stage sets no USER
    assert parse_dockerfile("Dockerfile", "FROM a\nUSER 0:0\n").runs_as_root == "true"
    assert parse_dockerfile("Dockerfile", "FROM a\nUSER 1000\n").runs_as_root == "false"
    assert parse_dockerfile("D", 'FROM a\nCOPY ["src", "lib", "/app/"]\n').copies == ["src", "lib"]


def test_file_classification() -> None:
    assert classify("Dockerfile") == classify("svc/Dockerfile.prod") == "dockerfile"
    assert classify("docker-compose.override.yml") == classify("compose.yaml") == "compose"
    assert classify(".github/workflows/ci.yml") == "github_actions"
    assert classify("infra/main.tf") == "terraform" and classify("k8s/app.yaml") == "yaml"
    assert classify("src/app.py") is None


def test_ingress_makes_the_workload_internet_facing(tmp_path: Path) -> None:
    graph = Graph(
        tmp_path,
        {
            "api/app.py": CODE,
            "api/Dockerfile": DOCKERFILE,
            "k8s/api.yaml": DEPLOYMENT,
            "k8s/ingress.yaml": INGRESS,
        },
    )
    (workload,) = graph.nodes("Workload").values()
    assert workload["exposure"] == "internet" and workload["exposure_reason"] == "Ingress public"
    assert workload["runs_as_root"] == "false" and workload["code_paths"] == ["api"]
    assert {(s.split("::")[0], d.split("::")[0]) for s, d, _ in graph.edges("DEPLOYED_AS")} == {
        ("k8s/api.yaml", "k8s/api.yaml"),  # Service -> Workload
        ("api/Dockerfile", "k8s/api.yaml"),  # Container -> Workload, by image name
    }
    image_link = next(p for s, _, p in graph.edges("DEPLOYED_AS") if s.startswith("api/"))
    assert (image_link["_provenance"], image_link["_confidence"]) == ("INFERRED", 0.6)
    assert len(graph.edges("EXPOSED_VIA")) == 1
    assert len(graph.nodes("Ingress")) == len(graph.nodes("NetworkPolicy")) == 1
    container = graph.nodes("Container")["api/Dockerfile::Dockerfile"]
    assert container["runs_as_root"] == "false" and container["ports"] == ["8000"]


def test_without_an_ingress_exposure_is_internal_and_absence_is_unknown(tmp_path: Path) -> None:
    graph = Graph(tmp_path, {"k8s/api.yaml": DEPLOYMENT})
    assert next(iter(graph.nodes("Workload").values()))["exposure"] == "internal"
    alone = Graph(tmp_path / "b", {"k8s/api.yaml": DEPLOYMENT.split("---")[0]})
    # No Service in this repo says nothing about Services elsewhere.
    assert next(iter(alone.nodes("Workload").values()))["exposure"] == "unknown"


def test_internal_load_balancer_and_root_containers(tmp_path: Path) -> None:
    manifest = """
apiVersion: v1
kind: Pod
metadata: {name: p, labels: {app: p}}
spec:
  hostNetwork: true
  containers: [{name: c, image: "c:1", securityContext: {privileged: true}}]
---
apiVersion: v1
kind: Service
metadata:
  name: p
  annotations: {service.beta.kubernetes.io/aws-load-balancer-internal: "true"}
spec: {type: LoadBalancer, selector: {app: p}}
---
apiVersion: v1
kind: Service
metadata: {name: q}
spec: {type: LoadBalancer, selector: {app: q}}
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: q}
spec:
  jobTemplate:
    spec:
      template:
        metadata: {labels: {app: q}}
        spec: {containers: [{name: c, image: "q:1"}]}
"""
    workloads = Graph(tmp_path, {"k8s.yaml": manifest}).nodes("Workload")
    pod = workloads["k8s.yaml::Pod/default/p"]
    assert (pod["exposure"], pod["runs_as_root"], pod["privileged"]) == ("internal", "true", True)
    assert pod["host_network"] is True
    assert workloads["k8s.yaml::CronJob/default/q"]["exposure"] == "internet"


def test_compose_build_context_and_published_ports(tmp_path: Path) -> None:
    compose = """
services:
  web:
    build: ./web
    ports: ["8080:80"]
  db:
    image: postgres:16
    ports: ["127.0.0.1:5432:5432"]
  worker:
    build: {context: ./worker}
    user: root
"""
    graph = Graph(
        tmp_path,
        {
            "docker-compose.yml": compose,
            "web/Dockerfile": "FROM node:22\nCOPY . .\n",
            "web/app.js": "function f() {}\n",
        },
    )
    workloads = {k.split("/")[-1]: v for k, v in graph.nodes("Workload").items()}
    assert workloads["web"]["exposure"] == "internet" and workloads["web"]["code_paths"] == ["web"]
    assert workloads["web"]["exposure_confidence"] == 0.6
    assert workloads["db"]["exposure"] == "internal"
    assert (
        workloads["worker"]["exposure"] == "unknown"
        and workloads["worker"]["runs_as_root"] == "true"
    )


def test_context_conflict_when_iac_contradicts_the_context_file(tmp_path: Path) -> None:
    files = {
        "api/app.py": CODE,
        "api/Dockerfile": DOCKERFILE,
        "k8s/api.yaml": DEPLOYMENT,
        "k8s/ingress.yaml": INGRESS,
    }
    internal = Graph(tmp_path / "a", {**files, "kurojisho.context.yaml": CONTEXT % "internal"})
    (conflict,) = internal.nodes("ContextConflict").values()
    assert (conflict["asserted"], conflict["observed"], conflict["effective"]) == (
        "internal",
        "internet",
        "internet",  # the worse of the two
    )
    assert conflict["_provenance"] == "INFERRED" and conflict["_confidence"] == 0.6
    assert [d for _, d, _ in internal.edges("BELONGS_TO") if d == "shop-api"]

    agree = Graph(tmp_path / "b", {**files, "kurojisho.context.yaml": CONTEXT % "internet"})
    assert agree.nodes("ContextConflict") == {}

    # The other direction is a disagreement too, and the worse value still wins.
    del files["k8s/ingress.yaml"]
    claimed = Graph(tmp_path / "c", {**files, "kurojisho.context.yaml": CONTEXT % "internet"})
    (conflict,) = claimed.nodes("ContextConflict").values()
    assert (conflict["observed"], conflict["effective"]) == ("internal", "internet")


def test_pipelines_terraform_and_broken_manifests(tmp_path: Path) -> None:
    workflow = """
name: CI
on: [push, pull_request]
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - run: make test
"""
    graph = Graph(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow,
            ".gitlab-ci.yml": "stages: [test]\nunit:\n  script: [make]\n",
            "infra/main.tf": 'resource "aws_lb" "x" { internal = false }\n',
            "k8s/broken.yaml": "apiVersion: v1\nkind: Service\nmetadata: {name: [\n",
            "notes.yaml": "just: [a, list\n",
        },
    )
    pipelines = graph.nodes("Pipeline")
    ci = pipelines[".github/workflows/ci.yml::CI"]
    assert ci["triggers"] == ["pull_request", "push"] and ci["uses"] == ["actions/checkout@v4"]
    assert pipelines[".gitlab-ci.yml::.gitlab-ci.yml"]["jobs"] == ["unit"]
    gaps = {k.split("::")[1]: v["files"] for k, v in graph.nodes("CoverageGap").items()}
    # Terraform is not read and a broken manifest cannot be: both are blind spots, said so.
    assert gaps == {"iac_not_modelled": ["infra/main.tf"], "iac_unparsed": ["k8s/broken.yaml"]}


def test_unreadable_candidates_are_reported() -> None:
    deploy = parse_deploy({"Dockerfile": None, "a.yaml": "x: 1\n"})
    assert deploy.unparsed == ["Dockerfile"] and deploy.containers == []
