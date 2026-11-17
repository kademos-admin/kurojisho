"""Read deployment descriptions: Kubernetes manifests, Dockerfiles, Compose files, CI.

Only what is written in the files is reported. What they do not say (a Service that lives
in another repository, a USER set by a base image) stays ``unknown``.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}
_COMPOSE = re.compile(r"^(docker-)?compose(\.[\w-]+)?\.ya?ml$")
_INTERNAL = re.compile(r"internal", re.IGNORECASE)


@dataclass
class Container:
    path: str
    base_images: list[str] = field(default_factory=list)
    user: str | None = None
    ports: list[str] = field(default_factory=list)
    copies: list[str] = field(default_factory=list)

    @property
    def runs_as_root(self) -> str:
        if self.user is None:
            return "unknown"  # root unless the base image says otherwise, which we cannot see
        return "true" if self.user.split(":")[0] in ("root", "0") else "false"


@dataclass
class Workload:
    path: str
    source: str  # k8s | compose
    kind: str
    name: str
    namespace: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    images: list[str] = field(default_factory=list)
    runs_as_root: str = "unknown"
    privileged: bool = False
    host_network: bool = False
    build_context: str | None = None  # compose: directory the image is built from
    published: list[str] = field(default_factory=list)  # compose: published ports


@dataclass
class Service:
    path: str
    name: str
    namespace: str
    type: str
    selector: dict[str, str]
    internal: bool


@dataclass
class Ingress:
    path: str
    name: str
    namespace: str
    backends: list[str]
    internal: bool
    class_name: str


@dataclass
class NetworkPolicy:
    path: str
    name: str
    namespace: str
    selector: dict[str, str]
    policy_types: list[str]


@dataclass
class Pipeline:
    path: str
    system: str
    name: str
    triggers: list[str]
    jobs: list[str]
    uses: list[str]


@dataclass
class Deploy:
    containers: list[Container] = field(default_factory=list)
    workloads: list[Workload] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    ingresses: list[Ingress] = field(default_factory=list)
    policies: list[NetworkPolicy] = field(default_factory=list)
    pipelines: list[Pipeline] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)  # deployment files we could not read
    not_modelled: list[str] = field(default_factory=list)  # e.g. Terraform


def classify(path: str) -> str | None:
    base = posixpath.basename(path)
    lower = base.lower()
    if lower in ("dockerfile", "containerfile") or lower.startswith("dockerfile."):
        return "dockerfile"
    if lower.endswith(".dockerfile"):
        return "dockerfile"
    if _COMPOSE.match(lower):
        return "compose"
    if lower.endswith((".tf", ".tf.json")):
        return "terraform"
    if lower.endswith((".yml", ".yaml")):
        if posixpath.dirname(path) == ".github/workflows":
            return "github_actions"
        if lower == ".gitlab-ci.yml":
            return "gitlab_ci"
        return "yaml"
    return None


def _strings(value: Any) -> dict[str, str]:
    return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def parse_dockerfile(path: str, text: str) -> Container:
    container = Container(path)
    joined = re.sub(r"\\\r?\n", " ", text)
    for raw in joined.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        word, _, rest = line.partition(" ")
        word, rest = word.upper(), rest.strip()
        if word == "FROM":
            parts = [p for p in rest.split() if not p.startswith("--")]
            if parts:
                container.base_images.append(parts[0])
            container.user = None  # each stage starts from its base image's user
        elif word == "USER":
            container.user = rest.split()[0] if rest else None
        elif word == "EXPOSE":
            container.ports += rest.split()
        elif word in ("COPY", "ADD"):
            try:
                parts = (
                    rest[1:-1].replace('"', "").split(",") if rest[:1] == "[" else shlex.split(rest)
                )
            except ValueError:
                continue
            if any(p.startswith("--from") for p in parts):
                continue
            sources = [p.strip() for p in parts if not p.startswith("--")][:-1]
            container.copies += [s for s in sources if "://" not in s]
    return container


def _pod(spec: dict[str, Any], workload: Workload) -> None:
    security = _dict(spec.get("securityContext"))
    states = []
    for item in _list(spec.get("containers")) + _list(spec.get("initContainers")):
        item = _dict(item)
        if item.get("image"):
            workload.images.append(str(item["image"]))
        own = {**security, **_dict(item.get("securityContext"))}
        if own.get("privileged") is True:
            workload.privileged = True
        if own.get("runAsUser") == 0 or own.get("privileged") is True:
            states.append("true")
        elif own.get("runAsNonRoot") is True or isinstance(own.get("runAsUser"), int):
            states.append("false")
        else:
            states.append("unknown")
    workload.host_network = spec.get("hostNetwork") is True
    if "true" in states:
        workload.runs_as_root = "true"
    elif states and all(s == "false" for s in states):
        workload.runs_as_root = "false"


def _k8s(path: str, doc: dict[str, Any], out: Deploy) -> None:
    kind = str(doc.get("kind"))
    meta = _dict(doc.get("metadata"))
    name, namespace = str(meta.get("name") or ""), str(meta.get("namespace") or "default")
    spec = _dict(doc.get("spec"))
    annotations = _strings(meta.get("annotations"))
    internal = any(
        (_INTERNAL.search(k) and v.lower() not in ("false", "0")) or _INTERNAL.search(v)
        for k, v in annotations.items()
    )
    if kind in WORKLOAD_KINDS:
        template = spec
        if kind == "CronJob":
            template = _dict(_dict(spec.get("jobTemplate")).get("spec"))
        if kind != "Pod":
            pod_meta = _dict(_dict(template.get("template")).get("metadata"))
            template = _dict(_dict(template.get("template")).get("spec"))
        else:
            pod_meta = meta
        workload = Workload(path, "k8s", kind, name, namespace, _strings(pod_meta.get("labels")))
        _pod(template, workload)
        out.workloads.append(workload)
    elif kind == "Service":
        out.services.append(
            Service(
                path,
                name,
                namespace,
                str(spec.get("type") or "ClusterIP"),
                _strings(spec.get("selector")),
                internal,
            )
        )
    elif kind == "Ingress":
        backends = []
        default = _dict(_dict(spec.get("defaultBackend")).get("service")).get("name")
        if default:
            backends.append(str(default))
        for rule in _list(spec.get("rules")):
            for item in _list(_dict(_dict(rule).get("http")).get("paths")):
                backend = _dict(_dict(item).get("backend"))
                service = _dict(backend.get("service")).get("name") or backend.get("serviceName")
                if service:
                    backends.append(str(service))
        class_name = str(spec.get("ingressClassName") or "")
        out.ingresses.append(
            Ingress(
                path,
                name,
                namespace,
                sorted(set(backends)),
                internal or bool(_INTERNAL.search(class_name)),
                class_name,
            )
        )
    elif kind == "NetworkPolicy":
        selector = _strings(_dict(spec.get("podSelector")).get("matchLabels"))
        types = [str(t) for t in _list(spec.get("policyTypes"))]
        out.policies.append(NetworkPolicy(path, name, namespace, selector, types))


def _compose(path: str, doc: dict[str, Any], out: Deploy) -> None:
    base = posixpath.dirname(path)
    for name, raw in sorted(_dict(doc.get("services")).items()):
        service = _dict(raw)
        workload = Workload(path, "compose", "ComposeService", str(name))
        if service.get("image"):
            workload.images.append(str(service["image"]))
        build = service.get("build")
        context = build if isinstance(build, str) else _dict(build).get("context")
        if isinstance(context, str):
            workload.build_context = posixpath.normpath(posixpath.join(base, context)).strip(".")
        for port in _list(service.get("ports")):
            published = (
                f"{port.get('host_ip', '')}:{port.get('published', '')}"
                if isinstance(port, dict)
                else str(port)
            )
            workload.published.append(published)
        workload.privileged = service.get("privileged") is True
        workload.host_network = service.get("network_mode") == "host"
        user = service.get("user")
        if user is not None:
            workload.runs_as_root = "true" if str(user).split(":")[0] in ("root", "0") else "false"
        out.workloads.append(workload)


def _pipeline(path: str, system: str, doc: dict[str, Any], out: Deploy) -> None:
    # YAML 1.1 reads the key ``on`` as boolean true.
    loose: dict[Any, Any] = doc
    trigger = loose.get("on", loose.get(True))
    triggers = [trigger] if isinstance(trigger, str) else sorted(str(t) for t in trigger or [])
    jobs = _dict(doc.get("jobs")) if system == "github_actions" else {}
    uses = set()
    for job in jobs.values():
        for step in _list(_dict(job).get("steps")):
            if _dict(step).get("uses"):
                uses.add(str(_dict(step)["uses"]))
    if system == "gitlab_ci":
        reserved = {"stages", "variables", "include", "default", "workflow", "image", "services"}
        jobs = {k: v for k, v in doc.items() if isinstance(v, dict) and k not in reserved}
    name = str(doc.get("name") or posixpath.basename(path))
    out.pipelines.append(
        Pipeline(path, system, name, triggers, sorted(str(j) for j in jobs), sorted(uses))
    )


def parse_deploy(files: dict[str, str | None]) -> Deploy:
    """``files``: path -> text for every candidate file (None when it could not be read)."""
    out = Deploy()
    for path in sorted(files):
        kind = classify(path)
        text = files[path]
        if kind == "terraform":
            out.not_modelled.append(path)
            continue
        if kind is None:
            continue
        if text is None:
            out.unparsed.append(path)
            continue
        if kind == "dockerfile":
            out.containers.append(parse_dockerfile(path, text))
            continue
        try:
            docs = [d for d in YAML(typ="safe", pure=True).load_all(text) if isinstance(d, dict)]
        except (YAMLError, ValueError, RecursionError):
            # Only deployment files matter here; an unreadable one is a blind spot.
            if kind != "yaml" or "apiVersion:" in text:
                out.unparsed.append(path)
            continue
        for doc in docs:
            if kind == "compose":
                _compose(path, doc, out)
            elif kind in ("github_actions", "gitlab_ci"):
                _pipeline(path, kind, doc, out)
            elif "apiVersion" in doc and "kind" in doc:
                items = _list(doc.get("items")) if doc.get("kind") == "List" else [doc]
                for item in items:
                    if isinstance(item, dict):
                        _k8s(path, item, out)
    return out
