"""Deployment nodes, exposure, and conflicts with the asserted business context."""

from __future__ import annotations

import posixpath
from typing import Any

from kurojisho.config.context import Context
from kurojisho.deploy.parse import Container, Deploy, Workload
from kurojisho.model import Edge, EdgeType, Evidence, Node, NodeType, Provenance, node_id, node_key

SOURCE = "deploy"
IMAGE_MATCH = 0.6  # an image name matched to a Dockerfile by naming convention only
COMPOSE_PUBLISHED = 0.6  # a port published on every host interface: reachable, by whom unknown


def covers(code_paths: list[str], path: str) -> bool:
    return any(p == "" or path == p or path.startswith(p + "/") for p in code_paths)


def _code_paths(container: Container, files: list[str], code_dirs: set[str]) -> list[str]:
    """Directories whose files end up in the image. ``""`` is the whole repository."""
    here = posixpath.dirname(container.path)
    roots = [here] if here in code_dirs or not here else [here, ""]
    explicit = [c.strip("/") for c in container.copies if c.strip("./")]
    for root in roots:
        resolved = [posixpath.normpath(posixpath.join(root, c)) for c in explicit]
        if explicit and all(any(covers([r], f) for f in files) for r in resolved):
            if len(explicit) == len(container.copies):
                return sorted(set(resolved))
            return [root]
    # Only ``COPY . .``: the build context, which is this directory if it holds code.
    return [here if here in code_dirs else ""]


def _image_name(image: str) -> str:
    name = image.split("@", 1)[0]
    last = name.rsplit("/", 1)[-1]
    return last.split(":", 1)[0]


def _selects(selector: dict[str, str], labels: dict[str, str]) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def _ev(path: str, note: str, hashes: dict[str, str]) -> Evidence:
    return Evidence(path=path, source=SOURCE, content_hash=hashes.get(path), note=note)


def build_deploy(
    deploy: Deploy, context: Context, files: list[str], hashes: dict[str, str], code_dirs: set[str]
) -> tuple[list[Node], list[Edge]]:
    nodes: list[Node] = []
    edges: list[Edge] = []

    def add(
        kind: NodeType,
        path: str,
        name: str,
        props: dict[str, Any],
        *,
        confidence: float = 1.0,
        note: str = "",
    ) -> Node:
        node = Node(
            type=kind,
            key=node_key(kind, path, name),
            name=name,
            owner_file=path,
            props={"path": path, **props},
            provenance=Provenance.EXTRACTED,
            confidence=confidence,
            evidence=(_ev(path, note or f"{kind.value}:{name}", hashes),),
        )
        nodes.append(node)
        return node

    def link(
        kind: EdgeType, src: Node, dst: Node, provenance: Provenance, confidence: float, note: str
    ) -> None:
        edges.append(
            Edge(
                type=kind,
                src=src.id,
                dst=dst.id,
                owner_file=src.owner_file,
                provenance=provenance,
                confidence=confidence,
                evidence=(_ev(src.owner_file or ".", note, hashes),),
            )
        )

    containers: dict[str, tuple[Container, Node, list[str]]] = {}
    for container in deploy.containers:
        paths = _code_paths(container, files, code_dirs)
        node = add(
            NodeType.CONTAINER,
            container.path,
            posixpath.basename(container.path),
            {
                "base_images": container.base_images,
                "user": container.user,
                "runs_as_root": container.runs_as_root,
                "ports": container.ports,
                "code_paths": paths,
            },
        )
        containers[container.path] = (container, node, paths)

    service_nodes = {
        (s.namespace, s.name): (
            s,
            add(
                NodeType.SERVICE,
                s.path,
                f"{s.namespace}/{s.name}",
                {"type": s.type, "selector": s.selector, "internal_load_balancer": s.internal},
            ),
        )
        for s in deploy.services
    }
    ingress_nodes = [
        (
            i,
            add(
                NodeType.INGRESS,
                i.path,
                f"{i.namespace}/{i.name}",
                {
                    "backends": i.backends,
                    "class": i.class_name or None,
                    "exposure": "internal" if i.internal else "internet",
                },
            ),
        )
        for i in deploy.ingresses
    ]
    for policy in deploy.policies:
        add(
            NodeType.NETWORK_POLICY,
            policy.path,
            f"{policy.namespace}/{policy.name}",
            {"selector": policy.selector, "policy_types": policy.policy_types},
        )
    for pipeline in deploy.pipelines:
        add(
            NodeType.PIPELINE,
            pipeline.path,
            pipeline.name,
            {
                "system": pipeline.system,
                "triggers": pipeline.triggers,
                "jobs": pipeline.jobs,
                "uses": pipeline.uses,
            },
        )

    #: (exposure, confidence, why, code paths) per workload, for the conflict check
    observed: list[tuple[str, float, str, list[str], Workload]] = []
    for workload in deploy.workloads:
        exposure, confidence, why = "unknown", 0.0, ""
        via: list[Node] = []
        selecting: list[Node] = []
        if workload.source == "k8s":
            for (namespace, _), (service, node) in sorted(service_nodes.items()):
                if namespace != workload.namespace or not _selects(
                    service.selector, workload.labels
                ):
                    continue
                selecting.append(node)
                level = "internal"
                reason = f"Service {service.name} ({service.type})"
                if service.type == "LoadBalancer" and not service.internal:
                    level = "internet"
                for ingress, ingress_node in ingress_nodes:
                    if ingress.namespace == namespace and service.name in ingress.backends:
                        via.append(ingress_node)
                        if not ingress.internal:
                            level, reason = "internet", f"Ingress {ingress.name}"
                if exposure != "internet":
                    exposure, confidence, why = level, 1.0, reason
        else:
            for port in workload.published:
                loopback = port.startswith(("127.", "localhost", "[::1]", "::1"))
                level = "internal" if loopback else "internet"
                if exposure != "internet":
                    exposure, why = level, f"published port {port}"
                    confidence = 1.0 if loopback else COMPOSE_PUBLISHED
        code_paths: list[str] = []
        matched: list[tuple[Node, Provenance, float, str]] = []
        root_states = {workload.runs_as_root}
        if workload.build_context is not None:
            code_paths.append(workload.build_context)
            for path, (container, node, _) in sorted(containers.items()):
                if posixpath.dirname(path) == workload.build_context:
                    matched.append((node, Provenance.EXTRACTED, 1.0, "compose build context"))
                    root_states.add(container.runs_as_root)
        else:
            names = {_image_name(i) for i in workload.images}
            for path, (container, node, paths) in sorted(containers.items()):
                folder = posixpath.basename(posixpath.dirname(path))
                if folder in names or len(containers) == 1:
                    matched.append((node, Provenance.INFERRED, IMAGE_MATCH, "image name"))
                    code_paths += paths
                    root_states.add(container.runs_as_root)
        runs_as_root = workload.runs_as_root
        if runs_as_root == "unknown" and "true" in root_states:
            runs_as_root = "true"
        label = f"{workload.kind}/{workload.namespace}/{workload.name}".replace("//", "/")
        node = add(
            NodeType.WORKLOAD,
            workload.path,
            label,
            {
                "kind": workload.kind,
                "source": workload.source,
                "images": workload.images,
                # ``unknown`` when nothing here exposes it: other manifests may.
                "exposure": exposure,
                "exposure_reason": why or None,
                "exposure_confidence": confidence,
                "runs_as_root": runs_as_root,
                "privileged": workload.privileged,
                "host_network": workload.host_network,
                "code_paths": sorted(set(code_paths)),
            },
        )
        for service_node in selecting:
            link(EdgeType.DEPLOYED_AS, service_node, node, Provenance.EXTRACTED, 1.0, "selector")
        for ingress_node in {n.id: n for n in via}.values():
            link(EdgeType.EXPOSED_VIA, node, ingress_node, Provenance.EXTRACTED, 1.0, "backend")
        for container_node, provenance, score, note in matched:
            link(EdgeType.DEPLOYED_AS, container_node, node, provenance, score, note)
        if exposure != "unknown" and code_paths:
            link_confidence = min([confidence, *(m[2] for m in matched)])
            observed.append((exposure, link_confidence, why, sorted(set(code_paths)), workload))

    # Context says one thing, the deployment files another: record it, use the worse.
    for asset in context.assets:
        if asset.exposure is None:
            continue
        seen = [o for o in observed if any(asset.matches(f) and covers(o[3], f) for f in files)]
        if not seen:
            continue
        worst = max(seen, key=lambda o: (o[0] == "internet", o[1]))
        if (asset.exposure == "internet") == (worst[0] == "internet"):
            continue
        effective = "internet"
        workload = worst[4]
        node = Node(
            type=NodeType.CONTEXT_CONFLICT,
            key=node_key(NodeType.CONTEXT_CONFLICT, asset.id, "exposure"),
            name=f"{asset.id}: exposure",
            props={
                "asset": asset.id,
                "field": "exposure",
                "asserted": asset.exposure,
                "observed": worst[0],
                "observed_reason": worst[2],
                "effective": effective,
            },
            provenance=Provenance.INFERRED,
            confidence=worst[1],
            evidence=(_ev(workload.path, f"{workload.kind}/{workload.name}: {worst[2]}", hashes),),
        )
        nodes.append(node)
        edges.append(
            Edge(
                type=EdgeType.BELONGS_TO,
                src=node.id,
                dst=node_id(node_key(NodeType.ASSET, asset.id)),
                provenance=Provenance.INFERRED,
                confidence=worst[1],
                evidence=node.evidence,
            )
        )
    for reason, paths, detail in (
        ("iac_not_modelled", deploy.not_modelled, "Terraform is not read for exposure"),
        ("iac_unparsed", deploy.unparsed, "deployment file could not be parsed"),
    ):
        if paths:
            nodes.append(
                Node(
                    type=NodeType.COVERAGE_GAP,
                    key=node_key(NodeType.COVERAGE_GAP, SOURCE, reason),
                    name=f"deploy: {reason}",
                    props={
                        "tool": SOURCE,
                        "category": "iac",
                        "reason": reason,
                        # Exposure for code these files deploy stays unknown (worst case).
                        "detail": detail,
                        "files": sorted(paths),
                    },
                    provenance=Provenance.EXTRACTED,
                    confidence=1.0,
                    evidence=tuple(_ev(p, reason, hashes) for p in sorted(paths)[:25]),
                )
            )
    return nodes, edges
