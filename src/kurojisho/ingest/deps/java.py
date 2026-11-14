"""Maven pom.xml: declared dependencies only. Maven itself is never run."""

from __future__ import annotations

import re
from xml.etree.ElementTree import Element  # type only; parsing goes through defusedxml

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

from kurojisho.ingest.deps.base import Dep, ManifestError, find_line
from kurojisho.model import Scope

_PROPERTY = re.compile(r"\$\{([^}]+)\}")


def _strip(element: Element) -> None:
    for node in element.iter():
        if isinstance(node.tag, str) and "}" in node.tag:
            node.tag = node.tag.split("}", 1)[1]


def _text(element: Element | None, tag: str) -> str:
    child = element.find(tag) if element is not None else None
    return (child.text or "").strip() if child is not None else ""


def parse_pom(path: str, text: str) -> tuple[list[Dep], list[str]]:
    try:
        root = fromstring(text)
    except (ParseError, DefusedXmlException, ValueError, RecursionError) as exc:
        raise ManifestError(f"{path}: invalid or unsafe XML") from exc
    _strip(root)
    notes = []
    parent = root.find("parent")
    if parent is not None:
        notes.append("parent_pom_not_resolved")
    properties = {
        "project.version": _text(root, "version") or _text(parent, "version"),
        "project.groupId": _text(root, "groupId") or _text(parent, "groupId"),
    }
    for prop in root.findall("properties/*"):
        properties[str(prop.tag)] = (prop.text or "").strip()

    def expand(value: str) -> str:
        for _ in range(5):
            replaced = _PROPERTY.sub(lambda m: properties.get(m.group(1), m.group(0)), value)
            if replaced == value:
                break
            value = replaced
        return value

    managed = {}
    for dep in root.findall("dependencyManagement/dependencies/dependency"):
        coordinate = f"{expand(_text(dep, 'groupId'))}:{expand(_text(dep, 'artifactId'))}"
        managed[coordinate] = expand(_text(dep, "version"))
    out = []
    for dep in root.findall("dependencies/dependency"):
        group, artifact = expand(_text(dep, "groupId")), expand(_text(dep, "artifactId"))
        if not group or not artifact:
            continue
        name = f"{group}:{artifact}"
        declared = _text(dep, "version")
        version = expand(declared) if declared else managed.get(name, "")
        resolved = bool(version) and "${" not in version and not version.startswith(("[", "("))
        if not resolved:
            notes.append(f"version_not_resolved:{name}")
        scope = Scope.TEST if _text(dep, "scope") == "test" else Scope.RUNTIME
        line = find_line(text, rf"<artifactId>\s*{re.escape(_text(dep, 'artifactId'))}\s*<")
        out.append(
            Dep(
                "maven",
                name,
                version if resolved else None,
                (version or declared or None) if not resolved else declared or None,
                True,
                scope,
                path,
                line,
            )
        )
    return out, sorted(set(notes))
