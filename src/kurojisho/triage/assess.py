"""Reachability, exploitability and business impact of each finding, read from the graph.

Every answer is a :class:`Factor` that says where it came from. "We found nothing" is
never turned into a favourable value here: it is ``R0``, or an ``assumed`` factor that the
guards will not let lower a severity.
"""

from __future__ import annotations

import heapq
import re
from collections import defaultdict
from dataclasses import dataclass

from kurojisho.config.context import Context
from kurojisho.deploy.graph import covers
from kurojisho.model import Edge, EdgeType, Node, NodeType, Provenance, Severity
from kurojisho.triage.engine import QUALIFYING_CONFIDENCE, UNKNOWN_AUTH, Factor, Inputs

_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|testdata|spec|e2e)/|(^|/)src/test/"
    r"|(^|/)test_[^/]*\.py$|_test\.(py|go)$|\.(test|spec)\.[cm]?[jt]sx?$|(^|/)conftest\.py$"
)
_FIXTURE_PATH = re.compile(r"(^|/)(fixtures?|testdata|mocks?|examples?|samples?)/")
_CI_PATH = re.compile(
    r"^\.github/workflows/|^\.gitlab-ci\.yml$|(^|/)Jenkinsfile$|^\.circleci/"
    r"|^azure-pipelines\.ya?ml$|^bitbucket-pipelines\.yml$"
)
_SENSITIVE = {"PCI", "PHI", "secrets"}
#: Tools name the same weakness at different levels of the CWE tree.
_CWE_FAMILY = {
    **dict.fromkeys(("CWE-77", "CWE-78", "CWE-88"), "command"),
    **dict.fromkeys(("CWE-89", "CWE-564", "CWE-943"), "sql"),
    **dict.fromkeys(("CWE-94", "CWE-95", "CWE-96"), "code"),
    **dict.fromkeys(("CWE-79", "CWE-80"), "xss"),
    **dict.fromkeys(("CWE-22", "CWE-23", "CWE-36", "CWE-73"), "path"),
}
MODULE_LEVEL = 0.7  # module-level code runs when a handler in the same file is served
NOT_CALLED_GUESS = 0.6  # "we saw no call" in a best-effort call graph
EPSS_E2, EPSS_E1 = 0.10, 0.01


def is_test_path(path: str | None) -> bool:
    return bool(path) and _TEST_PATH.search(path or "") is not None


@dataclass(frozen=True)
class Reached:
    """How entry points get to a function."""

    state: str  # R4 | R3
    confidence: float
    entry_point: str
    authenticated: bool  # every external entry point that gets here requires auth


class GraphIndex:
    def __init__(
        self, nodes: list[Node], edges: list[Edge], context: Context, has_context: bool
    ) -> None:
        self.context = context
        self.has_context = has_context
        self.by_id = {n.id: n for n in nodes}
        self.file_ids = {
            n.props["path"]: n.id for n in nodes if n.type is NodeType.FILE and "path" in n.props
        }
        self.advisories: dict[str, Node] = {}
        self.packages: dict[str, Node] = {}
        self.workloads = [n for n in nodes if n.type is NodeType.WORKLOAD]
        self.sinks: dict[str, list[Node]] = defaultdict(list)
        self.functions_in: dict[str, list[str]] = defaultdict(list)
        for node in nodes:
            if node.type is NodeType.ADVISORY:
                for identifier in [node.props["id"], *node.props.get("aliases", [])]:
                    self.advisories[identifier] = node
            elif node.type is NodeType.PACKAGE and node.props.get("purl"):
                self.packages[node.props["purl"]] = node
            elif node.type is NodeType.SINK:
                self.sinks[node.props["path"]].append(node)
            elif node.type is NodeType.FUNCTION and node.props.get("path"):
                self.functions_in[node.props["path"]].append(node.id)
        calls: dict[str, list[tuple[str, float]]] = defaultdict(list)
        handles: dict[str, list[tuple[str, float]]] = defaultdict(list)
        self.located: dict[str, str] = {}
        self.flows: dict[str, list[Edge]] = defaultdict(list)
        self.assets: dict[str, list[Node]] = defaultdict(list)
        #: (purl, advisory id) -> calls of that advisory's vulnerable symbols
        self.uses: dict[tuple[str, str], list[Edge]] = defaultdict(list)
        self.duplicate_of: dict[str, str] = {}
        self.conflicts: dict[str, Node] = {}
        for edge in edges:
            kind = edge.type
            if kind is EdgeType.CALLS:
                target = self.by_id.get(edge.dst)
                if target is not None and target.props.get("role") != "dynamic_target":
                    calls[edge.src].append((edge.dst, edge.confidence))
            elif kind is EdgeType.HANDLES:
                handles[edge.src].append((edge.dst, edge.confidence))
            elif kind is EdgeType.LOCATED_IN:
                target = self.by_id.get(edge.dst)
                # prefer the function over the file when both are recorded
                if edge.src not in self.located or (
                    target is not None and target.type is NodeType.FUNCTION
                ):
                    self.located[edge.src] = edge.dst
            elif kind is EdgeType.FLOWS_TO:
                self.flows[edge.dst].append(edge)
            elif kind is EdgeType.BELONGS_TO:
                owner = self.by_id.get(edge.dst)
                source = self.by_id.get(edge.src)
                if owner is not None and source is not None:
                    if source.type is NodeType.CONTEXT_CONFLICT:
                        self.conflicts[owner.props["id"]] = source
                    elif owner.type is NodeType.ASSET:
                        self.assets[edge.src].append(owner)
            elif kind is EdgeType.USES_SYMBOL:
                symbol = self.by_id.get(edge.dst)
                if symbol is not None:
                    key = (symbol.props["purl"], symbol.props["advisory_id"])
                    self.uses[key].append(edge)
            elif kind is EdgeType.DUPLICATE_OF:
                self.duplicate_of[edge.src] = edge.dst
        self._calls = calls
        open_: dict[str, tuple[float, str]] = {}
        authed: dict[str, tuple[float, str]] = {}
        internal: dict[str, tuple[float, str]] = {}
        for node in nodes:
            if node.type is not NodeType.ENTRY_POINT:
                continue
            props = node.props
            proven_auth = (
                props.get("auth_required") == "true"
                and props.get("auth_confidence", 0.0) >= QUALIFYING_CONFIDENCE
            )
            group = internal if not props.get("external") else authed if proven_auth else open_
            for function, confidence in handles.get(node.id, []):
                best = min(confidence, node.confidence)
                if best > group.get(function, (0.0, ""))[0]:
                    group[function] = (best, node.key)
        self._open = self._spread(open_)
        self._authed = self._spread(authed)
        self._internal = self._spread(internal)

    def _spread(self, seeds: dict[str, tuple[float, str]]) -> dict[str, tuple[float, str]]:
        """Best (highest-confidence) call path from any seed to every function."""
        best: dict[str, tuple[float, str]] = {}
        heap = [(-confidence, function, key) for function, (confidence, key) in seeds.items()]
        heapq.heapify(heap)
        while heap:
            negative, function, key = heapq.heappop(heap)
            if function in best:
                continue
            best[function] = (-negative, key)
            for callee, confidence in self._calls.get(function, ()):
                if callee not in best:
                    heapq.heappush(heap, (-min(-negative, confidence), callee, key))
        return best

    def reached(self, function: str | None) -> Reached | None:
        if function is None:
            return None
        open_, authed = self._open.get(function), self._authed.get(function)
        if open_ is not None or authed is not None:
            best = max(x for x in (open_, authed) if x is not None)
            return Reached("R4", best[0], (open_ or authed or best)[1], open_ is None)
        internal = self._internal.get(function)
        if internal is not None:
            return Reached("R3", internal[0], internal[1], False)
        return None

    def reached_from_file(self, path: str) -> Reached | None:
        """Module-level code: reachable when a handler defined in the same file is."""
        hits = []
        for function in self.functions_in.get(path, ()):
            seeds = (self._open, self._authed, self._internal)
            if any(function in seed for seed in seeds):
                found = self.reached(function)
                if found is not None:
                    hits.append(found)
        if not hits:
            return None
        best = max(hits, key=lambda r: (r.state, r.confidence, r.entry_point))
        authenticated = all(h.authenticated for h in hits if h.state == "R4")
        return Reached(
            best.state, min(best.confidence, MODULE_LEVEL), best.entry_point, authenticated
        )


@dataclass
class Assessment:
    inputs: Inputs
    entry_points: list[str]
    asset: str | None = None
    exposure: str | None = None


def _auth(reached: list[Reached]) -> Factor:
    external = [r for r in reached if r.state == "R4"]
    if external and all(r.authenticated for r in external):
        return Factor("true", Provenance.EXTRACTED, 0.9, "every reaching entry point requires auth")
    return UNKNOWN_AUTH


def _code_reach(index: GraphIndex, node: Node) -> tuple[Factor, Factor, Factor, list[str]]:
    """(reach, auth, sanitizer, entry points) for a finding in first-party code."""
    props = node.props
    path = props.get("path")
    none = UNKNOWN_AUTH
    if is_test_path(path):
        reason = "the file is test code and is not part of the shipped artefact"
        return Factor("R1", Provenance.EXTRACTED, 1.0, reason), none, none, []
    span = props.get("span") or [0, 0]
    on_line = [s for s in index.sinks.get(path or "", []) if span[0] <= s.props["line"] <= span[1]]
    wanted = {_CWE_FAMILY.get(c, c) for c in props.get("cwe") or []}
    # A finding with no CWE at all is matched by position; otherwise the weakness must agree
    # (a disabled TLS check on a line that also makes a request is not an SSRF finding).
    matching = [
        s
        for s in on_line
        if not wanted or _CWE_FAMILY.get(s.props["cwe"], s.props["cwe"]) in wanted
    ]
    if matching:
        ways: list[tuple[Reached, Edge]] = []
        tainted = False
        for sink in matching:
            for flow in index.flows.get(sink.id, []):
                tainted = True
                source = index.by_id[flow.src]
                where = index.located.get(source.id)
                found = index.reached(where)
                if found is None and source.props.get("function") is None:
                    found = index.reached_from_file(source.props["path"])
                if found is not None:
                    ways.append((found, flow))
        if not ways:
            reason = (
                "untrusted input reaches this call, but no known entry point leads to it"
                if tainted
                else "no path from untrusted input to this call was found"
            )
            return Factor("R0", Provenance.INFERRED, 0.0, reason), none, none, []
        state = "R4" if any(r.state == "R4" for r, _ in ways) else "R3"
        relevant = [(r, f) for r, f in ways if r.state == state]
        confidence = max(min(r.confidence, f.confidence) for r, f in relevant)
        entries = sorted({r.entry_point for r, _ in relevant})
        reach = Factor(
            state,
            Provenance.INFERRED,
            confidence,
            f"untrusted input flows from {entries[0].split(':', 1)[1]} to this call",
        )
        sanitizer = none
        if all(f.props["sanitized"] == "strong" for _, f in relevant):
            weakest = min(f.props["sanitizer_confidence"] for _, f in relevant)
            names = sorted({n for _, f in relevant for n in f.props["sanitized_by"]})
            sanitizer = Factor("true", Provenance.INFERRED, weakest, ", ".join(names))
        return reach, _auth([r for r, _ in relevant]), sanitizer, entries

    where = index.located.get(node.id)
    target = index.by_id.get(where) if where else None
    found = None
    if (
        target is not None
        and target.type is NodeType.FUNCTION
        and not target.props.get("synthetic")
    ):
        found = index.reached(target.id)
        what = "the enclosing function is called from"
    elif path:
        found = index.reached_from_file(path)
        what = "module-level code in a file served by"
    if found is None:
        reason = "no entry point is known to reach this code"
        return Factor("R0", Provenance.INFERRED, 0.0, reason), none, none, []
    reach = Factor(
        found.state,
        Provenance.INFERRED,
        found.confidence,
        f"{what} {found.entry_point.split(':', 1)[1]}",
    )
    return reach, _auth([found]), none, [found.entry_point]


def _advisory(index: GraphIndex, props: dict[str, object]) -> Node | None:
    ids = props.get("advisory_ids") or []
    assert isinstance(ids, list)
    return next((index.advisories[i] for i in sorted(ids) if i in index.advisories), None)


def _package_reach(index: GraphIndex, node: Node) -> tuple[Factor, Factor, list[str]]:
    props = node.props
    purl = str(props.get("purl") or "")
    package = index.packages.get(purl)
    scope = package.props.get("scope") if package is not None else None
    none = UNKNOWN_AUTH
    if scope in ("dev", "test"):
        reason = f"{scope}-only dependency: not in the shipped artefact"
        return Factor("R1", Provenance.EXTRACTED, 1.0, reason), none, []
    traced = props.get("tool_reachability")
    tool = f"{props.get('tool')} call analysis"
    ids = [*(props.get("advisory_ids") or []), props.get("rule_id")]
    uses = [e for i in sorted({str(i) for i in ids if i}) for e in index.uses.get((purl, i), [])]
    if traced == "symbol" or uses:
        reached = [(index.reached(e.src), e) for e in uses]
        hits = [(r, e) for r, e in reached if r is not None]
        by_tool = traced == "symbol"
        provenance = Provenance.TOOL if by_tool else Provenance.INFERRED
        if not hits:
            confidence = node.confidence if by_tool else max(e.confidence for e in uses)
            reason = "the vulnerable symbol is called; no entry point is known to lead there"
            return Factor("R3", provenance, confidence, reason), none, []
        state = "R4" if any(r.state == "R4" for r, _ in hits) else "R3"
        relevant = [(r, e) for r, e in hits if r.state == state]
        confidence = max(min(r.confidence, e.confidence) for r, e in relevant)
        entries = sorted({r.entry_point for r, _ in relevant})
        reason = f"the vulnerable symbol is called on a path from {entries[0].split(':', 1)[1]}"
        return (
            Factor(state, provenance, confidence, reason),
            _auth([r for r, _ in relevant]),
            entries,
        )
    if traced in ("package", "module"):
        reason = f"{tool}: the vulnerable symbol is not called"
        return Factor("R2", Provenance.TOOL, node.confidence, reason), none, []
    advisory = _advisory(index, props)
    if advisory is not None and advisory.props.get("symbols"):
        # We know the symbols and saw no call. In a best-effort call graph that is a hint.
        reason = "the advisory names its vulnerable symbols and no call to them was found"
        return Factor("R2", Provenance.INFERRED, NOT_CALLED_GUESS, reason), none, []
    reason = "the advisory has no symbol data, so use of the vulnerable code is unknown"
    return Factor("R0", Provenance.INFERRED, 0.0, reason), none, []


def _exploit_sca(index: GraphIndex, props: dict[str, object]) -> tuple[Factor, str]:
    advisory = _advisory(index, props)
    data = advisory.props if advisory is not None else {}
    kev, epss, public = data.get("kev"), data.get("epss"), data.get("exploit_public")
    kev_text = "unknown" if kev is None else str(bool(kev)).lower()
    if kev is True:
        return Factor("E3", Provenance.INTEL, 1.0, "listed in CISA KEV"), kev_text
    if public is True or (epss is not None and epss >= EPSS_E2):
        why = "public exploit" if public is True else f"EPSS {epss:.3f}"
        return Factor("E2", Provenance.INTEL, 1.0, why), kev_text
    if kev is None or epss is None:
        reason = "exploit intelligence is missing; assumed exploitable"
        return Factor("E2", Provenance.INTEL, 1.0, reason, assumed=True), kev_text
    # Below 1% EPSS is still E1: only unmet preconditions make a vulnerability E0.
    return Factor("E1", Provenance.INTEL, 1.0, f"EPSS {epss:.3f}, not in KEV"), kev_text


def _exploit_sast(raw: Severity, sanitizer: Factor) -> Factor:
    if sanitizer.value == "true" and sanitizer.qualifies:
        return Factor(
            "E0", sanitizer.provenance, sanitizer.confidence, "strong sanitizer on every path"
        )
    if raw in (Severity.CRITICAL, Severity.HIGH, Severity.UNKNOWN):
        return Factor("E2", Provenance.TOOL, 1.0, f"tool severity {raw.value}")
    return Factor("E1", Provenance.TOOL, 1.0, f"tool severity {raw.value}")


def _impact(index: GraphIndex, path: str | None) -> tuple[Factor, str | None, str | None]:
    """(impact, asset id, effective exposure)."""
    if not index.has_context:
        reason = "no business context file: impact assumed I2"
        return Factor("I2", Provenance.ASSERTED, 1.0, reason, assumed=True), None, None
    observed: tuple[str, float] | None = None
    for workload in index.workloads:
        level = workload.props.get("exposure")
        if (
            level in ("internet", "internal")
            and path
            and covers(workload.props["code_paths"], path)
        ):
            candidate = (level, min(workload.props["exposure_confidence"], workload.confidence))
            if observed is None or (candidate[0] == "internet", candidate[1]) > (
                observed[0] == "internet",
                observed[1],
            ):
                observed = candidate
    assets = index.assets.get(index.file_ids.get(path or "", ""), [])
    options: list[tuple[int, Factor, str | None, str]] = []
    candidates: list[Node | None] = [*assets] if assets else [None]
    for asset in candidates:
        props = asset.props if asset is not None else {}
        tier = int(props.get("tier") or index.context.defaults["tier"])
        classes = set(props.get("data_classes") or [])
        asserted = props.get("exposure")
        provenance, confidence = Provenance.ASSERTED, 1.0
        note = ""
        if asserted is None and observed is None:
            exposure, note = "internet", " (exposure unknown: treated as internet)"
        elif asserted is None and observed is not None:
            exposure = observed[0]
            if exposure != "internet":  # a favourable reading rests on the deploy files
                provenance, confidence = Provenance.INFERRED, observed[1]
            note = " (from deployment files)"
        elif observed is not None and observed[0] == "internet" and asserted != "internet":
            exposure, note = "internet", f" (context says {asserted}; deployment files disagree)"
        else:
            exposure = str(asserted)
        column = 0 if exposure == "internet" else 2 if exposure == "none" else 1
        if tier == 1 or classes & _SENSITIVE:
            level_ = (3, 2, 1)[column]
        elif tier == 2 or "PII" in classes:
            level_ = (2, 2, 1)[column]
        else:
            level_ = (1, 1, 0)[column]
        name = props.get("id")
        label = f"asset {name}" if name else "no asset; context defaults"
        detail = ", ".join(sorted(classes))
        reason = f"{label}: tier {tier}{', ' + detail if detail else ''}; exposure {exposure}{note}"
        options.append(
            (level_, Factor(f"I{level_}", provenance, confidence, reason), name, exposure)
        )
    worst = max(options, key=lambda o: (o[0], o[2] or ""))
    return worst[1], worst[2], worst[3]


def assess(index: GraphIndex, node: Node) -> Assessment:
    props = node.props
    category = props["category"]
    raw = Severity(props.get("group_severity") or props["raw_severity"])
    cwe = tuple(props.get("cwe") or ())
    path = props.get("path")
    if category == "secret":
        location = "unknown"
        if props.get("location") == "history":
            location = "history"
        elif props.get("location") == "file" and path:
            location = "ci_config" if _CI_PATH.search(path) else "src"
        fixture = is_test_path(path) or _FIXTURE_PATH.search(str(path or "")) is not None
        inputs = Inputs(
            "secret",
            raw,
            verified_live=str(props.get("verified_live") or "unknown"),
            location=location,
            test_fixture=fixture,
        )
        return Assessment(inputs, [])
    if category not in ("sast", "sca"):
        return Assessment(Inputs(category, raw, cwe=cwe), [])
    impact, asset, exposure = _impact(index, path)
    if category == "sca":
        reach, auth, entries = _package_reach(index, node)
        exploit, kev = _exploit_sca(index, props)
        inputs = Inputs("sca", raw, reach, exploit, impact, auth=auth, cwe=cwe, kev=kev)
        return Assessment(inputs, entries, asset, exposure)
    reach, auth, sanitizer, entries = _code_reach(index, node)
    exploit = _exploit_sast(raw, sanitizer)
    inputs = Inputs("sast", raw, reach, exploit, impact, auth=auth, sanitizer=sanitizer, cwe=cwe)
    return Assessment(inputs, entries, asset, exposure)
