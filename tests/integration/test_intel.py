"""M2-AC8: intel cache, refresh by the host process, offline behaviour, Advisory nodes."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from kurojisho.clock import FixedClock
from kurojisho.intel import refresh as r
from kurojisho.intel.advisories import IntelData
from kurojisho.intel.cache import IntelCache, cache_root
from kurojisho.intel.fetch import FetchError, HttpFetcher
from kurojisho.scanner import scan_with_tools
from kurojisho.store import Store
from kurojisho.store import queries as q
from kurojisho.tools.runners import RUNNERS, ScanOptions
from kurojisho.tools.runtime import RunResult
from tests.conftest import CLOCK, copy_fixture
from tests.helpers import PINS, FakeFetcher, FakeRuntime, all_handlers, make_intel, zip_bytes

LATER = FixedClock(datetime(2024, 1, 3, tzinfo=UTC))
SCA = {name: RUNNERS[name] for name in ("osv-scanner", "trivy", "grype")}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tar_gz(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


@pytest.fixture
def cache(tmp_path: Path) -> IntelCache:
    return IntelCache(tmp_path / "intel")


# -- cache ---------------------------------------------------------------------------------
def test_cache_manifest_staleness_and_snapshot(cache: IntelCache) -> None:
    assert (
        not cache.has("kev") and cache.stale("kev", CLOCK) and cache.age_hours("kev", CLOCK) is None
    )
    cache.record("kev", "a" * 64, CLOCK)
    cache.record("epss", "b" * 64, CLOCK)
    first = cache.snapshot_id()
    assert not cache.stale("kev", CLOCK) and cache.stale("kev", LATER)
    assert cache.age_hours("kev", LATER) == 48.0
    reloaded = IntelCache(cache.root)
    assert reloaded.sources == cache.sources and reloaded.snapshot_id() == first
    cache.record("kev", "a" * 64, LATER)  # re-fetched, same content: identity unchanged
    assert cache.snapshot_id() == first
    cache.record("kev", "c" * 64, LATER)
    assert cache.snapshot_id() != first
    assert cache.snapshot_id(["epss"]) == cache.snapshot_id(["epss", "absent"])
    (cache.root / "manifest.json").write_text("{broken")
    assert IntelCache(cache.root).sources == {}


def test_cache_root_follows_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("KUROJISHO_CACHE_DIR", str(tmp_path / "x"))
    assert cache_root() == tmp_path / "x"
    monkeypatch.delenv("KUROJISHO_CACHE_DIR")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert cache_root() == tmp_path / "xdg" / "kurojisho"


def test_fetcher_refuses_plain_http_without_touching_the_network(tmp_path: Path) -> None:
    fetcher = HttpFetcher()
    with pytest.raises(FetchError, match="https"):
        fetcher.get("http://example.invalid/x")
    with pytest.raises(FetchError, match="https"):
        fetcher.download("ftp://example.invalid/x", tmp_path / "x")
    assert not list(tmp_path.iterdir())


# -- refresh -------------------------------------------------------------------------------
def test_osv_refresh_uses_the_layout_the_scanner_reads(cache: IntelCache) -> None:
    data = zip_bytes({"GHSA-x.json": "{}"})
    done = r.refresh_osv(
        cache, FakeFetcher({r.OSV_URL.format(ecosystem="PyPI"): data}), CLOCK, "PyPI"
    )
    assert done == r.Refreshed("osv:PyPI", "updated")
    assert (cache.root / "osv/osv-scalibr/PyPI/all.zip").read_bytes() == data
    assert cache.sources["osv:PyPI"]["sha256"] == sha(data)
    failed = r.refresh_osv(cache, FakeFetcher({}), CLOCK, "npm")
    assert failed.status == "failed" and not cache.has("osv:npm")


def trivy_routes(layer: bytes, digest: str | None = None) -> dict[str, bytes]:
    digest = digest or "sha256:" + sha(layer)
    manifest = {"layers": [{"mediaType": r.TRIVY_LAYER, "digest": digest}]}
    base = f"{r.TRIVY_REGISTRY}/v2/{r.TRIVY_REPOSITORY}"
    return {
        f"{r.TRIVY_REGISTRY}/token": b'{"token": "t"}',
        f"{base}/manifests/": json.dumps(manifest).encode(),
        f"{base}/blobs/": layer,
    }


def test_trivy_refresh_verifies_the_digest_and_extracts_only_expected_files(
    cache: IntelCache,
) -> None:
    layer = tar_gz({"trivy.db": b"DB", "metadata.json": b"{}", "../escape": b"x", "sub/evil": b"x"})
    fetcher = FakeFetcher(trivy_routes(layer))
    assert r.refresh_trivy(cache, fetcher, CLOCK).status == "updated"
    assert sorted(p.name for p in (cache.root / "trivy/db").iterdir()) == [
        "metadata.json",
        "trivy.db",
    ]
    assert not (cache.root / "trivy/escape").exists() and not (cache.root / "escape").exists()
    assert not (cache.root / "trivy/db.tar.gz").exists()
    fetcher.requested.clear()
    assert r.refresh_trivy(cache, fetcher, LATER).status == "current"  # same digest: no download
    assert not any("/blobs/" in url for url in fetcher.requested)
    assert not cache.stale("trivy-db", LATER)


def test_trivy_refresh_rejects_a_layer_that_does_not_match(cache: IntelCache) -> None:
    layer = tar_gz({"trivy.db": b"DB"})
    tampered = FakeFetcher(trivy_routes(layer, "sha256:" + "0" * 64))
    done = r.refresh_trivy(cache, tampered, CLOCK)
    assert done.status == "failed" and "digest" in done.detail
    assert not cache.has("trivy-db") and not (cache.root / "trivy/db/trivy.db").exists()
    assert r.refresh_trivy(cache, FakeFetcher({}), CLOCK).status == "failed"
    bad = trivy_routes(layer, "md5:abc")
    assert r.refresh_trivy(cache, FakeFetcher(bad), CLOCK).status == "failed"


def grype_import(spec: Any, _out: Path) -> RunResult:
    assert spec.args[:2] == ("db", "import") and not spec.network
    database = next(m.source for m in spec.mounts if m.target == "/db")
    (database / "6").mkdir()
    (database / "6" / "vulnerability.db").write_bytes(b"indexed")
    return RunResult(0)


def test_grype_refresh_checks_the_archive_and_imports_in_the_sandbox(cache: IntelCache) -> None:
    archive = b"zstd-archive"
    listing = {
        "path": "vulnerability-db_v6.1.10_2026.tar.zst",
        "checksum": "sha256:" + sha(archive),
    }
    routes = {r.GRYPE_BASE + "latest.json": json.dumps(listing).encode(), r.GRYPE_BASE: archive}
    runtime = FakeRuntime({"grype": grype_import})
    assert (
        r.refresh_grype(cache, FakeFetcher(routes), CLOCK, runtime, PINS["grype"]).status
        == "updated"
    )
    assert (cache.root / "grype/db/6/vulnerability.db").is_file()
    assert "--network=none" in runtime.commands[0]
    assert (
        r.refresh_grype(cache, FakeFetcher(routes), CLOCK, runtime, PINS["grype"]).status
        == "current"
    )

    fresh = IntelCache(cache.root.parent / "other")
    assert (
        r.refresh_grype(fresh, FakeFetcher(routes), CLOCK, None, PINS["grype"]).status == "failed"
    )
    wrong = {**routes, r.GRYPE_BASE: b"different bytes"}
    done = r.refresh_grype(fresh, FakeFetcher(wrong), CLOCK, runtime, PINS["grype"])
    assert done.status == "failed" and "checksum" in done.detail
    hostile = {
        r.GRYPE_BASE + "latest.json": b'{"path": "../../x.tar.zst", "checksum": "sha256:00"}'
    }
    assert (
        r.refresh_grype(fresh, FakeFetcher(hostile), CLOCK, runtime, PINS["grype"]).status
        == "failed"
    )
    broken = FakeRuntime({"grype": lambda _s, _o: RunResult(1)})
    assert (
        r.refresh_grype(fresh, FakeFetcher(routes), CLOCK, broken, PINS["grype"]).status == "failed"
    )
    assert not fresh.has("grype-db")


def test_feeds_are_validated_before_they_replace_the_cached_copy(cache: IntelCache) -> None:
    kev = json.dumps(
        {"vulnerabilities": [{"cveID": "CVE-2024-1", "dateAdded": "2024-01-01"}]}
    ).encode()
    epss = gzip.compress(b"#v\ncve,epss,percentile\nCVE-2024-1,0.5,0.9\n")
    good = FakeFetcher({r.KEV_URL: kev, r.EPSS_URL: epss})
    assert r.refresh_kev(cache, good, CLOCK).status == "updated"
    assert r.refresh_epss(cache, good, CLOCK).status == "updated"
    bad = FakeFetcher({r.KEV_URL: b"<html>maintenance</html>", r.EPSS_URL: b"not gzip"})
    assert r.refresh_kev(cache, bad, LATER).status == "failed"
    assert r.refresh_epss(cache, bad, LATER).status == "failed"
    data = IntelData(cache)  # the earlier good copies are still what is read
    assert data.kev == {"CVE-2024-1": "2024-01-01"} and data.epss == {"CVE-2024-1": (0.5, 0.9)}
    assert cache.sources["kev"]["sha256"] == sha(kev)


def test_govulndb_refresh_writes_only_flat_json_members(cache: IntelCache) -> None:
    members = ["index/db.json", "ID/GO-2021-0001.json", "../evil.json", "ID/sub/x.json", "README"]
    bundle = zip_bytes(dict.fromkeys(members, "{}"))
    assert (
        r.refresh_govulndb(cache, FakeFetcher({r.GOVULNDB_URL: bundle}), CLOCK).status == "updated"
    )
    written = sorted(p.relative_to(cache.root / "govulndb").as_posix()
                     for p in (cache.root / "govulndb").rglob("*") if p.is_file())  # fmt: skip
    assert written == ["ID/GO-2021-0001.json", "index/db.json"]
    assert not (cache.root / "evil.json").exists()
    empty = IntelCache(cache.root.parent / "e")
    assert (
        r.refresh_govulndb(empty, FakeFetcher({r.GOVULNDB_URL: zip_bytes({})}), CLOCK).status
        == "failed"
    )
    assert (
        r.refresh_govulndb(empty, FakeFetcher({r.GOVULNDB_URL: b"junk"}), CLOCK).status == "failed"
    )


def test_nvd_refresh_respects_budget_rate_limit_and_cache(cache: IntelCache) -> None:
    record = json.dumps(
        {
            "vulnerabilities": [
                {"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}
            ]
        }
    ).encode()
    fetcher = FakeFetcher({"https://services.nvd.nist.gov/": record})
    naps: list[float] = []
    ids = [
        "CVE-2024-0003",
        "CVE-2024-0001",
        "CVE-2024-0002",
        "GHSA-not-a-cve",
        "CVE-2024-1; rm -rf",
    ]
    done = r.refresh_nvd(cache, fetcher, CLOCK, ids, budget=2, sleep=naps.append)
    assert done.detail == "2 fetched, 1 remaining" and naps == [r.NVD_DELAY_SECONDS]
    assert len(fetcher.requested) == 2 and all("cveId=CVE-2024-000" in u for u in fetcher.requested)
    again = r.refresh_nvd(cache, fetcher, CLOCK, ids, budget=5, sleep=naps.append, api_key="k")
    assert again.detail == "1 fetched, 0 remaining" and len(fetcher.requested) == 3
    assert (
        r.refresh_nvd(cache, fetcher, CLOCK, ids, budget=5, sleep=naps.append).status == "current"
    )
    assert IntelData(cache).nvd_score("CVE-2024-0001") == 9.8
    assert IntelData(cache).nvd_score("CVE-1999-0001") is None
    failing = r.refresh_nvd(
        cache, FakeFetcher({}), CLOCK, ["CVE-2025-0001"], budget=1, sleep=naps.append
    )
    assert failing.status == "failed"


def test_refresh_skips_fresh_sources_unless_forced(cache: IntelCache) -> None:
    kev = json.dumps({"vulnerabilities": []}).encode()
    fetcher = FakeFetcher({r.KEV_URL: kev})
    assert [d.status for d in r.refresh(cache, fetcher, CLOCK, ["kev"])] == ["updated"]
    assert [d.status for d in r.refresh(cache, fetcher, CLOCK, ["kev", "kev"])] == ["current"]
    assert len(fetcher.requested) == 1
    assert [d.status for d in r.refresh(cache, fetcher, LATER, ["kev"])] == ["updated"]  # a day old
    assert [d.status for d in r.refresh(cache, fetcher, LATER, ["kev"], force=True)] == ["updated"]
    assert [d.status for d in r.refresh(cache, fetcher, CLOCK, ["mystery"])] == ["failed"]


# -- dependency scanners and advisories ----------------------------------------------------
class Sca:
    def __init__(
        self, tmp_path: Path, intel: IntelCache | None, runners: dict[str, Any] = SCA
    ) -> None:
        self.root = copy_fixture("vuln_app", tmp_path)
        self.store = Store(tmp_path / "state" / "graph.db")
        self.runtime = FakeRuntime(all_handlers())
        self.intel = intel
        self.runners = runners
        self.messages: list[str] = []

    def run(self, clock: Any = CLOCK, fetcher: Any = None, **options: Any) -> dict[str, str]:
        _, outcomes = scan_with_tools(
            self.root, self.store, clock, runtime=self.runtime, options=ScanOptions(**options),
            runners=self.runners, intel=self.intel, fetcher=fetcher, notify=self.messages.append,
        )  # fmt: skip
        return {o.tool: o.status for o in outcomes}

    def nodes(self, kind: str) -> list[dict[str, Any]]:
        return q.find_nodes(self.store, node_type=kind)


def test_three_dependency_scanners_merge_into_advisories(tmp_path: Path) -> None:
    sca = Sca(tmp_path, make_intel(tmp_path / "intel", CLOCK))
    assert sca.run() == {"grype": "ok", "osv-scanner": "ok", "trivy": "ok"}
    findings = sca.nodes("Finding")
    per_tool = {t: sum(1 for f in findings if f["props"]["tool"] == t) for t in SCA}
    assert per_tool == {"osv-scanner": 44, "trivy": 45, "grype": 44}
    canonical = [f for f in findings if f["props"]["canonical"]]
    advisories = {a["name"]: a for a in sca.nodes("Advisory")}
    assert len(canonical) == len(advisories) == 45  # 133 reports, 45 distinct issues
    assert {f["props"]["tool"] for f in canonical} == {"osv-scanner", "trivy"}

    log4shell = advisories["CVE-2021-44228"]
    assert log4shell["provenance"] == "INTEL"
    props = log4shell["props"]
    assert props["aliases"] == ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"]
    assert props["kev"] is True and props["kev_added"] == "2021-12-10"
    assert (props["epss"], props["epss_percentile"]) == (0.975, 0.9999)
    assert props["cvss"] == 10.0 and props["cvss_v3_vector"].startswith("CVSS:3.1/AV:N")
    assert props["summary"] == "Remote code injection in Log4j" and props["exploit_public"] is None
    assert props["reported_by"] == ["grype", "osv-scanner", "trivy"]
    assert "2.15.0" in props["fixed_versions"]
    assert log4shell["evidence"][0]["source"] == "intel:osv+kev+epss"
    flask = advisories["CVE-2018-1000656"]["props"]
    assert flask["kev"] is False and flask["epss"] == 0.003  # KEV loaded and it is not listed
    assert flask["summary"] is None  # no OSV record in this small cache: unknown, not invented

    edge = sca.store.conn.execute(
        "SELECT p.key, e.provenance, e.props FROM edges e JOIN nodes p ON p.id = e.src "
        "WHERE e.type = 'AFFECTED_BY' AND e.dst = ?", (log4shell["id"],),
    ).fetchone()  # fmt: skip
    assert edge[0] == "Package:pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert edge[1] == "TOOL" and json.loads(edge[2])["reported_by"] == [
        "grype",
        "osv-scanner",
        "trivy",
    ]
    high = [f for f in canonical if f["props"]["purl"].startswith("pkg:maven/org.apache.logging")]
    assert any(f["props"]["group_severity"] == "Critical" for f in high)
    assert sca.nodes("CoverageGap") == []
    for command in sca.runtime.commands:
        assert "--network=none" in command
        assert any(a.startswith("--mount=") and "target=/intel,readonly" in a for a in command)


def test_without_databases_dependency_scanners_are_gaps_not_clean_results(tmp_path: Path) -> None:
    sca = Sca(tmp_path, None)
    assert set(sca.run().values()) == {"offline_db_missing"}
    assert sca.runtime.runs == [] and sca.nodes("Finding") == []
    assert len(sca.nodes("CoverageGap")) == 3
    partial = Sca(tmp_path / "p", IntelCache(tmp_path / "empty"))
    partial.intel.record("trivy-db", "t" * 64, CLOCK)  # type: ignore[union-attr]
    partial.intel.dir("trivy")  # type: ignore[union-attr]
    statuses = partial.run()
    assert statuses == {
        "grype": "offline_db_missing",
        "osv-scanner": "offline_db_missing",
        "trivy": "ok",
    }
    # advisories exist from what Trivy said, but exploitation data is unknown and flagged
    advisory = partial.nodes("Advisory")[0]
    assert advisory["provenance"] == "TOOL" and advisory["props"]["kev"] is None
    assert advisory["props"]["epss"] is None
    gaps = {g["props"]["reason"]: g["props"] for g in partial.nodes("CoverageGap")}
    assert gaps["intel_missing"]["sources"] == ["kev", "epss"]


def test_stale_intel_is_flagged_and_offline_never_fetches(tmp_path: Path) -> None:
    sca = Sca(tmp_path, make_intel(tmp_path / "intel", CLOCK))
    fetcher = FakeFetcher({})
    assert set(sca.run(clock=LATER, fetcher=fetcher, offline=True).values()) == {"ok"}
    assert fetcher.requested == [] and sca.messages == []
    stale = next(g for g in sca.nodes("CoverageGap") if g["props"]["reason"] == "intel_stale")
    assert "trivy-db" in stale["props"]["sources"] and "kev" in stale["props"]["sources"]


def test_online_scan_refreshes_stale_sources_first_and_says_so(tmp_path: Path) -> None:
    intel = make_intel(tmp_path / "intel", CLOCK)
    kev = json.dumps({"vulnerabilities": []}).encode()
    fetcher = FakeFetcher({r.KEV_URL: kev})  # everything else is unreachable
    sca = Sca(tmp_path, intel, {"trivy": RUNNERS["trivy"]})
    assert sca.run(clock=LATER, fetcher=fetcher) == {"trivy": "ok"}  # old database still usable
    assert sca.messages[0].startswith("refreshing vulnerability data (network): ")
    assert any(m.startswith("could not refresh trivy-db") for m in sca.messages)
    assert not intel.stale("kev", LATER) and intel.stale("trivy-db", LATER)
    assert any(u == r.KEV_URL for u in fetcher.requested)
    # KEV was replaced by an empty list: Log4Shell is now "not in KEV", a real change in output
    advisory = next(a for a in sca.nodes("Advisory") if a["name"] == "CVE-2021-44228")
    assert advisory["props"]["kev"] is False
    fetcher.requested.clear()
    sca.run(clock=LATER, fetcher=fetcher)
    assert r.KEV_URL not in fetcher.requested  # fresh now: not fetched again


def test_intel_snapshot_is_part_of_the_result_cache_key(tmp_path: Path) -> None:
    intel = make_intel(tmp_path / "intel", CLOCK)
    sca = Sca(tmp_path, intel, {"trivy": RUNNERS["trivy"]})
    assert sca.run() == {"trivy": "ok"}
    assert sca.run() == {"trivy": "cached"}
    intel.record("trivy-db", "n" * 64, CLOCK)  # a new database: old results no longer apply
    assert sca.run() == {"trivy": "ok"}


def test_trivy_config_needs_no_database_and_reports_misconfigurations(tmp_path: Path) -> None:
    sca = Sca(tmp_path, None, {"trivy-config": RUNNERS["trivy-config"]})
    assert sca.run() == {"trivy-config": "ok"}
    got = sca.nodes("Finding")
    assert len(got) == 37 and {f["props"]["category"] for f in got} == {"iac"}
    latest = next(f for f in got if f["name"] == "DS-0001")
    assert latest["props"]["path"] == "deploy/Dockerfile" and latest["props"]["span"] == [1, 1]
    assert latest["props"]["raw_severity"] == "Medium" and latest["props"]["tool"] == "trivy-config"
    assert "FROM python" not in json.dumps(got)
    assert (
        sca.store.conn.execute("SELECT version FROM tool_runs").fetchone()[0]
        == PINS["trivy"].version
    )
