"""Fetch vulnerability intelligence into the cache. This is the host process talking to the
network; scanners themselves never do."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import shutil
import tarfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from kurojisho.clock import Clock
from kurojisho.intel.cache import IntelCache
from kurojisho.intel.fetch import Fetcher, FetchError
from kurojisho.tools.lock import ToolPin
from kurojisho.tools.runtime import Runtime
from kurojisho.tools.sandbox import SRC, Mount, RunSpec

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
OSV_ECOSYSTEMS = ("PyPI", "npm", "Go", "Maven")
#: Other lockfiles OSV-Scanner understands -> the database it will then ask for.
OSV_EXTRA = {
    "Cargo.lock": "crates.io",
    "Gemfile.lock": "RubyGems",
    "composer.lock": "Packagist",
    "packages.lock.json": "NuGet",
    "pubspec.lock": "Pub",
    "mix.lock": "Hex",
}
TRIVY_REGISTRY = "https://ghcr.io"
TRIVY_REPOSITORY = "aquasecurity/trivy-db"
TRIVY_TAG = "2"
TRIVY_LAYER = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
GRYPE_BASE = "https://grype.anchore.io/databases/v6/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
GOVULNDB_URL = "https://vuln.go.dev/vulndb.zip"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
#: NVD allows 5 requests per 30 seconds without an API key.
NVD_DELAY_SECONDS = 6.5
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_GOVULN_MEMBER = re.compile(r"^(ID|index)/[A-Za-z0-9._-]+\.json$")
_GRYPE_ARCHIVE = re.compile(r"^[A-Za-z0-9._:-]+\.tar\.zst$")


@dataclass(frozen=True)
class Refreshed:
    source: str
    status: str  # updated | current | failed
    detail: str = ""


def osv_source(ecosystem: str) -> str:
    return f"osv:{ecosystem}"


def refresh_osv(cache: IntelCache, fetcher: Fetcher, clock: Clock, ecosystem: str) -> Refreshed:
    source = osv_source(ecosystem)
    # OSV-Scanner 2.x looks for <dir>/osv-scalibr/<ecosystem>/all.zip
    target = cache.dir(f"osv/osv-scalibr/{ecosystem}") / "all.zip"
    try:
        digest = fetcher.download(OSV_URL.format(ecosystem=ecosystem), target)
    except FetchError as exc:
        return Refreshed(source, "failed", str(exc))
    cache.record(source, digest, clock)
    return Refreshed(source, "updated")


def refresh_trivy(cache: IntelCache, fetcher: Fetcher, clock: Clock) -> Refreshed:
    """Pull the trivy-db OCI artifact, verify the layer digest, unpack its two files."""
    try:
        token_url = f"{TRIVY_REGISTRY}/token?scope=repository:{TRIVY_REPOSITORY}:pull"
        token = json.loads(fetcher.get(token_url))["token"]
        auth = {"Authorization": f"Bearer {token}"}
        manifest = json.loads(
            fetcher.get(
                f"{TRIVY_REGISTRY}/v2/{TRIVY_REPOSITORY}/manifests/{TRIVY_TAG}",
                {**auth, "Accept": "application/vnd.oci.image.manifest.v1+json"},
            )
        )
        layer = next(entry for entry in manifest["layers"] if entry["mediaType"] == TRIVY_LAYER)
        digest = str(layer["digest"])
        if not _SHA.match(digest):
            raise FetchError("trivy-db manifest has no sha256 layer digest")
        if cache.sources.get("trivy-db", {}).get("sha256") == digest[7:]:
            cache.record("trivy-db", digest[7:], clock)
            return Refreshed("trivy-db", "current")
        archive = cache.dir("trivy") / "db.tar.gz"
        got = fetcher.download(
            f"{TRIVY_REGISTRY}/v2/{TRIVY_REPOSITORY}/blobs/{digest}", archive, auth
        )
        if got != digest[7:]:
            archive.unlink(missing_ok=True)
            raise FetchError("trivy-db layer does not match its digest")
        _extract(archive, cache.dir("trivy/db"), {"trivy.db", "metadata.json"})
        archive.unlink()
    except (
        FetchError,
        KeyError,
        StopIteration,
        ValueError,
        TypeError,
        OSError,
        tarfile.TarError,
    ) as exc:
        return Refreshed("trivy-db", "failed", str(exc) or type(exc).__name__)
    cache.record("trivy-db", digest[7:], clock)
    return Refreshed("trivy-db", "updated")


def _extract(archive: Path, dest: Path, allowed: set[str]) -> None:
    """Extract only the expected regular files; anything else in the archive is ignored."""
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            name = member.name.lstrip("./")
            if name in allowed and member.isfile():
                source = tar.extractfile(member)
                if source is not None:
                    with (dest / name).open("wb") as handle:
                        shutil.copyfileobj(source, handle)


def refresh_grype(
    cache: IntelCache, fetcher: Fetcher, clock: Clock, runtime: Runtime | None, pin: ToolPin
) -> Refreshed:
    """Download the Grype v6 archive, verify its checksum, and let Grype itself (sandboxed,
    no network) unpack and index it."""
    try:
        latest = json.loads(fetcher.get(GRYPE_BASE + "latest.json"))
        name, checksum = str(latest["path"]), str(latest["checksum"])
        if not _GRYPE_ARCHIVE.match(name) or not _SHA.match(checksum):
            raise FetchError("unexpected Grype database listing")
        if cache.sources.get("grype-db", {}).get("sha256") == checksum[7:]:
            cache.record("grype-db", checksum[7:], clock)
            return Refreshed("grype-db", "current")
        if runtime is None:
            raise FetchError("a container runtime is needed to import the Grype database")
        staging = cache.dir("grype/staging")
        archive = staging / "db.tar.zst"
        if fetcher.download(GRYPE_BASE + name, archive) != checksum[7:]:
            archive.unlink(missing_ok=True)
            raise FetchError("Grype database does not match its checksum")
        database = cache.dir("grype/db")
        done = runtime.run(
            RunSpec(
                image=pin.ref,
                args=("db", "import", f"{SRC}/db.tar.zst"),
                mounts=(Mount(staging, SRC), Mount(database, "/db", read_only=False)),
                env={"GRYPE_DB_CACHE_DIR": "/db", "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                     "TMPDIR": "/db", "SQLITE_TMPDIR": "/db"},
                workdir="/db",
                memory_mb=6144,
                timeout_s=1800,
            )
        )  # fmt: skip
        archive.unlink(missing_ok=True)
        if done.exit_code != 0 or not (database / "6" / "vulnerability.db").is_file():
            raise FetchError("grype could not import the database")
    except (FetchError, KeyError, ValueError, TypeError, OSError) as exc:
        return Refreshed("grype-db", "failed", str(exc) or type(exc).__name__)
    cache.record("grype-db", checksum[7:], clock)
    return Refreshed("grype-db", "updated")


def refresh_govulndb(cache: IntelCache, fetcher: Fetcher, clock: Clock) -> Refreshed:
    """The Go vulnerability database, unpacked the way ``govulncheck -db file://`` reads it."""
    staging = cache.dir("govulndb-staging")
    archive = staging / "vulndb.zip"
    try:
        digest = fetcher.download(GOVULNDB_URL, archive)
        target = cache.dir("govulndb")
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                if not _GOVULN_MEMBER.match(member.filename) or member.file_size > 16 * 1024 * 1024:
                    continue  # only flat ID/*.json and index/*.json are ever written
                destination = target / member.filename
                destination.parent.mkdir(exist_ok=True)
                with bundle.open(member) as source, destination.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
        archive.unlink()
        if not (target / "index" / "db.json").is_file():
            raise FetchError("Go vulnerability database has no index")
    except (FetchError, OSError, zipfile.BadZipFile) as exc:
        return Refreshed("govulndb", "failed", str(exc) or type(exc).__name__)
    cache.record("govulndb", digest, clock)
    return Refreshed("govulndb", "updated")


def _feed(
    cache: IntelCache, fetcher: Fetcher, clock: Clock, source: str, url: str, name: str,
    check: Callable[[bytes], None],
) -> Refreshed:  # fmt: skip
    try:
        data = fetcher.get(url)
        check(data)
    except (FetchError, ValueError, KeyError, OSError, EOFError) as exc:
        return Refreshed(source, "failed", str(exc) or type(exc).__name__)
    target = cache.dir("feeds") / name
    temporary = target.with_suffix(".part")
    temporary.write_bytes(data)
    temporary.replace(target)
    cache.record(source, hashlib.sha256(data).hexdigest(), clock)
    return Refreshed(source, "updated")


def _check_kev(data: bytes) -> None:
    if not isinstance(json.loads(data)["vulnerabilities"], list):
        raise ValueError("KEV feed has no vulnerabilities list")


def _check_epss(data: bytes) -> None:
    head = gzip.GzipFile(fileobj=io.BytesIO(data)).read(4096).decode("utf-8", "replace")
    if "cve,epss" not in head:
        raise ValueError("EPSS feed has an unexpected header")


def refresh_kev(cache: IntelCache, fetcher: Fetcher, clock: Clock) -> Refreshed:
    return _feed(cache, fetcher, clock, "kev", KEV_URL, "kev.json", _check_kev)


def refresh_epss(cache: IntelCache, fetcher: Fetcher, clock: Clock) -> Refreshed:
    return _feed(cache, fetcher, clock, "epss", EPSS_URL, "epss.csv.gz", _check_epss)


def refresh_nvd(
    cache: IntelCache,
    fetcher: Fetcher,
    clock: Clock,
    cve_ids: list[str],
    *,
    budget: int,
    sleep: Callable[[float], None],
    api_key: str | None = None,
) -> Refreshed:
    """Fetch NVD records for CVEs not yet cached, within NVD's rate limit. ``budget`` caps
    the requests per call; the rest are picked up by later refreshes."""
    directory = cache.dir("nvd")
    wanted = [
        c for c in sorted(set(cve_ids)) if _CVE.match(c) and not (directory / f"{c}.json").exists()
    ]
    fetched = 0
    headers = {"apiKey": api_key} if api_key else None
    for cve in wanted[:budget]:
        if fetched:
            sleep(0.7 if api_key else NVD_DELAY_SECONDS)
        try:
            data = fetcher.get(NVD_URL.format(cve=cve), headers)
            json.loads(data)["vulnerabilities"]
        except (FetchError, ValueError, KeyError) as exc:
            return Refreshed("nvd", "failed", f"{cve}: {exc}")
        (directory / f"{cve}.json").write_bytes(data)
        fetched += 1
    digest = hashlib.sha256()
    for path in sorted(directory.glob("CVE-*.json")):
        digest.update(path.name.encode() + hashlib.sha256(path.read_bytes()).digest())
    cache.record("nvd", digest.hexdigest(), clock)
    remaining = len(wanted) - fetched
    return Refreshed(
        "nvd", "updated" if fetched else "current", f"{fetched} fetched, {remaining} remaining"
    )


def refresh(
    cache: IntelCache,
    fetcher: Fetcher,
    clock: Clock,
    sources: list[str],
    *,
    runtime: Runtime | None = None,
    grype: ToolPin | None = None,
    force: bool = False,
) -> list[Refreshed]:
    """Refresh each named source that is missing or older than a day (or all, with force)."""
    results = []
    for source in sorted(set(sources)):
        if not force and not cache.stale(source, clock):
            results.append(Refreshed(source, "current"))
        elif source.startswith("osv:"):
            results.append(refresh_osv(cache, fetcher, clock, source[4:]))
        elif source == "trivy-db":
            results.append(refresh_trivy(cache, fetcher, clock))
        elif source == "grype-db" and grype is not None:
            results.append(refresh_grype(cache, fetcher, clock, runtime, grype))
        elif source == "govulndb":
            results.append(refresh_govulndb(cache, fetcher, clock))
        elif source == "kev":
            results.append(refresh_kev(cache, fetcher, clock))
        elif source == "epss":
            results.append(refresh_epss(cache, fetcher, clock))
        else:
            results.append(Refreshed(source, "failed", "unknown source"))
    return results
