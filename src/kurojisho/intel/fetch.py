"""HTTP for intel refresh. HTTPS only, bounded size, no credentials, a generic user agent."""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Protocol

from kurojisho import __version__

DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024
_CHUNK = 1 << 20


class FetchError(RuntimeError):
    """A download failed. The previous copy, if any, is left in place."""


class Fetcher(Protocol):
    def get(self, url: str, headers: dict[str, str] | None = None) -> bytes: ...
    def download(self, url: str, dest: Path, headers: dict[str, str] | None = None) -> str: ...


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not newurl.startswith("https://"):
            raise FetchError(f"refusing non-HTTPS redirect to {newurl.split('?')[0]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpFetcher:
    def __init__(self, timeout: int = 60, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._opener = urllib.request.build_opener(_HttpsOnly())

    def _open(self, url: str, headers: dict[str, str] | None):  # type: ignore[no-untyped-def]
        if not url.startswith("https://"):
            raise FetchError("only https:// URLs are fetched")
        request = urllib.request.Request(  # noqa: S310 - scheme checked above
            url, headers={"User-Agent": f"kurojisho/{__version__}", **(headers or {})}
        )
        try:
            return self._opener.open(request, timeout=self.timeout)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise FetchError(f"could not fetch {url.split('?')[0]}: {exc}") from exc

    def get(self, url: str, headers: dict[str, str] | None = None) -> bytes:
        with self._open(url, headers) as response:
            data: bytes = response.read(64 * 1024 * 1024 + 1)
        if len(data) > 64 * 1024 * 1024:
            raise FetchError("response too large")
        return data

    def download(self, url: str, dest: Path, headers: dict[str, str] | None = None) -> str:
        """Stream ``url`` to ``dest`` atomically; returns the SHA-256 of the content."""
        digest = hashlib.sha256()
        temporary = dest.with_name(dest.name + ".part")
        total = 0
        try:
            with self._open(url, headers) as response, temporary.open("wb") as handle:
                while chunk := response.read(_CHUNK):
                    total += len(chunk)
                    if total > self.max_bytes:
                        raise FetchError("download exceeds the size limit")
                    digest.update(chunk)
                    handle.write(chunk)
            temporary.replace(dest)
        except OSError as exc:
            raise FetchError(f"could not save {dest.name}: {exc}") from exc
        finally:
            temporary.unlink(missing_ok=True)
        return digest.hexdigest()
