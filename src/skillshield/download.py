"""Download a skill from a GitHub URL and unpack it for scanning.

SkillShield is offline unless it is handed a github.com URL. Only the standard
library is used (urllib, zipfile, tempfile); nothing downloaded is executed.
"""

from __future__ import annotations

import io
import re
import shutil
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_UNPACKED_BYTES = 500 * 1024 * 1024  # 500 MB, guards against zip bombs
MAX_ARCHIVE_FILES = 10_000
DOWNLOAD_TIMEOUT = 30.0
_GITHUB_HOSTS = {"github.com", "www.github.com"}
_COMMIT_RE = re.compile(r"(?<=/zip/)([0-9a-f]{40})|(?<=/archive/)([0-9a-f]{40})")
_SHA_RE = re.compile(r"[0-9a-f]{40}")


class DownloadError(Exception):
    """A download or unpacking problem. Nothing was scanned."""


@dataclass
class DownloadedArchive:
    """Unpacked GitHub archive; ``scan_dir`` is the folder to scan."""

    directory: Path
    scan_dir: Path
    commit: str | None
    url: str

    def __enter__(self) -> "DownloadedArchive":
        return self

    def __exit__(self, *exc) -> bool:
        shutil.rmtree(self.directory, ignore_errors=True)
        return False


def is_github_url(target: str) -> bool:
    """True when ``target`` is a github.com URL this module can download."""
    parsed = urlparse(target)
    return parsed.scheme in ("http", "https") and parsed.netloc.lower() in _GITHUB_HOSTS


def parse_github_url(url: str) -> tuple[str, str, str | None, list[str]]:
    """Split a github.com URL into (owner, repo, ref, subpath)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.netloc.lower() not in _GITHUB_HOSTS:
        raise DownloadError(f"not a github.com URL: {url}")
    segments = [s for s in parsed.path.split("/") if s]
    if len(segments) < 2:
        raise DownloadError(f"not a repository URL: {url}")
    owner, repo = segments[0], segments[1].removesuffix(".git")
    if not repo:
        raise DownloadError(f"not a repository URL: {url}")
    ref = None
    subpath: list[str] = []
    rest = segments[2:]
    if rest:
        if rest[0] not in ("tree", "blob") or len(rest) < 2:
            raise DownloadError(f"unsupported GitHub URL path: {url}")
        ref = rest[1]
        subpath = rest[2:]
    return owner, repo, ref, subpath


def _download_archive(owner: str, repo: str, ref: str | None) -> tuple[bytes, str | None]:
    url = f"https://codeload.github.com/{owner}/{repo}/zip/{ref or 'HEAD'}"
    request = urllib.request.Request(url, headers={"User-Agent": "skillshield"})
    try:
        with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response:
            commit = None
            final = getattr(response, "geturl", lambda: "")()
            match = _COMMIT_RE.search(final)
            if match:
                commit = next(group for group in match.groups() if group)
            else:
                sha = _SHA_RE.search(response.headers.get("ETag") or "")
                commit = sha.group(0) if sha else None
            data = b""
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                data += chunk
                if len(data) > MAX_DOWNLOAD_BYTES:
                    raise DownloadError("download exceeds the 50 MB limit")
        return data, commit
    except DownloadError:
        raise
    except Exception as exc:
        raise DownloadError(f"could not download {url}: {exc}") from exc


def _check_zip_entry(info: zipfile.ZipInfo) -> None:
    name = info.filename.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[a-zA-Z]:", name):
        raise DownloadError(f"zip-slip refused: absolute path {info.filename!r}")
    if ".." in name.split("/"):
        raise DownloadError(f"zip-slip refused: '..' in {info.filename!r}")
    if ((info.external_attr >> 16) & 0o170000) == 0o120000:
        raise DownloadError(f"zip-slip refused: symlink {info.filename!r}")


def _safe_extract(data: bytes, destination: Path) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_FILES:
                raise DownloadError(f"archive contains more than {MAX_ARCHIVE_FILES} files")
            total = 0
            for info in infos:
                _check_zip_entry(info)
                total += info.file_size
                if total > MAX_UNPACKED_BYTES:
                    raise DownloadError("archive unpacks to more than the 500 MB limit")
            archive.extractall(destination)
    except DownloadError:
        raise
    except Exception as exc:
        raise DownloadError(f"could not unpack archive: {exc}") from exc


def _resolve_scan_dir(root: Path, subpath: list[str], url: str) -> Path:
    """Join ``subpath`` onto ``root``, refusing anything that escapes it."""
    for part in subpath:
        if part in ("", ".", "..") or part.startswith("/") or re.match(r"^[a-zA-Z]:", part):
            raise DownloadError(f"refused unsafe path segment {part!r} in {url}")
    scan_dir = root.joinpath(*subpath).resolve()
    if not scan_dir.is_relative_to(root.resolve()):
        raise DownloadError(f"refused path outside the archive in {url}")
    if not scan_dir.exists():
        raise DownloadError(f"{url} does not contain the requested folder")
    return scan_dir


def fetch_github(url: str) -> DownloadedArchive:
    """Download a GitHub archive, unpack it safely, and point at the scan folder."""
    owner, repo, ref, subpath = parse_github_url(url)
    data, commit = _download_archive(owner, repo, ref)
    directory = Path(tempfile.mkdtemp(prefix="skillshield-"))
    try:
        _safe_extract(data, directory)
        root = next((entry for entry in directory.iterdir() if entry.is_dir()), directory)
        scan_dir = _resolve_scan_dir(root, subpath, url)
        return DownloadedArchive(directory=directory, scan_dir=scan_dir, commit=commit, url=url)
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
