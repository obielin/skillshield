"""Tests for scanning a skill from a GitHub URL (issue #100).

These never touch the network: ``urlopen`` is patched to serve a local zip,
including a malicious sample from ``tests/fixtures/redteam/`` and zip-slip
archives.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from skillshield import cli, download

MALICIOUS = Path(__file__).parent / "fixtures" / "redteam" / "malicious" / "01-plain-injection.md"


class FakeResponse:
    def __init__(self, data, commit=None):
        self._buf = data
        self._pos = 0
        self.commit = commit
        self.headers = {"ETag": f'"{commit}"'} if commit else {}

    def read(self, n=-1):
        n = len(self._buf) - self._pos if n < 0 else n
        chunk = self._buf[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk

    def geturl(self):
        return f"https://codeload.github.com/o/r/zip/{self.commit}" if self.commit else "https://x/zip/HEAD"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def skill_zip(skill=("skills/clean/SKILL.md", b"# clean\n"), root="repo-main"):
    return make_zip({f"{root}/{skill[0]}": skill[1]})


def run_cli(monkeypatch, *argv):
    import builtins

    captured = io.StringIO()
    real_print = builtins.print
    builtins.print = lambda *a, **k: real_print(*a, file=captured, **k)
    try:
        with patch.object(sys, "argv", ["skillshield", *argv]):
            with pytest.raises(SystemExit) as ei:
                cli.main()
    finally:
        builtins.print = real_print
    return ei.value.code, captured.getvalue()


@pytest.fixture
def patch_urlopen():
    def install(data, commit=None):
        return patch.object(download.urllib.request, "urlopen", return_value=FakeResponse(data, commit))

    return install


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/owner/repo", ("owner", "repo", None, [])),
        ("https://github.com/owner/repo/tree/main/skills/my", ("owner", "repo", "main", ["skills", "my"])),
        ("https://github.com/owner/repo.git", ("owner", "repo", None, [])),
    ],
)
def test_parse_github_url(url, expected):
    assert download.parse_github_url(url) == expected


@pytest.mark.parametrize(
    "url",
    ["https://github.com/owner/repo/commits/HEAD", "https://example.com/owner/repo", "https://github.com/owner"],
)
def test_parse_rejects_bad_url(url):
    with pytest.raises(download.DownloadError):
        download.parse_github_url(url)


def test_scan_clean_repo_exit_0(monkeypatch, patch_urlopen):
    with patch_urlopen(skill_zip(), commit="a" * 40):
        code, out = run_cli(monkeypatch, "scan", "https://github.com/owner/repo")
    assert code == 0
    assert "https://github.com/owner/repo" in out and "a" * 40 in out


def test_scan_malicious_sample_flagged(monkeypatch, patch_urlopen):
    data = make_zip({"repo-main/skills/evil/SKILL.md": MALICIOUS.read_bytes()})
    with patch_urlopen(data):
        code, out = run_cli(monkeypatch, "scan", "https://github.com/owner/repo")
    assert code == 1 and "SG-001" in out


def test_scan_subfolder_only(monkeypatch, patch_urlopen):
    data = make_zip(
        {
            "repo-main/skills/clean/SKILL.md": b"# clean\n",
            "repo-main/skills/evil/SKILL.md": MALICIOUS.read_bytes(),
        }
    )
    with patch_urlopen(data):
        code, _ = run_cli(monkeypatch, "scan", "https://github.com/owner/repo/tree/main/skills/clean")
    assert code == 0
    with patch_urlopen(data):
        code, _ = run_cli(monkeypatch, "scan", "https://github.com/owner/repo/tree/main/skills/evil")
    assert code == 1


def test_json_output_names_source(monkeypatch, patch_urlopen):
    import json

    with patch_urlopen(skill_zip(), commit="b" * 40):
        code, out = run_cli(monkeypatch, "scan", "https://github.com/owner/repo", "--format", "json")
    assert code == 0
    assert json.loads(out)["source"] == "https://github.com/owner/repo (commit " + "b" * 40 + ")"


@pytest.mark.parametrize(
    "kind",
    ["size", "count", "dotdot", "absolute", "traversal", "symlink"],
)
def test_defensive_limits_stop_scan(monkeypatch, patch_urlopen, kind):
    if kind == "symlink":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("repo-main/link")
            info.external_attr = (0o120000 << 16) | 0o777
            zf.writestr(info, b"target")
        bad = buf.getvalue()
    else:
        bad = {
            "size": b"x" * (download.MAX_DOWNLOAD_BYTES + 1),
            "count": make_zip({f"repo-main/f{i}.md": b"x" for i in range(download.MAX_ARCHIVE_FILES + 1)}),
            "dotdot": make_zip({"../evil.sh": b"x"}),
            "absolute": make_zip({"/abs/evil.sh": b"x"}),
            "traversal": make_zip({"repo-main/../../evil.sh": b"x"}),
        }[kind]
    with patch_urlopen(bad):
        code, out = run_cli(monkeypatch, "scan", "https://github.com/owner/repo")
    assert code == 2 and "Error:" in out


def test_timeout_exits_2(monkeypatch, patch_urlopen):
    with patch.object(download.urllib.request, "urlopen", side_effect=TimeoutError("timed out")):
        code, out = run_cli(monkeypatch, "scan", "https://github.com/owner/repo")
    assert code == 2 and "timed out" in out


def test_temp_folder_deleted_even_on_scan_failure(monkeypatch, patch_urlopen):
    import shutil
    import tempfile

    created = []
    real_mkdtemp = tempfile.mkdtemp
    real_rmtree = shutil.rmtree

    def mkdtemp(*a, **k):
        p = Path(real_mkdtemp(*a, **k))
        created.append(p)
        return str(p)

    def rmtree(p, *a, **k):
        p = Path(p)
        if p in created:
            created.remove(p)
        return real_rmtree(p, *a, **k)

    with patch_urlopen(skill_zip()), patch.object(tempfile, "mkdtemp", mkdtemp), patch.object(
        shutil, "rmtree", rmtree
    ):
        run_cli(monkeypatch, "scan", "https://github.com/owner/repo")
    assert created == []
