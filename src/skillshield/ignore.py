"""
Accept reviewed findings with a reason, through a ``.skillshield-ignore`` file.

Each line accepts one rule for a set of paths, or one exact finding, and must say why:

    # rule or fingerprint    path glob         reason (required)
    SG-004                   docs/attacks/**   Attack phrases quoted as examples in our docs
    fp:3f9a1c0e7b2d4a55      -                 Reviewed 2026-11-21: installer pins a hash

The first column is a rule ID or a finding fingerprint (``fp:`` and 16 hex characters).
The second is a path glob relative to the ignore file, or ``-`` for any path. Everything
after it is the reason. ``*`` matches within one folder, ``**`` across folders.

A rule entry accepts findings up to HIGH. A CRITICAL finding is only accepted by its own
fingerprint, so a broad old entry can never hide a new critical finding.

Only the standard library is used: the format is read line by line.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from skillshield.models import Finding, SkillScanResult
from skillshield.rules import ALL_RULES, Severity

IGNORE_FILE_NAME = ".skillshield-ignore"

_FINGERPRINT_RE = re.compile(r"^fp:[0-9a-f]{16}$")
_RULE_IDS = {rule.id for rule in ALL_RULES}


class IgnoreFileError(ValueError):
    """The ignore file has a line SkillShield cannot accept."""


def fingerprint(rule_id: str, path: str, snippets: list[str]) -> str:
    """A finding's fingerprint: tied to its rule, file and matched text.

    Line numbers are left out, so moving text up or down a file keeps the finding
    accepted. Changing the matched text gives a new fingerprint, so the finding comes
    back for review. Whitespace is collapsed, so re-wrapping a line does not count.
    """
    evidence = "\n".join(sorted({" ".join(s.split()) for s in snippets}))
    digest = hashlib.sha256(f"{rule_id}\0{path}\0{evidence}".encode()).hexdigest()
    return f"fp:{digest[:16]}"


def finding_fingerprint(finding: Finding, path: str) -> str:
    return fingerprint(finding.rule_id, path, finding.snippets)


def _glob_regex(glob: str) -> re.Pattern[str]:
    """Translate a path glob: ``**`` crosses folders, ``*`` and ``?`` stay within one."""
    out = []
    i = 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


@dataclass
class IgnoreEntry:
    line: int
    key: str  # a rule ID or a fingerprint
    glob: str
    reason: str
    _pattern: re.Pattern[str] | None = field(default=None, repr=False)

    @property
    def is_fingerprint(self) -> bool:
        return self.key.startswith("fp:")

    def matches(self, finding: Finding, path: str, finger: str) -> bool:
        if self.glob != "-":
            if self._pattern is None:
                self._pattern = _glob_regex(self.glob)
            if not self._pattern.match(path):
                return False
        if self.is_fingerprint:
            return self.key == finger
        return self.key == finding.rule_id and finding.severity != Severity.CRITICAL


@dataclass
class AcceptedFinding:
    finding: Finding
    reason: str
    fingerprint: str
    line: int


@dataclass
class IgnoreFile:
    path: Path
    entries: list[IgnoreEntry]
    used: set[int] = field(default_factory=set)

    @property
    def base(self) -> Path:
        return self.path.parent

    def relative(self, file: Path) -> str:
        """A scanned file's path relative to the ignore file, with forward slashes."""
        return Path(os.path.relpath(os.path.abspath(file), os.path.abspath(self.base))).as_posix()

    def apply(self, result: SkillScanResult, file: Path) -> None:
        """Move the findings this file accepts from ``result.findings`` to ``result.accepted``.

        The risk score and level are worked out again from the findings that are left.
        """
        if result.risk_level == "ERROR" and not result.findings:
            return
        from skillshield.scanner import _compute_risk_score, _risk_level

        path = self.relative(file)
        kept: list[Finding] = []
        for finding in result.findings:
            finger = finding_fingerprint(finding, path)
            entry = next((e for e in self.entries if e.matches(finding, path, finger)), None)
            if entry is None:
                kept.append(finding)
                continue
            self.used.add(entry.line)
            result.accepted.append(AcceptedFinding(finding, entry.reason, finger, entry.line))
        if len(kept) == len(result.findings):
            return
        result.findings = kept
        result.risk_score = _compute_risk_score(kept)
        # An unreadable file stays ERROR, so the scan still exits 2.
        if result.risk_level != "ERROR":
            result.risk_level = _risk_level(result.risk_score, kept)

    def stale_entries(self) -> list[IgnoreEntry]:
        """Entries that accepted nothing in this scan, so they can be cleaned up."""
        return [e for e in self.entries if e.line not in self.used]


def parse(text: str, path: Path) -> IgnoreFile:
    """Read an ignore file. A line without a reason, or with an unknown rule, is an error."""
    entries: list[IgnoreEntry] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        where = f"{path.name} line {number}"
        if len(parts) < 3 or not parts[2].strip():
            raise IgnoreFileError(
                f"{where}: every entry needs a rule or fingerprint, a path glob (or -) and a "
                "reason"
            )
        key, glob, reason = parts[0], parts[1], parts[2].strip()
        if key.startswith("fp:"):
            if not _FINGERPRINT_RE.match(key):
                raise IgnoreFileError(
                    f"{where}: {key!r} is not a fingerprint (fp: and 16 hex characters)"
                )
        elif key.upper() not in _RULE_IDS:
            raise IgnoreFileError(f"{where}: unknown rule {key!r}")
        else:
            key = key.upper()
        entries.append(IgnoreEntry(number, key, glob, reason))
    return IgnoreFile(path=path, entries=entries)


def load(path: str | Path) -> IgnoreFile:
    path = Path(path)
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise IgnoreFileError(f"cannot read {path}: {exc}") from exc
    return parse(text, path)


def find_default(folder: str | Path) -> Path | None:
    """``.skillshield-ignore`` in a folder, if there is one.

    Only CI uses this, on the workspace its own workflow names. The command line never
    picks up an ignore file by itself: a skill under review must not be able to ship a
    file that accepts its own findings.
    """
    candidate = Path(folder) / IGNORE_FILE_NAME
    return candidate if candidate.is_file() else None


def _one_line(text: str) -> str:
    """Text safe to write into a comment line: line breaks and control characters escaped."""
    return "".join(
        ch if ch.isprintable() or ch == " " else ch.encode("unicode_escape").decode("ascii")
        for ch in text
    )


def accept_lines(results: list[tuple[SkillScanResult, Path]], ignore: IgnoreFile, reason: str):
    """The lines that accept every remaining finding by its fingerprint."""
    lines: list[str] = []
    seen: set[str] = set()
    for result, file in results:
        path = ignore.relative(file)
        for finding in result.findings:
            finger = finding_fingerprint(finding, path)
            if finger in seen:
                continue
            seen.add(finger)
            lines.append(f"# {finding.rule_id} {finding.name}: {_one_line(path)}")
            lines.append(f"{finger}  -  {reason}")
    return lines
