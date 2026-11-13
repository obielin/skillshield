"""Core scanner engine for skillshield."""

from __future__ import annotations

import importlib.util
import re
import sys
import time
from pathlib import Path
from typing import Callable

from skillshield.mcp import ListingError, ToolListing, parse_listing
from skillshield.models import BatchScanReport, Finding, SkillScanResult
from skillshield.rules import (
    ALL_RULES,
    RULE_COMPILED_PYTHON,
    Rule,
    Severity,
    hidden_tag_match_lines,
    hidden_tag_text_with_lines,
)

# Severity weights for risk score calculation
_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 1,
}

# The level each finding severity sets as a floor. INFO stays informational.
_SEVERITY_LEVEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
}
_LEVEL_RANK = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Skill file extensions supported
SKILL_EXTENSIONS = {
    ".mdc",
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".py",
    ".js",
    ".ts",
    ".sh",
    ".bash",
    ".toml",
    ".xml",
    ".html",
}

# Extensionless instruction files read by coding agents.
_AGENT_RULE_FILENAMES = {".cursorrules", ".windsurfrules", ".clinerules", ".roorules", ".rules"}


def _is_agent_rule_file(path: Path) -> bool:
    if path.name in _AGENT_RULE_FILENAMES or path.name.startswith(".roorules-"):
        return True
    return any(
        parent.name == ".clinerules"
        or (
            parent.parent.name == ".roo"
            and (parent.name == "rules" or parent.name.startswith("rules-"))
        )
        for parent in path.parents
    )


# Files that can hold an MCP tool listing. A .json file is always scanned; a .jsonl
# file only when it is a listing, since most .jsonl files are data.
LISTING_EXTENSIONS = {".json", ".jsonl"}


def _read_text(path: Path, encoding: str = "utf-8") -> str:
    with path.open("rb") as source:
        data = source.read()
    text = data.decode(encoding, errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


# How much of a .jsonl file is read to decide whether it is a tool listing.
_LISTING_PREFIX_BYTES = 64 * 1024


def _is_tool_listing_file(path: Path) -> bool:
    """Whether a .jsonl file is an MCP tool listing, readable or not.

    Only the first 64 KB is read, so a large data file is skipped without being
    read in full; scan_file reads a listing in full. A line cut off at the limit
    is left out.
    """
    if path.suffix.lower() != ".jsonl":
        return False
    try:
        with path.open("rb") as source:
            data = source.read(_LISTING_PREFIX_BYTES + 1)
    except OSError:
        return False
    if len(data) > _LISTING_PREFIX_BYTES:
        data = data[: data.rfind(b"\n", 0, _LISTING_PREFIX_BYTES) + 1]
    text = data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    try:
        return parse_listing(text, path.suffix) is not None
    except ListingError:
        return True


# Compiled Python that Python runs directly but a text scanner cannot read.
COMPILED_PYTHON_EXTENSIONS = {".pyc", ".pyo"}

# Directories that hold tooling or dependencies, never skills the repo ships.
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"}

_LOCAL_ENV_NAMES = {"venv", ".venv"}


def _dir_is_skipped(directory: Path) -> bool:
    """Whether a directory is tooling rather than skill content.

    A venv name alone proves nothing: a skill can ship its own .venv/ to hide
    bytecode from the scanner. Only a directory that carries pyvenv.cfg next
    to its interpreter is a real local environment; anything else is scanned.
    """
    name = directory.name
    if name not in SKIP_DIRS:
        return False
    if name in _LOCAL_ENV_NAMES and not (directory / "pyvenv.cfg").is_file():
        return False
    return True


def compiled_source_path(path: Path) -> Path:
    """The source file a .pyc or .pyo was compiled from.

    A file in __pycache__ keeps its source one level up with the interpreter
    tag in the name (tool.cpython-310.pyc -> tool.py), so the naming rule
    comes from importlib instead of a swapped suffix.
    """
    try:
        return Path(importlib.util.source_from_cache(str(path)))
    except (ValueError, NotImplementedError):
        # .pyo in __pycache__, or a name source_from_cache will not take.
        # Keep the interpreter tag out of the guessed source name:
        # tool.cpython-310.pyo -> tool.py, not tool.cpython-310.py.
        if path.parent.name == "__pycache__":
            module = path.stem.split(".", 1)[0]
            return path.parent.parent / f"{module}.py"
        return path.with_suffix(".py")


def _compute_risk_score(findings: list[Finding]) -> float:
    """Compute a 0-100 risk score from a list of findings."""
    if not findings:
        return 0.0
    raw = sum(_SEVERITY_WEIGHTS.get(f.severity, 1) for f in findings)
    return min(100.0, round(raw, 2))


def _risk_level(score: float, findings: list[Finding]) -> str:
    """Derive risk level from score and findings."""
    if score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "SAFE"
    # The score alone reports one HIGH finding as MEDIUM, so the worst single
    # finding is a floor. INFO findings stay informational.
    for finding in findings:
        floor = _SEVERITY_LEVEL.get(finding.severity)
        if floor and _LEVEL_RANK[floor] > _LEVEL_RANK[level]:
            level = floor
    return level


# The checks that shorten a match cut it at 80 characters and add "...".
_CUT_SHORT_LENGTH = 80 + len("...")


def _locate(lines: list[str], snippet: str) -> list[int]:
    """The lines that carry a snippet.

    A snippet that is cut short (it ends in "...") or that spans lines is not in any one line
    whole, so the lines holding the first 40 characters of its first line are used instead.
    """
    ends_in_dots = snippet.endswith("...") and len(snippet) > 3
    prefix = snippet[:-3] if ends_in_dots else snippet
    # A snippet of the length a cut one has can be a prefix of longer text, so every line that
    # starts like it counts, and a literal "..." in the text does not hide the others.
    if ends_in_dots and len(snippet) == _CUT_SHORT_LENGTH:
        return [i + 1 for i, line in enumerate(lines) if prefix in line]
    # Any other "..." may be the text itself: the snippet as it is comes first, so that dropping
    # it does not also find earlier lines that only share the prefix.
    exact = [i + 1 for i, line in enumerate(lines) if snippet in line]
    if exact:
        return exact
    if ends_in_dots:
        whole = [i + 1 for i, line in enumerate(lines) if prefix in line]
        if whole:
            return whole
    # A snippet that spans lines is found whole in the text, on the line where it starts, so
    # an earlier line that only shares its first line is not reported.
    if "\n" in snippet:
        text = "\n".join(lines)
        starts = []
        lineno, last, at = 1, 0, text.find(snippet)
        while at >= 0:
            lineno += text.count("\n", last, at)
            last = at
            starts.append(lineno)
            at = text.find(snippet, at + 1)
        if starts:
            return sorted(set(starts))
    # Otherwise (its line endings differ, say) it is found by its first non-blank line.
    first = next((part for part in snippet.splitlines() if part.strip()), snippet)
    return [i + 1 for i, line in enumerate(lines) if first[:40] in line]


# Locating a snippet reads every line, so only the first snippets of a finding are located:
# a skill that matches thousands of times cannot slow a scan down by the number of its matches.
_MAX_SNIPPETS_LOCATED = 50


def _find_all_line_numbers(text: str, snippets: list[str]) -> list[int]:
    """The lines of every snippet of a finding, once each, in order."""
    lines = text.splitlines()
    found: set[int] = set()
    for snippet in snippets[:_MAX_SNIPPETS_LOCATED]:
        found.update(_locate(lines, snippet))
    return sorted(found)


def _pattern_line_numbers(text: str, pattern: re.Pattern[str]) -> list[int]:
    """Return the starting line of each regex match.

    A match that spans lines is reported on the line where it starts, and
    every match is reported. A line that contains several matches is listed
    once, in the order the matches appear.
    """
    line_numbers: list[int] = []
    seen: set[int] = set()
    lineno = 1
    last_start = 0
    for match in pattern.finditer(text):
        lineno += text.count("\n", last_start, match.start())
        last_start = match.start()
        if lineno not in seen:
            seen.add(lineno)
            line_numbers.append(lineno)
    return line_numbers


class SkillScanner:
    """
    Scan AI agent skills for security vulnerabilities.

    Supports Claude SKILL.md, CLAUDE.md, AGENTS.md, OpenCode skills,
    Codex plugins, MCP tool definitions, and any text/YAML/JSON/Python.

    Example:
        scanner = SkillScanner()

        # Scan a single skill file
        result = scanner.scan_file("SKILL.md")
        print(result.summary_line())
        print(f"Risk: {result.risk_level}, Score: {result.risk_score}/100")

        # Scan text directly
        result = scanner.scan_text(skill_content, name="my_skill")

        # Scan an entire directory of skills
        report = scanner.scan_directory("./skills/")
        print(report.summary())
        print(f"Flag rate: {report.flag_rate:.0%}")
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        min_severity: Severity = Severity.INFO,
        verbose: bool = False,
    ) -> None:
        """
        Args:
            rules:        Custom rule set (defaults to ALL_RULES)
            min_severity: Minimum severity to report (default: INFO = all)
            verbose:      Print scan progress
        """
        self.rules = ALL_RULES if rules is None else rules
        self.min_severity = min_severity
        self.verbose = verbose
        self._severity_order = list(Severity)

    def scan_text(
        self, text: str, name: str = "skill", listing: ToolListing | None = None
    ) -> SkillScanResult:
        """
        Scan a skill provided as plain text.

        Args:
            text:    The skill content (SKILL.md, YAML, Python, etc.)
            name:    Identifier for this skill in the report
            listing: The text parsed as an MCP tool listing, for rules that read one

        Returns:
            SkillScanResult with all findings and risk score
        """
        t0 = time.time()
        findings: list[Finding] = []

        # Text hidden in Unicode tag characters is read with every rule too, and the finding
        # says it was hidden. Each character of it knows the line it came from, taken from the
        # text itself: a line number is never read back from a snippet, which the skill wrote.
        hidden, hidden_owners = hidden_tag_text_with_lines(text)

        for rule in self.rules:
            if self._below_min_severity(rule.severity):
                continue
            try:
                snippets = rule.match(text)
            except Exception:
                snippets = []
            try:
                found_hidden = rule.match(hidden) if hidden else []
            except Exception:
                found_hidden = []
            try:
                hits = rule.match_listing(listing) if listing is not None else []
            except Exception:
                hits = []
            if not snippets and not found_hidden and not hits:
                continue
            # Pattern hits can span lines or repeat, so a pattern rule reports the line of each
            # match offset. check_fn rules return plain strings, so their snippets are located.
            if not snippets:
                line_numbers = set()
            elif rule.pattern is not None:
                line_numbers = set(_pattern_line_numbers(text, rule.pattern))
            else:
                line_numbers = set(_find_all_line_numbers(text, snippets))
            if rule.id == "SG-008":
                # The tag matches are generated snippets, so they are not in the text to be
                # searched for; their lines come from the text.
                line_numbers.update(hidden_tag_match_lines(text))
            # A match in the hidden text reports the lines whose characters it is made of.
            for match in found_hidden:
                start = hidden.find(match)
                owners = hidden_owners[start : start + len(match)] if start >= 0 else []
                line_numbers.update(owners or hidden_owners)
            # A listing finding reports the line where its tool starts.
            line_numbers.update(tool.line for tool, _ in hits)
            line_numbers = sorted(n for n in line_numbers if n >= 1)
            snippets = snippets + [f"[hidden in Unicode tag characters] {s}" for s in found_hidden]
            snippets += [snippet for _, snippet in hits]
            findings.append(Finding(rule=rule, snippets=snippets, line_numbers=line_numbers))

        score = _compute_risk_score(findings)
        level = _risk_level(score, findings)

        return SkillScanResult(
            skill_name=name,
            findings=findings,
            risk_score=score,
            risk_level=level,
            scan_time_ms=round((time.time() - t0) * 1000, 2),
            line_count=text.count("\n") + 1,
            char_count=len(text),
        )

    def scan_file(self, path: str | Path, encoding: str = "utf-8") -> SkillScanResult:
        """
        Scan a skill file.

        Args:
            path:     Path to the skill file
            encoding: File encoding (default utf-8)

        Returns:
            SkillScanResult
        """
        p = Path(path)
        if p.suffix.lower() in COMPILED_PYTHON_EXTENSIONS:
            return self._scan_compiled_file(p)
        self._log(f"  Scanning {p.name}...")
        try:
            text = _read_text(p, encoding)
        except Exception as e:
            return SkillScanResult(
                skill_name=p.name,
                findings=[],
                risk_score=0.0,
                risk_level="ERROR",
                error=str(e),
            )
        listing = None
        broken = ""
        if p.suffix.lower() in LISTING_EXTENSIONS:
            try:
                listing = parse_listing(text, p.suffix)
            except ListingError as e:
                broken = f"malformed MCP tool listing: {e}"
        result = self.scan_text(text, name=p.name, listing=listing)
        if broken:
            # The text rules still ran, so their findings stay with the file, but a listing
            # that cannot be read is never reported as SAFE.
            result.risk_level = "ERROR"
            result.error = broken
        return result

    def _scan_compiled_file(self, path: Path, base: Path | None = None) -> SkillScanResult:
        """Report a compiled Python file as a HIGH finding.

        Bytecode is not reviewable and Python runs it directly, so a skill that
        ships a .pyc/.pyo is treated as a payload carrier rather than skipped.
        """
        name = path.relative_to(base).as_posix() if base is not None else path.name
        self._log(f"  Scanning {name} (compiled)...")
        try:
            with path.open("rb") as compiled:
                compiled.read(1)
        except OSError as exc:
            # An unreadable path is an error, not a finding: CI reserves exit
            # code 2 for a file it could not read at all.
            return SkillScanResult(
                skill_name=name,
                findings=[],
                risk_score=0.0,
                risk_level="ERROR",
                error=str(exc),
            )
        snippet = name
        source = compiled_source_path(path)
        if not source.is_file():
            snippet = f"{name} (no matching {source.name}; ship the source instead)"
        findings: list[Finding] = []
        configured_rule = next(
            (rule for rule in self.rules if rule.id == RULE_COMPILED_PYTHON.id), None
        )
        if configured_rule is not None and not self._below_min_severity(configured_rule.severity):
            findings.append(Finding(rule=configured_rule, snippets=[snippet], line_numbers=[1]))
        score = _compute_risk_score(findings)
        return SkillScanResult(
            skill_name=name,
            findings=findings,
            risk_score=score,
            risk_level=_risk_level(score, findings),
            scan_time_ms=0.0,
            line_count=0,
            char_count=0,
        )

    def scan_directory(
        self,
        directory: str | Path,
        extensions: set[str] | None = None,
        recursive: bool = True,
        on_progress: Callable[[str, int, int], None] | None = None,
    ) -> BatchScanReport:
        """
        Scan all skill files in a directory.

        Args:
            directory:   Directory containing skill files
            extensions:  File extensions to scan (default: common skill types)
            recursive:   Scan subdirectories (default: True)
            on_progress: Optional callback(name, done, total)

        Returns:
            BatchScanReport with all results
        """
        exts = extensions or SKILL_EXTENSIONS
        base = Path(directory)
        glob = base.rglob("*") if recursive else base.glob("*")
        all_files = [p for p in sorted(glob) if p.is_file()]
        paths = [
            p
            for p in all_files
            if p.suffix.lower() in exts or _is_agent_rule_file(p) or _is_tool_listing_file(p)
        ]
        selected_paths = set(paths)
        # A compiled file selected above already reaches
        # scan_file, which dispatches to the compiled check; collecting it
        # here as well would report the same file twice. Compiled Python is
        # never filtered by directory name: a submitted skill can hide
        # bytecode inside any directory, including a real local environment.
        compiled = [
            p
            for p in all_files
            if p.suffix.lower() in COMPILED_PYTHON_EXTENSIONS and p not in selected_paths
        ]

        selected = set(paths) | set(compiled)
        unscanned = [
            path.relative_to(base).as_posix() for path in all_files if path not in selected
        ]
        self._log(
            f"  Found {len(paths)} skill files and {len(compiled)} compiled files in {directory}"
        )
        results: list[SkillScanResult] = []
        total = len(paths) + len(compiled)

        for i, path in enumerate(paths):
            name = path.relative_to(base).as_posix()
            on_progress and on_progress(name, i + 1, total)
            result = self.scan_file(path)
            result.skill_name = name
            results.append(result)

        for i, path in enumerate(compiled, start=len(paths)):
            name = path.relative_to(base).as_posix()
            on_progress and on_progress(name, i + 1, total)
            results.append(self._scan_compiled_file(path, base))

        metadata = {"unscanned": unscanned} if unscanned else {}
        return BatchScanReport(results=results, metadata=metadata)

    def scan_texts(
        self,
        skills: dict[str, str],
        on_progress: Callable[[str, int, int], None] | None = None,
    ) -> BatchScanReport:
        """
        Scan multiple skills provided as {name: text} dict.

        Args:
            skills:      Dict of {skill_name: skill_content}
            on_progress: Optional callback(name, done, total)

        Returns:
            BatchScanReport
        """
        names = list(skills.keys())
        results: list[SkillScanResult] = []
        for i, name in enumerate(names):
            on_progress and on_progress(name, i + 1, len(names))
            self._log(f"  Scanning {name} ({i + 1}/{len(names)})...")
            results.append(self.scan_text(skills[name], name=name))
        return BatchScanReport(results=results)

    def _below_min_severity(self, severity: Severity) -> bool:
        order = {s: i for i, s in enumerate(self._severity_order)}
        return order.get(severity, 99) > order.get(self.min_severity, 0)

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg, file=sys.stderr)
