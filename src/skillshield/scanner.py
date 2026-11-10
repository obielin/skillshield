"""Core scanner engine for skillshield."""

from __future__ import annotations

import importlib.util
import re
import sys
import time
from pathlib import Path
from typing import Callable

from skillshield.models import BatchScanReport, Finding, SkillScanResult
from skillshield.rules import ALL_RULES, RULE_COMPILED_PYTHON, Rule, Severity

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


def _find_line_numbers(text: str, snippet: str) -> list[int]:
    """Return line numbers where a snippet appears in text."""
    lines = text.splitlines()
    return [i + 1 for i, line in enumerate(lines) if snippet[:40] in line]


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

    def scan_text(self, text: str, name: str = "skill") -> SkillScanResult:
        """
        Scan a skill provided as plain text.

        Args:
            text: The skill content (SKILL.md, YAML, Python, etc.)
            name: Identifier for this skill in the report

        Returns:
            SkillScanResult with all findings and risk score
        """
        t0 = time.time()
        findings: list[Finding] = []

        for rule in self.rules:
            if self._below_min_severity(rule.severity):
                continue
            try:
                snippets = rule.match(text)
            except Exception:
                snippets = []
            if snippets:
                # Pattern hits can span lines or repeat. The match offset is
                # the line to report; searching for the first snippet misses
                # a later hit and never finds a snippet that contains a newline.
                # check_fn rules return plain strings, so they stay on snippet lookup.
                if rule.pattern is not None:
                    line_numbers = _pattern_line_numbers(text, rule.pattern)
                else:
                    line_numbers = _find_line_numbers(text, snippets[0])
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
            text = p.read_text(encoding=encoding, errors="replace")
        except Exception as e:
            return SkillScanResult(
                skill_name=p.name,
                findings=[],
                risk_score=0.0,
                risk_level="ERROR",
                error=str(e),
            )
        return self.scan_text(text, name=p.name)

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
        paths = [p for p in all_files if p.suffix.lower() in exts]
        # A compiled file asked for through extensions already reaches
        # scan_file, which dispatches to the compiled check; collecting it
        # here as well would report the same file twice. Compiled Python is
        # never filtered by directory name: a submitted skill can hide
        # bytecode inside any directory, including a real local environment.
        compiled = [
            p
            for p in all_files
            if p.suffix.lower() in COMPILED_PYTHON_EXTENSIONS and p.suffix.lower() not in exts
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
