"""Core scanner engine for skillshield."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Callable

from skillshield.models import BatchScanReport, Finding, SkillScanResult
from skillshield.rules import ALL_RULES, Rule, Severity

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
        paths = [p for p in sorted(glob) if p.is_file() and p.suffix.lower() in exts]

        self._log(f"  Found {len(paths)} skill files in {directory}")
        results: list[SkillScanResult] = []

        for i, path in enumerate(paths):
            name = path.relative_to(base).as_posix()
            on_progress and on_progress(name, i + 1, len(paths))
            result = self.scan_file(path)
            result.skill_name = name
            results.append(result)

        return BatchScanReport(results=results)

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
