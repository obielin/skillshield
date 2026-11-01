"""
skillshield
==========
Security scanner for AI agent skills.
Flags known prompt-injection, data-exfiltration and malicious-payload patterns
before you install. Zero dependencies.

Inspired by the ClawHavoc campaign (341 malicious skills, Jan 2026)
and Snyk ToxicSkills (13.4% of 3,984 skills contained critical issues).

Quick start:
    from skillshield import SkillScanner

    scanner = SkillScanner()

    # Scan a skill file
    result = scanner.scan_file("SKILL.md")
    print(result.risk_level)    # CRITICAL / HIGH / MEDIUM / LOW / SAFE
    print(result.risk_score)    # 0-100
    for finding in result.findings:
        print(finding.rule_id, finding.severity.value, finding.name)

    # Scan a directory of skills
    report = scanner.scan_directory("./skills/")
    print(report.summary())
    print(f"Flag rate: {report.flag_rate:.0%}")

    # Scan text directly
    result = scanner.scan_text(skill_content, name="my_skill")
"""

from skillshield.models import BatchScanReport, Finding, SkillScanResult
from skillshield.rules import ALL_RULES, Rule, Severity
from skillshield.scanner import SkillScanner

__version__ = "1.2.0"
__author__ = "Linda Oraegbunam"
__all__ = [
    "SkillScanner",
    "SkillScanResult",
    "BatchScanReport",
    "Finding",
    "Rule",
    "Severity",
    "ALL_RULES",
]
