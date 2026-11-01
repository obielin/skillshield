"""
Run a SkillShield scan in CI and report the result.

This is what the SkillShield GitHub Action runs. It can also be used from any
CI system with ``python -m skillshield.ci``. Settings come from environment
variables, so CI inputs never have to be pasted into a shell command:

    SKILLSHIELD_PATHS         Files or directories to scan, one per line (default ".")
    SKILLSHIELD_FAIL_ON       Fail at this risk level or above:
                              critical, high, medium, low or none (default "high")
    SKILLSHIELD_MIN_SEVERITY  Ignore findings below this severity (default "info")
    SKILLSHIELD_SARIF_FILE    Write a SARIF 2.1.0 file here (optional)
    SKILLSHIELD_WORKSPACE     Report paths relative to this directory
                              (default: GITHUB_WORKSPACE, or the current directory)

When running in GitHub Actions it also writes a job summary
(GITHUB_STEP_SUMMARY) and step outputs (GITHUB_OUTPUT).

Exit codes: 0 pass, 1 a skill is at or above the fail-on level, 2 a path does
not exist, a file could not be read, or a setting is invalid.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from skillshield.models import SkillScanResult
from skillshield.rules import Severity
from skillshield.sarif import results_to_sarif
from skillshield.scanner import SKILL_EXTENSIONS, SkillScanner

LEVELS = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
FAIL_ON = {"none": None, "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
SEVERITIES = {s.value.lower(): s for s in Severity}
# Directories that hold tooling or dependencies, never skills the repo ships.
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"}


class SettingError(ValueError):
    """A setting has a value SkillShield does not accept."""


def _rank(level: str) -> int:
    return LEVELS.index(level) if level in LEVELS else -1


def _relative(path: Path, workspace: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def scan_paths(
    paths: list[str], workspace: Path, min_severity: Severity = Severity.INFO
) -> tuple[list[SkillScanResult], list[str]]:
    """Scan each path. Returns the results and the paths that do not exist."""
    scanner = SkillScanner(min_severity=min_severity)
    results: list[SkillScanResult] = []
    missing: list[str] = []
    for raw in paths:
        p = Path(raw)
        if not p.is_absolute():
            p = workspace / p
        if p.is_dir():
            files = sorted(
                f
                for f in p.rglob("*")
                if f.is_file()
                and f.suffix.lower() in SKILL_EXTENSIONS
                and not SKIP_DIRS.intersection(f.relative_to(p).parts[:-1])
            )
        elif p.is_file():
            files = [p]
        else:
            missing.append(raw)
            continue
        for f in files:
            result = scanner.scan_file(f)
            # scan_file names a result by file name only; use the path relative
            # to the workspace so findings point at the right file.
            result.skill_name = _relative(f, workspace)
            results.append(result)
    return results, missing


def decide(results: list[SkillScanResult], missing: list[str], fail_on: str | None) -> int:
    """Return the exit code for these results."""
    if missing or any(r.risk_level == "ERROR" for r in results):
        return 2
    if fail_on is None:
        return 0
    threshold = _rank(fail_on)
    return 1 if any(_rank(r.risk_level) >= threshold for r in results) else 0


def highest_level(results: list[SkillScanResult]) -> str:
    """The most severe risk level among the results that were read."""
    read = [r for r in results if r.risk_level != "ERROR"]
    if not read:
        return "SAFE"
    return max((r.risk_level for r in read), key=_rank)


def summary_markdown(
    results: list[SkillScanResult], missing: list[str], fail_on: str | None, exit_code: int
) -> str:
    """A Markdown summary of the scan, for the GitHub job summary."""
    verdict = {0: "Passed", 1: "Failed", 2: "Error"}[exit_code]
    threshold = fail_on or "never"
    flagged = [r for r in results if r.risk_level not in ("SAFE", "ERROR")]
    errors = [r for r in results if r.risk_level == "ERROR"]
    lines = [
        f"## SkillShield scan: {verdict}",
        "",
        f"Scanned {len(results)} file(s). Fails at: {threshold.lower()}.",
        "",
        "| Result | Count |",
        "|---|---|",
        f"| Highest risk level | {highest_level(results)} |",
        f"| Flagged files | {len(flagged)} |",
        f"| Unreadable files | {len(errors)} |",
        f"| Missing paths | {len(missing)} |",
        "",
    ]
    if flagged:
        lines += ["| File | Risk | Score | Findings |", "|---|---|---|---|"]
        for r in sorted(flagged, key=lambda r: (-_rank(r.risk_level), r.skill_name)):
            ids = ", ".join(f.rule_id for f in r.findings)
            lines.append(f"| `{r.skill_name}` | {r.risk_level} | {r.risk_score:.0f} | {ids} |")
        lines.append("")
    for r in errors:
        lines.append(f"- Could not read `{r.skill_name}`: {r.error}")
    for m in missing:
        lines.append(f"- Path does not exist: `{m}`")
    return "\n".join(lines).rstrip() + "\n"


def console_report(results: list[SkillScanResult], missing: list[str], exit_code: int) -> str:
    """Plain text lines for the job log, with GitHub annotations for flagged files."""
    lines = []
    for r in results:
        if r.risk_level == "ERROR":
            lines.append(
                f"::error file={r.skill_name}::SkillShield could not read this file: {r.error}"
            )
        elif r.risk_level != "SAFE":
            ids = ", ".join(f"{f.rule_id} {f.name}" for f in r.findings)
            level = r.risk_level
            kind = "error" if exit_code == 1 and level in ("HIGH", "CRITICAL") else "warning"
            line = r.findings[0].line_numbers[0] if r.findings and r.findings[0].line_numbers else 1
            lines.append(
                f"::{kind} file={r.skill_name},line={line},title=SkillShield {level}::{ids}"
            )
    for m in missing:
        lines.append(f"::error::SkillShield: path does not exist: {m}")
    lines.append(
        f"SkillShield scanned {len(results)} file(s); highest risk level {highest_level(results)}."
    )
    return "\n".join(lines)


def _write(path: str | None, text: str, mode: str = "w") -> None:
    if path:
        with open(path, mode, encoding="utf-8") as fh:
            fh.write(text)


def read_settings(env: dict[str, str]) -> dict:
    """Read and check the settings from environment variables."""
    paths = [p.strip() for p in env.get("SKILLSHIELD_PATHS", ".").splitlines() if p.strip()]
    fail_on_raw = env.get("SKILLSHIELD_FAIL_ON", "high").strip().lower() or "high"
    if fail_on_raw not in FAIL_ON:
        raise SettingError(f"fail-on must be one of {', '.join(FAIL_ON)}; got {fail_on_raw!r}")
    sev_raw = env.get("SKILLSHIELD_MIN_SEVERITY", "info").strip().lower() or "info"
    if sev_raw not in SEVERITIES:
        raise SettingError(f"min-severity must be one of {', '.join(SEVERITIES)}; got {sev_raw!r}")
    workspace = env.get("SKILLSHIELD_WORKSPACE") or env.get("GITHUB_WORKSPACE") or os.getcwd()
    return {
        "paths": paths or ["."],
        "fail_on": FAIL_ON[fail_on_raw],
        "min_severity": SEVERITIES[sev_raw],
        "sarif_file": env.get("SKILLSHIELD_SARIF_FILE", "").strip() or None,
        "workspace": Path(workspace),
    }


def run(env: dict[str, str]) -> int:
    """Run a scan with the given environment and return the exit code."""
    try:
        s = read_settings(env)
    except SettingError as e:
        print(f"::error::SkillShield: {e}")
        return 2

    results, missing = scan_paths(s["paths"], s["workspace"], s["min_severity"])
    exit_code = decide(results, missing, s["fail_on"])

    if s["sarif_file"]:
        _write(s["sarif_file"], json.dumps(results_to_sarif(results), indent=2))

    print(console_report(results, missing, exit_code))
    _write(
        env.get("GITHUB_STEP_SUMMARY"),
        summary_markdown(results, missing, s["fail_on"], exit_code),
        "a",
    )

    flagged = sum(1 for r in results if r.risk_level not in ("SAFE", "ERROR"))
    outputs = {
        "risk-level": highest_level(results),
        "scanned": str(len(results)),
        "flagged": str(flagged),
        "findings": str(sum(len(r.findings) for r in results)),
        "sarif-file": s["sarif_file"] or "",
        "exit-code": str(exit_code),
    }
    _write(env.get("GITHUB_OUTPUT"), "".join(f"{k}={v}\n" for k, v in outputs.items()), "a")
    return exit_code


def main() -> None:
    sys.exit(run(dict(os.environ)))


if __name__ == "__main__":
    main()
