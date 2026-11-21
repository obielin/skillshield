"""
SARIF 2.1.0 output format for skillshield.

Converts SkillScanResult / BatchScanReport objects into a valid SARIF log
that can be uploaded to GitHub Advanced Security (Security tab).

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillshield import __version__
from skillshield.models import BatchScanReport, SkillScanResult, missing_source_note
from skillshield.rules import ALL_RULES, RULE_COMPILED_PYTHON, Rule, Severity

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_TOOL_NAME = "skillshield"
_TOOL_VERSION = __version__
_TOOL_INFO_URI = "https://github.com/obielin/skillshield"

# Map skillshield Severity to SARIF level
_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def _rule_descriptor(rule: Rule) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor for a Rule."""
    return {
        "id": rule.id,
        "name": rule.name.replace(" ", "").replace("/", "").replace("-", ""),
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "help": {
            "text": rule.remediation,
            "markdown": f"**Remediation:** {rule.remediation}",
        },
        "defaultConfiguration": {
            "level": _SEVERITY_TO_LEVEL.get(rule.severity, "warning"),
        },
        "properties": {
            "tags": rule.tags,
            "severity": rule.severity.value,
        },
    }


def _artifact_uri(skill_name: str) -> str:
    """
    Normalise a skill_name to a URI suitable for SARIF artifactLocation.

    Absolute paths (installed skills) become percent-encoded ``file:`` URIs so
    spaces, ``#``, and other reserved characters keep their meaning. Relative
    skill names keep the plain forward-slash form that GitHub path-matching
    expects.
    """
    path = Path(skill_name)
    try:
        if path.is_absolute():
            return path.as_uri()
    except (OSError, ValueError):
        pass
    return skill_name.replace("\\", "/")


def results_to_sarif(results: list[SkillScanResult]) -> dict[str, Any]:
    """
    Convert a list of SkillScanResult objects to a SARIF 2.1.0 log dict.

    Args:
        results: One or more SkillScanResult objects from a scan.

    Returns:
        A dict that serialises to a valid SARIF 2.1.0 JSON document.

    Example::

        from skillshield import SkillScanner
        from skillshield.sarif import results_to_sarif
        import json

        scanner = SkillScanner()
        result  = scanner.scan_file("SKILL.md")
        log     = results_to_sarif([result])
        print(json.dumps(log, indent=2))
    """
    # Build the full rule index from ALL_RULES so ruleIndex references are stable
    all_rule_ids = [rule.id for rule in ALL_RULES]
    rule_id_to_index = {rid: i for i, rid in enumerate(all_rule_ids)}

    sarif_results: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []
    for scan_result in results:
        uri = _artifact_uri(scan_result.file_path or scan_result.skill_name)
        if scan_result.risk_level == "ERROR" or scan_result.error:
            artifact_location: dict[str, Any] = {"uri": uri}
            if not scan_result.file_path:
                artifact_location["uriBaseId"] = "%SRCROOT%"
            notification: dict[str, Any] = {
                "level": "error",
                "message": {
                    "text": scan_result.error
                    or f"Failed to scan {scan_result.file_path or scan_result.skill_name}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": artifact_location,
                        }
                    }
                ],
            }
            if scan_result.agent:
                notification["properties"] = {
                    "agent": scan_result.agent,
                    "skill": scan_result.skill_name,
                    "path": scan_result.file_path or scan_result.skill_name,
                }
            notifications.append(notification)
        # Accepted findings stay in the log, marked as suppressed with their reason,
        # so code scanning keeps a record of what was accepted and why.
        accepted = [(a.finding, a) for a in scan_result.accepted]
        for finding, acceptance in [(f, None) for f in scan_result.findings] + accepted:
            level = _SEVERITY_TO_LEVEL.get(finding.severity, "warning")
            message_text = (
                f"{finding.name}: {finding.rule.description}"
                f" — Remediation: {finding.rule.remediation}"
            )
            note = missing_source_note(scan_result)
            if note and finding.rule_id == RULE_COMPILED_PYTHON.id:
                message_text = f"{message_text} - {note}"

            locations: list[dict[str, Any]] = []
            # Emit one location per matched line number (up to 5 — matches the
            # JSON output cap); fall back to line 1 when no line numbers are
            # available so the result always has a valid physicalLocation.
            line_numbers = finding.line_numbers[:5] if finding.line_numbers else [1]
            for lineno in line_numbers:
                artifact_location: dict[str, Any] = {"uri": uri}
                if not scan_result.file_path:
                    artifact_location["uriBaseId"] = "%SRCROOT%"
                locations.append(
                    {
                        "physicalLocation": {
                            "artifactLocation": artifact_location,
                            "region": {"startLine": lineno},
                        }
                    }
                )

            entry: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": level,
                "message": {"text": message_text},
                "locations": locations,
            }
            if finding.rule_id in rule_id_to_index:
                entry["ruleIndex"] = rule_id_to_index[finding.rule_id]
            if acceptance is not None:
                entry["suppressions"] = [{"kind": "external", "justification": acceptance.reason}]
                entry["partialFingerprints"] = {"skillshield/v1": acceptance.fingerprint}
            if scan_result.agent:
                entry["properties"] = {
                    "agent": scan_result.agent,
                    "skill": scan_result.skill_name,
                    "path": scan_result.file_path or scan_result.skill_name,
                }

            sarif_results.append(entry)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": _TOOL_NAME,
                "version": _TOOL_VERSION,
                "informationUri": _TOOL_INFO_URI,
                "rules": [_rule_descriptor(rule) for rule in ALL_RULES],
            }
        },
        "results": sarif_results,
    }
    if notifications:
        run["invocations"] = [
            {
                "executionSuccessful": False,
                "toolExecutionNotifications": notifications,
            }
        ]

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def report_to_sarif(report: BatchScanReport) -> dict[str, Any]:
    """
    Convert a BatchScanReport to a SARIF 2.1.0 log dict.

    This is a convenience wrapper around :func:`results_to_sarif`. Paths
    the scanner refused to open travel in the run-level custom properties, so
    a skipped file cannot disappear from a machine-readable report.
    """
    log = results_to_sarif(report.results)
    properties = log["runs"][0].setdefault("properties", {})
    properties["unscanned"] = report.metadata.get("unscanned") or []
    if "skipped" in report.metadata:
        properties["skipped"] = report.metadata["skipped"]
    if "locations" in report.metadata:
        properties["locations"] = report.metadata["locations"]
    return log


def to_sarif_string(results: list[SkillScanResult], indent: int = 2) -> str:
    """Serialise scan results to a SARIF 2.1.0 JSON string."""
    return json.dumps(results_to_sarif(results), indent=indent)
