"""
Tests for the MCP tool listing fixtures in tests/fixtures/mcp/.

Safe listings must produce no HIGH or CRITICAL findings. Malicious listings
target specific rules and may be expected failures until those rules land,
as tests/test_redteam.py does for known gaps.
"""

from pathlib import Path

import pytest

from skillshield import SkillScanner
from skillshield.rules import Severity

FIXTURES = Path(__file__).parent / "fixtures" / "mcp"
ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# Malicious fixtures whose rules are not yet implemented. Remove from this set
# once the corresponding rule lands and the test starts passing.
KNOWN_GAPS = {
    "sg-101-unsafe-auth",
    "sg-105-missing-schema",
}


def _target_rule(path: Path) -> str:
    """The rule a malicious listing targets: its file name, or SG-001 for tool poisoning."""
    if path.stem == "tool-poisoning":
        return "SG-001"  # caught by the text rules
    return path.stem[:6].upper()


def _worst(findings) -> Severity | None:
    return max((f.severity for f in findings), key=ORDER.index, default=None)


def _safe_samples():
    return sorted((FIXTURES / "safe").glob("*.json"))


def _malicious_samples():
    params = []
    for path in sorted((FIXTURES / "malicious").glob("*.json")):
        marks = []
        if path.stem in KNOWN_GAPS:
            marks.append(
                pytest.mark.xfail(reason=f"{path.stem} rule not yet implemented", strict=True)
            )
        params.append(pytest.param(path, id=path.stem, marks=marks))
    return params


@pytest.mark.parametrize("path", _safe_samples(), ids=lambda p: p.stem)
def test_safe_mcp_listing_has_no_high_or_critical(path):
    result = SkillScanner().scan_file(path)
    assert result.risk_level != "ERROR", result.error
    worst = _worst(result.findings)
    assert worst is None or ORDER.index(worst) < ORDER.index(
        Severity.HIGH
    ), f"{path.stem}: worst finding is {worst.value if worst else None}"


@pytest.mark.parametrize(
    "path", sorted((FIXTURES / "malicious").glob("*.json")), ids=lambda p: p.stem
)
def test_malicious_mcp_listing_is_readable(path):
    # Outside the expected failures, so a malformed fixture is never hidden by one.
    result = SkillScanner().scan_file(path)
    assert result.risk_level != "ERROR", result.error


@pytest.mark.parametrize("path", _malicious_samples())
def test_malicious_mcp_listing_is_caught_by_its_rule(path):
    result = SkillScanner().scan_file(path)
    rule = _target_rule(path)
    assert rule in {f.rule_id for f in result.findings}, f"{path.stem}: expected {rule}"
