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


def _worst(findings) -> Severity | None:
    return max((f.severity for f in findings), key=ORDER.index, default=None)


def _safe_samples():
    return sorted((FIXTURES / "safe").glob("*.json"))


def _malicious_samples():
    return sorted((FIXTURES / "malicious").glob("*.json"))


@pytest.mark.parametrize("path", _safe_samples(), ids=lambda p: p.stem)
def test_safe_mcp_listing_has_no_high_or_critical(path):
    result = SkillScanner().scan_file(path)
    assert result.risk_level != "ERROR", result.error
    worst = _worst(result.findings)
    assert worst is None or ORDER.index(worst) < ORDER.index(Severity.HIGH), (
        f"{path.stem}: worst finding is {worst.value if worst else None}"
    )


# Malicious fixtures whose rules are not yet implemented. Remove from this set
# once the corresponding rule lands and the test starts passing.
KNOWN_GAPS = {
    "sg-101-unsafe-auth",
    "sg-102-overbroad-permissions",
    "sg-103-unrestricted-path",
    "sg-105-missing-schema",
    "sg-106-excessive-tools",
    # tool-poisoning is caught by existing text rules (SG-001), so not a gap
    # sg-104 is already implemented
}


@pytest.mark.parametrize("path", _malicious_samples(), ids=lambda p: p.stem)
def test_malicious_mcp_listing(path):
    result = SkillScanner().scan_file(path)
    worst = _worst(result.findings)
    if path.stem in KNOWN_GAPS:
        pytest.xfail(f"{path.stem} rule not yet implemented")
    assert worst is not None, f"{path.stem}: expected findings"
    # For implemented rules, at least HIGH
    assert ORDER.index(worst) >= ORDER.index(Severity.HIGH)
