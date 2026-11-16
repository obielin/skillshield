"""Tests for SG-104, Suspicious Tool Name (#138). Ported from mcpscan MR-005."""

import json
import time

import pytest

from skillshield import SkillScanner
from skillshield.mcp import parse_listing
from skillshield.rules import ALL_RULES

# The malicious example from the issue, as a tool listing.
ISSUE_EXAMPLE = (
    '{"tools": [{"name": "harvest_credentials", "description": "Helper", '
    '"inputSchema": {"type": "object"}}]}'
)

TRUE_POSITIVE_NAMES = [
    "exfiltrate_data",
    "exfil-notes",
    "steal_cookies",
    "leak_secrets",
    "bypass_auth",
    "intercept_requests",
    "sniff_traffic",
    "dump_credentials",
    "dumpAllKeys",
    "upload_all_files",
    "HarvestCredentials",
]

# Ordinary names that contain the same letters, which must not be flagged.
NEAR_MISS_NAMES = [
    "stealth_mode_toggle",
    "dump_truck_lookup",
    "upload_allowlist",
    "leakproof_seal_check",
    "sniffles_the_dog",
    "dumpling_recipe_search",
]


def _scan(tmp_path, text, name="tools.json"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    result = SkillScanner().scan_file(path)
    return [finding for finding in result.findings if finding.rule.id == "SG-104"]


def _listing_with(*names):
    tools = [{"name": name, "inputSchema": {"type": "object"}} for name in names]
    return json.dumps({"tools": tools}, indent=2)


def test_issue_example_is_flagged_with_its_name_and_line(tmp_path):
    findings = _scan(tmp_path, ISSUE_EXAMPLE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule.severity.value == "high"
    assert finding.snippets == ["harvest_credentials"]
    assert finding.line_numbers == [1]


def test_control_characters_in_tool_name_are_escaped_in_snippet(tmp_path):
    decoded_name = "harvest_credentials\x1b[2J"

    findings = _scan(tmp_path, _listing_with(decoded_name))

    assert len(findings) == 1
    assert findings[0].snippets == [r"harvest_credentials\x1b[2J"]


@pytest.mark.parametrize("name", TRUE_POSITIVE_NAMES)
def test_harmful_tool_names_are_flagged(tmp_path, name):
    findings = _scan(tmp_path, _listing_with("read_file", name))
    assert len(findings) == 1
    assert findings[0].snippets == [name]


@pytest.mark.parametrize("name", NEAR_MISS_NAMES)
def test_ordinary_names_with_similar_letters_are_not_flagged(tmp_path, name):
    assert _scan(tmp_path, _listing_with("read_file", name)) == []


def test_each_flagged_tool_is_named_and_points_at_its_line(tmp_path):
    text = """{
  "serverInfo": {"name": "files"},
  "tools": [
    {"name": "read_file", "inputSchema": {"type": "object"}},
    {"name": "steal_cookies", "inputSchema": {"type": "object"}},

    {"name": "stealth_mode_toggle", "inputSchema": {"type": "object"}},
    {"name": "dump_credentials", "inputSchema": {"type": "object"}}
  ]
}
"""
    findings = _scan(tmp_path, text)
    assert len(findings) == 1
    assert findings[0].snippets == ["steal_cookies", "dump_credentials"]
    assert findings[0].line_numbers == [5, 8]


def test_word_in_a_skill_text_is_not_a_listing_finding(tmp_path):
    text = "---\nname: notes\n---\nThe tool harvest_credentials is described here.\n"
    assert _scan(tmp_path, text, name="SKILL.md") == []


def test_ordinary_json_with_the_name_is_not_scanned_as_a_listing(tmp_path):
    text = json.dumps({"tools": [{"name": "harvest_credentials"}]})
    assert _scan(tmp_path, text) == []


def test_matching_stays_fast_on_ten_thousand_tools():
    rule = next(r for r in ALL_RULES if r.id == "SG-104")
    names = [f"read_file_{i}" for i in range(10_000)]
    names[::2] = [f"harvest_credentials_{i}" for i in range(0, 10_000, 2)]
    listing = parse_listing(_listing_with(*names), ".json")
    started = time.perf_counter()
    hits = rule.match_listing(listing)
    elapsed = time.perf_counter() - started
    assert len(hits) == 5000
    assert elapsed < 2.0, f"matching took {elapsed:.2f}s"
