"""SG-101 checks saved server metadata without contacting the server."""

import json
import subprocess
import sys
import time

import pytest

from skillshield import SkillScanner
from skillshield.mcp import parse_listing
from skillshield.rules import ALL_RULES, Severity
from skillshield.sarif import results_to_sarif


def _scan(**metadata):
    text = json.dumps(
        {
            "serverInfo": {"name": "example"},
            **metadata,
            "tools": [
                {"name": "query", "description": "Query data.", "inputSchema": {}},
                {"name": "lookup", "description": "Look up a record.", "inputSchema": {}},
            ],
        },
        indent=2,
    )
    listing = parse_listing(text, ".json")
    return text, SkillScanner().scan_text(text, listing=listing)


def _findings(result):
    return [finding for finding in result.findings if finding.rule_id == "SG-101"]


@pytest.mark.parametrize(
    "metadata",
    [
        {"url": "https://example.com/mcp"},
        {"url": "https://example.com/mcp", "auth": {"type": "none"}},
        {"url": "https://example.com/mcp", "auth": False},
        {"url": "http://203.0.113.5/mcp", "auth": {"type": "oauth2"}},
        {"transport": "http://example.com/mcp", "auth": {"type": "oauth2"}},
        {"auth": {"apiKey": "sk-test-0000000000000000"}},
        {"auth": {"type": "bearer", "token": "dummy-token-not-a-secret"}},
        {"authentication": {"password": "dummy-password-not-a-secret"}},
        {"auth": {"access_token": "dummy-token-not-a-secret"}},
        {"auth": {"client_secret": "dummy-client-secret"}},
        {"auth": {"api_key": "short-demo-key"}},
        {"transport": "stdio", "auth": {"password": "dummy-password"}},
        {"url": "http://localhost:3000", "auth": {"token": "dummy-token-not-a-secret"}},
        {"auth": {"headers": {"api-key": "dummy-key-not-a-secret"}}},
    ],
)
def test_unsafe_server_metadata_is_high(metadata):
    _, result = _scan(**metadata)
    findings = _findings(result)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert result.risk_level in {"HIGH", "CRITICAL"}
    assert any(tag.startswith("owasp-asi") for tag in findings[0].rule.tags)
    assert any(tag.startswith("owasp-ast") for tag in findings[0].rule.tags)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost.example.com/mcp",
        "http://localhost@203.0.113.5/mcp",
        "http://example.com/mcp?next=localhost",
        "HTTP://EXAMPLE.COM/mcp",
        "http://0.0.0.0:8080/mcp",
    ],
)
def test_localhost_text_does_not_hide_a_remote_http_host(url):
    _, result = _scan(url=url, auth={"type": "oauth2"})
    assert _findings(result)


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {"transport": "stdio"},
        {"transport": "stdio", "auth": {"type": "none"}},
        {"url": "http://localhost:3000"},
        {"url": "http://127.0.0.1:3000"},
        {"url": "http://127.0.0.2:3000"},
        {"url": "http://[::1]:3000"},
        {"url": "http://[::ffff:127.0.0.1]:3000"},
        {"url": "http://LOCALHOST.:3000"},
        {"url": "https://example.com/mcp", "auth": {"type": "oauth2"}},
        {"url": "https://example.com/mcp", "auth": {"apiKeyEnv": "SERVICE_API_KEY"}},
        {"url": "https://example.com/mcp", "auth": {"apiKeyEnv": "SERVICE_PRIVATE_KEY"}},
        {"url": "https://example.com/mcp", "auth": {"token": "${SERVICE_TOKEN}"}},
        {"url": "https://example.com/mcp", "auth": {"token": "$SERVICE_TOKEN"}},
        {"url": "https://example.com/mcp", "auth": {"token": "env:SERVICE_TOKEN"}},
        {"url": "https://example.com/mcp", "auth": {"token": "%SERVICE_TOKEN%"}},
        {"url": "https://example.com/mcp", "auth": {"token": {"env": "SERVICE_TOKEN"}}},
        {"url": "https://example.com/mcp", "auth": {"token": {"env": "SERVICE_PRIVATE_KEY"}}},
        {
            "url": "https://example.com/mcp",
            "auth": {"headers": {"Authorization": "Bearer ${SERVICE_TOKEN}"}},
        },
    ],
)
def test_local_and_environment_based_authentication_is_not_flagged(metadata):
    _, result = _scan(**metadata)
    assert _findings(result) == []


def test_bare_protocol_listings_do_not_claim_authentication_is_missing():
    for payload, suffix in [
        ({"jsonrpc": "2.0", "result": {"tools": [{"name": "query"}]}}, ".json"),
        ({"name": "query", "inputSchema": {}}, ".jsonl"),
    ]:
        text = json.dumps(payload)
        listing = parse_listing(text, suffix)
        assert listing is not None
        assert _findings(SkillScanner().scan_text(text, listing=listing)) == []


def test_authentication_findings_name_tools_and_use_their_source_lines():
    text, result = _scan(url="https://example.com/mcp")
    finding = _findings(result)[0]
    assert any("query" in snippet for snippet in finding.snippets)
    assert any("lookup" in snippet for snippet in finding.snippets)
    assert finding.line_numbers == [
        n for n, line in enumerate(text.splitlines(), 1) if line == "    {"
    ]
    sarif = results_to_sarif([result])
    entry = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "SG-101")
    assert entry["level"] == "error"
    assert [loc["physicalLocation"]["region"]["startLine"] for loc in entry["locations"]] == (
        finding.line_numbers
    )


def test_new_authentication_snippets_do_not_echo_credentials():
    secret = "dummy-token-not-a-secret"
    _, result = _scan(auth={"token": secret})
    findings = _findings(result)
    assert findings
    assert all(secret not in snippet for finding in findings for snippet in finding.snippets)


def test_malformed_url_does_not_hide_a_hardcoded_credential():
    _, result = _scan(url="http://[invalid", auth={"token": "dummy-token-not-a-secret"})
    assert _findings(result)


def test_empty_server_has_no_tool_authentication_finding():
    text = '{"serverInfo":{"name":"empty"},"url":"https://example.com/mcp","tools":[]}'
    listing = parse_listing(text, ".json")
    assert listing is not None
    assert _findings(SkillScanner().scan_text(text, listing=listing)) == []


def test_authentication_rule_handles_ten_thousand_tools_quickly():
    rule = next((rule for rule in ALL_RULES if rule.id == "SG-101"), None)
    assert rule is not None
    text = json.dumps(
        {
            "serverInfo": {"name": "many-tools"},
            "url": "https://example.com/mcp",
            "tools": [{"name": f"query_{i}"} for i in range(10_000)],
        }
    )
    listing = parse_listing(text, ".json")
    start = time.perf_counter()
    hits = rule.match_listing(listing)
    assert len(hits) == 10_000
    assert time.perf_counter() - start < 1.0


def test_cli_json_reports_saved_unsafe_authentication(tmp_path):
    text, _ = _scan(auth={"token": "dummy-token-not-a-secret"})
    path = tmp_path / "tools.json"
    path.write_text(text, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "skillshield.cli", "scan", str(path), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert any(finding["id"] == "SG-101" for finding in payload["findings"])
