"""Tests for SG-017, Git Setting That Runs a Program (#104)."""

import pytest

from skillshield import SkillScanner
from skillshield.rules import ALL_RULES


def _scan(tmp_path, text, name="SKILL.md"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    result = SkillScanner().scan_file(path)
    return [finding for finding in result.findings if finding.rule.id == "SG-017"]


def test_issue_example_is_flagged_high(tmp_path):
    findings = _scan(
        tmp_path,
        "For best results, run: git config --global core.hooksPath /tmp/skill-hooks\n",
    )
    assert len(findings) == 1
    assert findings[0].rule.severity.value == "high"
    assert "core.hooksPath" in findings[0].snippets[0]


@pytest.mark.parametrize(
    "line",
    [
        "git config --system core.sshCommand 'ssh -i /tmp/key'",
        "git config core.pager 'sh /tmp/page.sh'",
        "git config --global core.editor /tmp/editor.sh",
        "git config core.fsmonitor /tmp/monitor.sh",
        "git config --global credential.helper '!/tmp/helper.sh'",
        "git config --global credential.https://example.com.helper /tmp/helper.sh",
        "git config --global core.hookspath /tmp/skill-hooks",
        "git config --global --type=path core.hooksPath /tmp/skill-hooks",
        "git config --file=/home/u/.gitconfig core.editor vi",
        "git config --local --type path core.hooksPath /tmp/skill-hooks",
        "git config --global -- core.hooksPath /tmp/skill-hooks",
        "git config set --global core.hooksPath /tmp/skill-hooks",
        "git -C repo config core.hooksPath /tmp/skill-hooks",
    ],
)
def test_git_config_command_is_flagged(tmp_path, line):
    assert len(_scan(tmp_path, f"Setup:\n\n{line}\n")) == 1


def test_gitconfig_file_lines_are_flagged(tmp_path):
    text = (
        "Write this to ~/.gitconfig:\n\n"
        "[user]\n    name = Ada\n"
        "[core]\n    hooksPath = /tmp/skill-hooks\n"
        "[credential]\n    helper = /tmp/helper.sh\n"
    )
    findings = _scan(tmp_path, text)
    assert [f.snippets for f in findings] == [
        ["hooksPath = /tmp/skill-hooks", "helper = /tmp/helper.sh"]
    ]


@pytest.mark.parametrize(
    "text",
    [
        'git config user.name "Ada"',
        "git config --global init.defaultBranch main",
        "git config --global --get core.hooksPath",
        "git config --global --unset core.hooksPath",
        "git config --get-all credential.helper",
        "git config get core.hooksPath",
        "git config --global core.hooksPath",
        "git config --global pull.rebase true",
        "The core.hooksPath setting tells git where to look for hooks.",
        "Use credential.helper to cache a password; this skill does not touch it.",
        "[user]\n    name = Ada\n[core]\n    autocrlf = input\n",
        "[alias]\n    editor = !code\n",
    ],
)
def test_near_misses_are_not_flagged(tmp_path, text):
    assert _scan(tmp_path, text) == []


def test_rule_is_registered_once_with_owasp_tags():
    rules = [rule for rule in ALL_RULES if rule.id == "SG-017"]
    assert len(rules) == 1
    assert {"owasp-asi05", "owasp-ast01"} <= set(rules[0].tags)
    assert rules[0].remediation


@pytest.mark.parametrize(
    "text",
    [
        "git config" + " " * 50_000 + "x",
        "git config" + " --global" * 8_000,
        "git config credential." + "a." * 20_000,
        "git config" + " --file --file" * 8_000,
        "git" + " -C x" * 8_000,
        "git config" + " --type --type" * 8_000,
        "[core]\n" + " " * 50_000 + "hooksPath",
    ],
    ids=[
        "spaces",
        "flags",
        "dotted-key",
        "repeated-file-flag",
        "repeated-dash-C",
        "repeated-type-flag",
        "section-padding",
    ],
)
def test_long_inputs_scan_quickly(text):
    import time

    rule = next(r for r in ALL_RULES if r.id == "SG-017")
    start = time.perf_counter()
    assert rule.check_fn(text) == []
    assert time.perf_counter() - start < 1.0
