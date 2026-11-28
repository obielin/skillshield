"""Tests for SG-018, Library Preloaded Into Other Programs (#103)."""

import pytest

from skillshield import SkillScanner
from skillshield.rules import ALL_RULES


def _scan(tmp_path, text, name="SKILL.md"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    result = SkillScanner().scan_file(path)
    return [finding for finding in result.findings if finding.rule.id == "SG-018"]


def test_issue_example_is_flagged_medium(tmp_path):
    findings = _scan(
        tmp_path,
        "Before running the tool, export LD_PRELOAD=/tmp/helper.so so the hook is active.\n",
    )
    assert len(findings) == 1
    assert findings[0].rule.severity.value == "medium"
    assert "LD_PRELOAD=/tmp/helper.so" in findings[0].snippets[0]


@pytest.mark.parametrize(
    "line",
    [
        "export LD_PRELOAD=/tmp/helper.so",
        "LD_PRELOAD=/opt/hook.so ./run-tool --fast",
        "env LD_PRELOAD='/opt/hook.so' python tool.py",
        "export DYLD_INSERT_LIBRARIES=/tmp/hook.dylib",
        "DYLD_INSERT_LIBRARIES=$HOME/hook.dylib ./run-tool",
        "export LD_PRELOAD=$LD_PRELOAD:/tmp/helper.so",
        "setenv LD_PRELOAD /tmp/helper.so",
        "ENV LD_PRELOAD /opt/hook.so",
        "ENV LD_PRELOAD=/opt/hook.so",
        "export LD_LIBRARY_PATH=/tmp/libs",
        "export LD_LIBRARY_PATH=/tmp",
        "export LD_LIBRARY_PATH=/usr/lib:/var/tmp/libs:$LD_LIBRARY_PATH",
        'LD_LIBRARY_PATH="$HOME/Downloads/libs" ./run-tool',
        "export LD_LIBRARY_PATH=/home/ada/Downloads/pkg/lib",
        "export LD_LIBRARY_PATH=~/Downloads",
        "export LD_LIBRARY_PATH=/dev/shm/x:/usr/lib",
        "echo /tmp/helper.so >> /etc/ld.so.preload",
        "echo /tmp/helper.so > /etc/ld.so.preload",
        "echo /tmp/helper.so | sudo tee -a /etc/ld.so.preload",
        "sudo cp /tmp/helper.so /etc/ld.so.preload",
        "sudo mv helper.so /etc/ld.so.preload",
        "sudo install -m 644 helper.so /etc/ld.so.preload",
        "open('/etc/ld.so.preload', 'w').write('/tmp/helper.so')",
    ],
)
def test_preload_and_risky_library_path_are_flagged(tmp_path, line):
    assert len(_scan(tmp_path, f"Setup:\n\n{line}\n")) == 1


def test_one_finding_collects_each_distinct_hit(tmp_path):
    text = "export LD_PRELOAD=/tmp/a.so\nexport DYLD_INSERT_LIBRARIES=/tmp/b.dylib\n"
    findings = _scan(tmp_path, text)
    assert len(findings) == 1
    assert len(findings[0].snippets) == 2


@pytest.mark.parametrize(
    "text",
    [
        "LD_PRELOAD is an environment variable that lists libraries to load first.",
        "DYLD_INSERT_LIBRARIES works on macOS much like LD_PRELOAD does on Linux.",
        "Explain what /etc/ld.so.preload does, but do not edit it.",
        "unset LD_PRELOAD",
        "echo $LD_PRELOAD",
        'echo "LD_PRELOAD is $LD_PRELOAD"',
        "LD_PRELOAD= ./run-tool",
        "export LD_PRELOAD=",
        "export LD_LIBRARY_PATH=/usr/local/lib",
        "export LD_LIBRARY_PATH=/opt/app/lib:/usr/lib",
        "export LD_LIBRARY_PATH=/tmpfiles/lib",
        "export LD_LIBRARY_PATH=/home/ada/Downloads-archive/lib",
        "cat /etc/ld.so.preload",
        "diff a b > /etc/ld.so.preload.new",
        "grep helper /etc/ld.so.preload",
        "wc -l < /etc/ld.so.preload",
        "open('/etc/ld.so.preload').read()",
    ],
)
def test_near_misses_are_not_flagged(tmp_path, text):
    assert _scan(tmp_path, text) == []


def test_rule_is_registered_once_with_owasp_tags():
    rules = [rule for rule in ALL_RULES if rule.id == "SG-018"]
    assert len(rules) == 1
    assert {"owasp-asi05", "owasp-ast01"} <= set(rules[0].tags)
    assert rules[0].remediation


@pytest.mark.parametrize(
    "text",
    [
        "LD_PRELOAD" + " " * 50_000 + "x",
        "LD_LIBRARY_PATH=" + "a:" * 40_000,
        "LD_LIBRARY_PATH=" * 8_000,
        "LD_LIBRARY_PATH=" + "/a" * 40_000,
        "tee" + " -a" * 20_000,
        "cp" + " x" * 40_000,
        "cp x " * 20_000 + "/etc/ld.so.prelo",
        ">" + " " * 50_000,
        "ENV" + " " * 50_000 + "LD_PRELOAD",
    ],
    ids=[
        "spaces",
        "colon-segments",
        "repeated-prefix",
        "long-path",
        "repeated-tee-flag",
        "cp-arguments",
        "repeated-cp-near-miss",
        "redirect-padding",
        "env-padding",
    ],
)
def test_long_inputs_scan_quickly(text):
    import time

    rule = next(r for r in ALL_RULES if r.id == "SG-018")
    start = time.perf_counter()
    assert rule.check_fn(text) == []
    assert time.perf_counter() - start < 1.0
