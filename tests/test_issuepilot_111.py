import io
import json
import sys
import unittest
from unittest.mock import patch

from skillshield import cli
from skillshield.rules import ALL_RULES


class TestRulesJson(unittest.TestCase):
    def invoke(self, *arguments, expected_code=0):
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["skillshield", "rules", *arguments]),
            patch.object(sys, "stdout", output),
            patch.object(sys, "stderr", io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as stopped:
                cli.main()
        self.assertEqual(stopped.exception.code, expected_code)
        return output.getvalue()

    def test_json_lists_every_rule_with_complete_metadata(self):
        rules = json.loads(self.invoke("--format", "json"))
        self.assertIsInstance(rules, list)
        self.assertEqual([entry["id"] for entry in rules], [rule.id for rule in ALL_RULES])
        for entry, rule in zip(rules, ALL_RULES):
            with self.subTest(rule=rule.id):
                self.assertEqual(
                    entry,
                    {
                        "id": rule.id,
                        "name": rule.name,
                        "severity": rule.severity.value,
                        "tags": rule.tags,
                        "description": rule.description,
                        "remediation": rule.remediation,
                    },
                )

    def test_explicit_text_matches_the_default_report(self):
        default = self.invoke()
        self.assertEqual(self.invoke("--format", "text"), default)
        self.assertTrue(
            default.startswith(f"\nSkillShield has {len(ALL_RULES)} detection rules:\n")
        )
        self.assertIn("SG-001  [CRITICAL]  Prompt Injection", default)

    def test_unsupported_format_is_rejected(self):
        self.assertEqual(self.invoke("--format", "yaml", expected_code=2), "")
