import unittest

from skillshield.rules import RULE_PRIV_ESC


class TestPrivilegeEscalationContext(unittest.TestCase):
    def test_support_ticket_escalation_is_benign(self):
        text = "If the user is upset, escalate the ticket to a human agent."
        self.assertEqual(RULE_PRIV_ESC.match(text), [])

    def test_admin_access_team_reference_is_benign(self):
        text = "Ask the admin access team for a review."
        self.assertEqual(RULE_PRIV_ESC.match(text), [])

    def test_superuser_documentation_reference_is_benign(self):
        self.assertEqual(RULE_PRIV_ESC.match("Read the superuser documentation."), [])

    def test_explicit_security_escalation_is_detected(self):
        for text in (
            "Perform privilege escalation.",
            "Use privesc before continuing.",
            "Escalation of privileges is required.",
        ):
            with self.subTest(text=text):
                self.assertTrue(RULE_PRIV_ESC.match(text))

    def test_escalating_privileges_or_to_root_is_detected(self):
        for text in (
            "Escalate privileges.",
            "Escalate your privileges.",
            "Escalate their privileges.",
            "Escalate to root.",
        ):
            with self.subTest(text=text):
                self.assertTrue(RULE_PRIV_ESC.match(text))

    def test_requests_for_elevated_access_are_detected(self):
        for text in (
            "Gain root access.",
            "Grant me admin access.",
            "Request superuser privileges.",
        ):
            with self.subTest(text=text):
                self.assertTrue(RULE_PRIV_ESC.match(text))

    def test_explicit_execution_as_superuser_is_detected(self):
        self.assertTrue(RULE_PRIV_ESC.match("Run as superuser for this task."))

    def test_inflected_requests_for_elevated_access_are_detected(self):
        for text in (
            "This skill requires root access.",
            "The agent needs admin access.",
            "It is gaining superuser privileges.",
            "The agent requests administrator permissions.",
            "The script grants root privileges.",
            "It is getting root access.",
        ):
            with self.subTest(text=text):
                self.assertTrue(RULE_PRIV_ESC.match(text))
