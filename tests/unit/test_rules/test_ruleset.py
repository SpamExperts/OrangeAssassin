"""Tests for pad.rules.ruleset"""

import email
import unittest

try:
    from unittest.mock import patch, Mock, PropertyMock, MagicMock, call
except ImportError:
    from mock import patch, Mock, PropertyMock, MagicMock, call

import pad.errors
import pad.rules.ruleset


class TestRuleSet(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_ctxt = Mock(plugins={}, conf={
            "report": [],
            "add_header": [],
            "remove_header": [],
            "required_score": 5,
            "report_contact": "",
            "report_safe": 1,
            "dns_query_restriction": [],
            "dns_options": "",
        })

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        mock_msg = MagicMock(rules_checked={})
        mock_rule = MagicMock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.checked = {"TEST_RULE": mock_rule}

        ruleset.match(mock_msg)

        mock_rule.match.assert_called_with(mock_msg)
        self.assertEqual(mock_msg.rules_checked["TEST_RULE"],
                         mock_rule.match(mock_msg))

    def test_match_check_score(self):
        mock_msg = MagicMock(rules_checked={}, score=0)
        mock_rule = MagicMock(score=42)
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.checked = {"TEST_RULE": mock_rule}

        ruleset.match(mock_msg)
        self.assertEqual(mock_msg.score, 42)

    def test_no_match_check_score(self):
        mock_msg = MagicMock(rules_checked={}, score=0)
        mock_rule = MagicMock(score=42, match=lambda m: False)
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.checked = {"TEST_RULE": mock_rule}

        ruleset.match(mock_msg)
        self.assertEqual(mock_msg.score, 0)

    def test_get_rule(self):
        mock_rule = Mock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.checked = {"TEST_RULE": mock_rule}

        self.assertEqual(ruleset.get_rule("TEST_RULE"), mock_rule)

    def test_get_rule_not_checked(self):
        mock_rule = Mock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.not_checked = {"TEST_RULE": mock_rule}

        self.assertEqual(ruleset.get_rule("TEST_RULE"), mock_rule)

    def test_get_rule_check_only(self):
        mock_rule = Mock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.not_checked = {"TEST_RULE": mock_rule}

        self.assertRaises(KeyError, ruleset.get_rule, "TEST_RULE",
                          checked_only=True)

    def test_add_rule_should_check(self):
        mock_rule = Mock(**{"should_check.return_value": True})
        name_mock = PropertyMock(return_value="TEST_RULE")
        type(mock_rule).name = name_mock

        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.add_rule(mock_rule)
        self.assertEqual(ruleset.checked, {"TEST_RULE": mock_rule})
        self.assertEqual(ruleset.not_checked, {})

    def test_add_rule_should_not_check(self):
        mock_rule = Mock(**{"should_check.return_value": False})
        name_mock = PropertyMock(return_value="TEST_RULE")
        type(mock_rule).name = name_mock

        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.add_rule(mock_rule)
        self.assertEqual(ruleset.checked, {})
        self.assertEqual(ruleset.not_checked, {"TEST_RULE": mock_rule})

    def test_add_rule_preprocess(self):
        mock_rule = Mock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)

        ruleset.add_rule(mock_rule)
        mock_rule.preprocess.assert_called_with(ruleset)

    def test_add_rule_postprocess(self):
        mock_rule = Mock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)

        ruleset.add_rule(mock_rule)
        mock_rule.postprocess.assert_called_with(ruleset)

    def test_post_parsing(self):
        mock_rule = Mock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.checked = {"TEST_RULE": mock_rule}

        ruleset.post_parsing()
        mock_rule.postparsing.assert_called_with(ruleset)

    def test_post_parsing_invalid_rule(self):
        mock_rule = Mock(**{"postparsing.side_effect":
                            pad.errors.InvalidRule("TEST_RULE")})
        self.mock_ctxt.paranoid = False
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.checked = {"TEST_RULE": mock_rule}

        ruleset.post_parsing()
        mock_rule.postparsing.assert_called_with(ruleset)
        self.assertEqual(ruleset.checked, {})

    def test_post_parsing_invalid_rule_parnoid(self):
        mock_rule = Mock(**{"postparsing.side_effect":
                            pad.errors.InvalidRule("TEST_RULE")})
        self.mock_ctxt.paranoid = True
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.checked = {"TEST_RULE": mock_rule}

        self.assertRaises(pad.errors.InvalidRule, ruleset.post_parsing)

    def test_interpolate(self):
        mock_msg = MagicMock(rules_checked={}, interpolate_data={}, score=4)
        mock_rule = MagicMock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.checked = {"TEST_RULE": mock_rule}

        result = ruleset._interpolate("test %(REQD)s test", mock_msg)
        self.assertEqual(result, "test 5.0 test")

    def test_interpolate_spam(self):
        mock_msg = MagicMock(rules_checked={}, interpolate_data={}, score=6)
        mock_rule = MagicMock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.checked = {"TEST_RULE": mock_rule}

        result = ruleset._interpolate("test %(YESNO)s test", mock_msg)
        self.assertEqual(result, "test Yes test")

    def test_interpolate_not_spam(self):
        mock_msg = MagicMock(rules_checked={}, interpolate_data={}, score=4)
        mock_rule = MagicMock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.checked = {"TEST_RULE": mock_rule}

        result = ruleset._interpolate("test %(YESNO)s test", mock_msg)
        self.assertEqual(result, "test No test")

    def test_interpolate_data_available(self):
        mock_msg = MagicMock(rules_checked={}, interpolate_data={"REQD": "5.0"},
                             score=4)
        mock_rule = MagicMock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.checked = {"TEST_RULE": mock_rule}

        result = ruleset._interpolate("test %(REQD)s test", mock_msg)
        self.assertEqual(result, "test 5.0 test")

    def test_convert_tags(self):
        original = '"test _YESNO_ test"'
        expected = 'test %(YESNO)s test'
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)

        result = ruleset._convert_tags(original)
        self.assertEqual(result, expected)

    def test_convert_tags_check_empty(self):
        original = '"test _YESNO_ test"'
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)

        ruleset._convert_tags(original)
        self.assertIn("YESNO", ruleset.tags)

    def test_get_report(self):
        mock_int = patch("pad.rules.ruleset.RuleSet._interpolate").start()
        mock_msg = MagicMock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.conf["report"].append("Some report")

        result = ruleset.get_report(mock_msg)
        self.assertEqual(result, mock_int("Some report", mock_msg) + "\n")

    def test_get_report_no_report(self):
        mock_msg = MagicMock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)

        result = ruleset.get_report(mock_msg)
        self.assertEqual(result, "\n(no report template found)\n")

    def test_add_header_rule_all(self):
        line = "all Test my value"
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset._add_header_rule(line, remove=False)

        result = ruleset.header_mod["all"][0]
        self.assertEqual(result, (False, "X-Spam-Test", "my value"))

    def test_add_header_rule_spam(self):
        line = "spam Test my value"
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset._add_header_rule(line, remove=False)

        result = ruleset.header_mod["spam"][0]
        self.assertEqual(result, (False, "X-Spam-Test", "my value"))

    def test_add_header_rule_ham(self):
        line = "ham Test my value"
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset._add_header_rule(line, remove=False)

        result = ruleset.header_mod["ham"][0]
        self.assertEqual(result, (False, "X-Spam-Test", "my value"))

    def test_add_header_rule_invalid(self):
        line = "bam Test my value"
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)

        with self.assertRaises(pad.errors.InvalidRule):
            ruleset._add_header_rule(line, remove=False)

    def test_remove_header_rule_all(self):
        line = "all Test"
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset._add_header_rule(line, remove=True)

        result = ruleset.header_mod["all"][0]
        self.assertEqual(result, (True, "X-Spam-Test", None))

    def test_remove_header_rule_spam(self):
        line = "spam Test"
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset._add_header_rule(line, remove=True)

        result = ruleset.header_mod["spam"][0]
        self.assertEqual(result, (True, "X-Spam-Test", None))

    def test_remove_header_rule_ham(self):
        line = "ham Test"
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset._add_header_rule(line, remove=True)

        result = ruleset.header_mod["ham"][0]
        self.assertEqual(result, (True, "X-Spam-Test", None))

    def test_remove_header_rule_invalid(self):
        line = "bam Test"
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)

        with self.assertRaises(pad.errors.InvalidRule):
            ruleset._add_header_rule(line, remove=True)

    def test_adjusted_all_spam(self):
        mock_bounce = patch("pad.rules.ruleset.RuleSet."
                            "_get_bounce_message").start()
        mock_adjust = patch("pad.rules.ruleset.RuleSet."
                            "_adjust_headers").start()
        mock_msg = MagicMock(score=6)
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.header_mod["all"].append("All mod")
        ruleset.header_mod["spam"].append("Spam mod")
        result = ruleset.get_adjusted_message(mock_msg)

        newmsg = mock_bounce(mock_msg)
        self.assertEqual(result, newmsg.as_string())

        calls = [
            call(mock_msg, newmsg, ["All mod"]),
            call(mock_msg, newmsg, ["Spam mod"])
        ]

        mock_adjust.assert_has_calls(calls)

    def test_adjusted_all_not_spam(self):
        mock_email = patch("pad.rules.ruleset."
                           "email.message_from_string").start()
        mock_bounce = patch("pad.rules.ruleset.RuleSet."
                            "_get_bounce_message").start()
        mock_adjust = patch("pad.rules.ruleset.RuleSet."
                            "_adjust_headers").start()
        mock_msg = MagicMock(score=4)
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.header_mod["all"].append("All mod")
        ruleset.header_mod["ham"].append("Ham mod")
        result = ruleset.get_adjusted_message(mock_msg)

        newmsg = mock_email(mock_msg.raw_msg)
        self.assertEqual(result, newmsg.as_string())

        calls = [
            call(mock_msg, newmsg, ["All mod"]),
            call(mock_msg, newmsg, ["Ham mod"])
        ]

        mock_adjust.assert_has_calls(calls)

    def test_adjusted_header_only_spam(self):
        mock_email = patch("pad.rules.ruleset."
                           "email.message_from_string").start()
        mock_bounce = patch("pad.rules.ruleset.RuleSet."
                            "_get_bounce_message").start()
        mock_adjust = patch("pad.rules.ruleset.RuleSet."
                            "_adjust_headers").start()
        mock_msg = MagicMock(score=6)
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.header_mod["all"].append("All mod")
        ruleset.header_mod["spam"].append("Spam mod")
        result = ruleset.get_adjusted_message(mock_msg, True)

        newmsg = mock_email(mock_msg.raw_msg)
        self.assertEqual(
            result, newmsg.as_string().split("\n\n", 1)[0] + "\n\n")

        calls = [
            call(mock_msg, newmsg, ["All mod"]),
            call(mock_msg, newmsg, ["Spam mod"])
        ]

        mock_adjust.assert_has_calls(calls)

    def test_adjusted_header_only_not_spam(self):
        mock_email = patch("pad.rules.ruleset."
                           "email.message_from_string").start()
        mock_bounce = patch("pad.rules.ruleset.RuleSet."
                            "_get_bounce_message").start()
        mock_adjust = patch("pad.rules.ruleset.RuleSet."
                            "_adjust_headers").start()
        mock_msg = MagicMock(score=4)
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset.header_mod["all"].append("All mod")
        ruleset.header_mod["ham"].append("Ham mod")
        result = ruleset.get_adjusted_message(mock_msg, True)

        newmsg = mock_email(mock_msg.raw_msg)
        self.assertEqual(
            result, newmsg.as_string().split("\n\n", 1)[0] + "\n\n")

        calls = [
            call(mock_msg, newmsg, ["All mod"]),
            call(mock_msg, newmsg, ["Ham mod"])
        ]

        mock_adjust.assert_has_calls(calls)

    def test_adjust_headers(self):
        rules = [(False, "X-Spam-Test", "value")]
        mock_msg = MagicMock(interpolate_data={"TEST": "test"})
        newmsg = MagicMock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset._adjust_headers(mock_msg, newmsg, rules)

        newmsg.add_header.assert_called_with("X-Spam-Test", "value")

    def test_adjust_headers_remove(self):
        rules = [(True, "X-Spam-Test", None)]
        mock_msg = MagicMock(interpolate_data={"TEST": "test"})
        newmsg = MagicMock()
        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        ruleset._adjust_headers(mock_msg, newmsg, rules)

        newmsg.__delitem__.assert_called_with("X-Spam-Test")

    def test_get_bounce_message(self):
        text = ("Subject: Test\n"
                "From: alex@example.com\n"
                "To: chirila@example.com\n\n"
                "This is a test.")
        msg = email.message_from_string(text)
        mock_msg = MagicMock(msg=msg)

        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        newmsg = ruleset._get_bounce_message(mock_msg)

        self.assertEqual(newmsg['Subject'], "Test")
        self.assertEqual(newmsg['From'], "chirila@example.com")
        self.assertEqual(newmsg['To'], "alex@example.com")

    def test_get_bounce_message_attach(self):
        patch("pad.rules.ruleset.RuleSet.get_report",
              return_value="Test report.").start()
        text = ("Subject: Test\n"
                "From: alex@example.com\n"
                "To: chirila@example.com\n\n"
                "This is a test.")
        msg = email.message_from_string(text)
        mock_msg = MagicMock(msg=msg, raw_msg=text)

        ruleset = pad.rules.ruleset.RuleSet(self.mock_ctxt)
        newmsg = ruleset._get_bounce_message(mock_msg)

        parts = list(newmsg.walk())
        self.assertEqual(parts[1].get_payload(decode=True),
                         b"Test report.")
        self.assertEqual(parts[2].get_payload(decode=True), text.encode("utf8"))


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestRuleSet, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
