"""Tests for pad.rules.meta"""

import unittest

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

import pad.errors
import pad.rules.meta


class TestMetaRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_msg = Mock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        mock_match = Mock(return_value=True)
        rule = pad.rules.meta.MetaRule("TEST", "None")
        rule._location["match"] = mock_match
        result = rule.match(self.mock_msg)

        mock_match.assert_called_once_with(self.mock_msg)
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        mock_match = Mock(return_value=False)
        rule = pad.rules.meta.MetaRule("TEST", "None")
        rule._location["match"] = mock_match
        result = rule.match(self.mock_msg)

        mock_match.assert_called_once_with(self.mock_msg)
        self.assertEqual(result, False)

    def test_get_rule_kwargs(self):
        data = {"value": "TEST_1 && TEST_2"}
        expected = {"rule": "TEST_1 && TEST_2"}
        kwargs = pad.rules.meta.MetaRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_init_subrules(self):
        perlrule = "TEST_1 && TEST_2"
        expected = {"TEST_1", "TEST_2"}
        rule = pad.rules.meta.MetaRule("TEST", perlrule)
        self.assertEqual(rule.subrules, expected)

    def test_init_convert_rule(self):
        perlrule = "TEST_1&&TEST_2"
        expected = "match = lambda msg: TEST_1(msg) and TEST_2(msg)"
        rule = pad.rules.meta.MetaRule("TEST", perlrule)
        self.assertEqual(rule.rule, expected)

    def test_init_convert_syntax(self):
        perlrule = "TEST_1&&TEST_2||!TEST_3"
        expected = "TEST_1(msg) and TEST_2(msg) or  not TEST_3(msg)"
        expected = "match = lambda msg: %s" % expected
        rule = pad.rules.meta.MetaRule("TEST", perlrule)
        self.assertEqual(rule.rule, expected)

    def test_postparsing(self):
        perlrule = "TEST_1 && TEST_2"
        mock_subrule = Mock()
        mock_ruleset = Mock(**{"get_rule.return_value": mock_subrule})
        rule = pad.rules.meta.MetaRule("TEST", perlrule)
        rule.postparsing(mock_ruleset)
        self.assertEqual(rule._location["TEST_1"], mock_subrule.match)
        self.assertEqual(rule._location["TEST_2"], mock_subrule.match)

    def test_postparsing_nomatch(self):
        mock_ruleset = Mock()
        rule = pad.rules.meta.MetaRule("TEST", "None")
        rule._code_obj = compile("None", "<meta>", "exec")
        self.assertRaises(AssertionError, rule.postparsing, mock_ruleset)

    def test_postparsing_undefined_subrule(self):
        mock_ruleset = Mock(**{"get_rule.side_effect": KeyError})
        rule = pad.rules.meta.MetaRule("TEST", "None")
        rule._code_obj = compile("None", "<meta>", "exec")
        self.assertRaises(pad.errors.InvalidRule, rule.postparsing,
                          mock_ruleset)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestMetaRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
