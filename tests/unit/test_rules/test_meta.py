"""Tests for pad.rules.meta"""

import unittest

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import oa.errors
import oa.rules.meta


class TestMetaRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_msg = Mock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_init(self):
        perlrule = "TEST_1 && TEST_2"
        rule = oa.rules.meta.MetaRule("TEST", perlrule)
        self.assertEqual(rule.rule, perlrule)

    def test_postparsing(self):
        perlrule = "TEST_1 && TEST_2"
        rule = oa.rules.meta.MetaRule("TEST", perlrule)
        mock_ruleset = MagicMock()
        result = rule.postparsing(mock_ruleset)
        self.assertEqual(result, None)

    def test_postparsing_no_match(self):
        perlrule = "TEST_1"
        rule = oa.rules.meta.MetaRule("TEST", perlrule)
        mock_ruleset = MagicMock()
        self.assertRaises(AssertionError, rule.postparsing(mock_ruleset))

    def test_match(self):
        mock_match = Mock(return_value=True)
        rule = oa.rules.meta.MetaRule("TEST", "None")
        rule._location["match"] = mock_match
        result = rule.match(self.mock_msg)

        mock_match.assert_called_once_with(self.mock_msg)
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        mock_match = Mock(return_value=False)
        rule = oa.rules.meta.MetaRule("TEST", "None")
        rule._location["match"] = mock_match
        result = rule.match(self.mock_msg)

        mock_match.assert_called_once_with(self.mock_msg)
        self.assertEqual(result, False)

    def test_get_rule_kwargs(self):
        data = {"value": "TEST_1 && TEST_2"}
        expected = {"rule": "TEST_1 && TEST_2"}
        kwargs = oa.rules.meta.MetaRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestMetaRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
