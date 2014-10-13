"""Tests for sa.rules.full"""

import unittest

try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock

import sa.rules.full


class TestFullRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_msg = Mock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        mock_pattern = Mock(**{"match.return_value": True})
        rule = sa.rules.full.FullRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)
        mock_pattern.match.assert_called_with(self.mock_msg.raw_msg)
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        mock_pattern = Mock(**{"match.return_value": False})
        rule = sa.rules.full.FullRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)
        mock_pattern.match.assert_called_with(self.mock_msg.raw_msg)
        self.assertEqual(result, False)

    def test_get_rule_kwargs(self):
        mock_perl2re = patch("sa.rules.body.sa.regex.perl2re").start()
        data = {"value": "/test/"}
        expected = {"pattern": mock_perl2re("/test/")}
        kwargs = sa.rules.full.FullRule.get_rule_kwargs(data)
        mock_perl2re.assert_called_with("/test/")
        self.assertEqual(kwargs, expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFullRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
