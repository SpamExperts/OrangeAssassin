"""Tests for pad.rules.body"""

import unittest

try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock

import oa.rules.body


class TestBodyRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_msg = Mock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        mock_pattern = Mock(**{"match.return_value": True})
        rule = oa.rules.body.BodyRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)
        mock_pattern.match.assert_called_with(self.mock_msg.text)
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        mock_pattern = Mock(**{"match.return_value": False})
        rule = oa.rules.body.BodyRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)
        mock_pattern.match.assert_called_with(self.mock_msg.text)
        self.assertEqual(result, False)

    def test_get_rule_kwargs(self):
        mock_perl2re = patch("oa.rules.body.oa.regex.perl2re").start()
        data = {"value": "/test/"}
        expected = {"pattern": mock_perl2re("/test/")}
        kwargs = oa.rules.body.BodyRule.get_rule_kwargs(data)
        mock_perl2re.assert_called_with("/test/")
        self.assertEqual(kwargs, expected)


class TestRawBodyRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_msg = Mock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        mock_pattern = Mock(**{"match.return_value": True})
        rule = oa.rules.body.RawBodyRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)
        mock_pattern.match.assert_called_with(self.mock_msg.raw_text)
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        mock_pattern = Mock(**{"match.return_value": False})
        rule = oa.rules.body.RawBodyRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)
        mock_pattern.match.assert_called_with(self.mock_msg.raw_text)
        self.assertEqual(result, False)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestBodyRule, "test"))
    test_suite.addTest(unittest.makeSuite(TestRawBodyRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
