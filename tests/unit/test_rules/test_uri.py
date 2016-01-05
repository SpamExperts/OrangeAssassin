"""Tests for pad.rules.uri"""

import unittest

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

import pad.rules.uri


class TestUriRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.uri_list = ["www.1.uri.example.com", "www.2.uri.example.com"]
        self.mock_msg = Mock(uri_list=self.uri_list)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        mock_pattern = Mock(**{"match.return_value": True})
        rule = pad.rules.uri.URIRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)

        mock_pattern.match.assert_called_once_with(self.uri_list[0])
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        mock_pattern = Mock(**{"match.return_value": False})
        rule = pad.rules.uri.URIRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)

        calls = [call(uri) for uri in self.uri_list]
        mock_pattern.match.assert_has_calls(calls)
        self.assertEqual(result, False)

    def test_get_rule_kwargs(self):
        mock_perl2re = patch("pad.rules.uri.pad.regex.perl2re").start()
        data = {"value": "/test/"}
        expected = {"pattern": mock_perl2re("/test/")}
        kwargs = pad.rules.uri.URIRule.get_rule_kwargs(data)
        mock_perl2re.assert_called_with("/test/")
        self.assertEqual(kwargs, expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestUriRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
