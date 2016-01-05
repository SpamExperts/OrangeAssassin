"""Tests for pad.rules.base"""

import unittest

try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock


import pad.errors
import pad.rules.base


class TestBaseRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_msg = Mock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_init_base(self):
        rule = pad.rules.base.BaseRule("TEST", [0.75], "Some Rule")
        self.assertEqual(rule.name, "TEST")
        self.assertEqual(rule._scores, [0.75])
        self.assertEqual(rule.description, "Some Rule")

    def test_init_base_no_score(self):
        rule = pad.rules.base.BaseRule("TEST", None, "Some Rule")
        self.assertEqual(rule.name, "TEST")
        self.assertEqual(rule._scores, [1.0])
        self.assertEqual(rule.description, "Some Rule")

    def test_init_base_no_desc(self):
        rule = pad.rules.base.BaseRule("TEST", [0.75], None)
        self.assertEqual(rule.name, "TEST")
        self.assertEqual(rule._scores, [0.75])
        self.assertEqual(rule.description, "No description available.")

    def test_init_base_invalid_score(self):
        self.assertRaises(pad.errors.InvalidRule, pad.rules.base.BaseRule,
                          "TEST", [0.75, 1.0])

    def test_match(self):
        rule = pad.rules.base.BaseRule("TEST")
        self.assertRaises(NotImplementedError, rule.match, self.mock_msg)

    def test_should_check(self):
        rule = pad.rules.base.BaseRule("TEST")
        self.assertEqual(rule.should_check(), True)

    def test_should_check_dunderscore(self):
        rule = pad.rules.base.BaseRule("__TEST")
        self.assertEqual(rule.should_check(), False)

    def test_should_check_zero_score(self):
        rule = pad.rules.base.BaseRule("TEST", [0])
        self.assertEqual(rule.should_check(), False)

    def test_preprocess(self):
        rule = pad.rules.base.BaseRule("TEST")
        self.assertIsNone(rule.preprocess(None))
        self.assertEqual(rule.score, 1.0)

    def test_preprocess_advanced(self):
        mock_ruleset = Mock(use_bayes=True, use_network=False)
        rule = pad.rules.base.BaseRule("TEST", [1.0, 2.0, 3.0, 4.0])
        rule.preprocess(mock_ruleset)
        self.assertEqual(rule.score, 3.0)

    def test_postprocess(self):
        rule = pad.rules.base.BaseRule("TEST")
        self.assertIsNone(rule.postprocess(None))

    def test_get_rule_kwargs(self):
        data = {"score": "0.1 0.2 0.3",
                "describe": "Test"}
        expected = {"score": [0.1, 0.2, 0.3],
                    "desc": "Test"}
        kwargs = pad.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_no_score(self):
        data = {"describe": "Test"}
        expected = {"desc": "Test"}
        kwargs = pad.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_no_desciptions(self):
        data = {"score": "0.1 0.2 0.3"}
        expected = {"score": [0.1, 0.2, 0.3]}
        kwargs = pad.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_no_data(self):
        data = {}
        expected = {}
        kwargs = pad.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule(self):
        mock_get_kwargs = patch("pad.rules.base.BaseRule.get_rule_kwargs",
                                return_value={}).start()
        rule = pad.rules.base.BaseRule.get_rule("test", {})
        mock_get_kwargs.assert_called_with({})
        self.assertEqual(rule.name, "test")

    def test_str(self):
        expected = "* 0 TEST DESC"
        rule = pad.rules.base.BaseRule("TEST", [0], "DESC")
        self.assertEqual(str(rule), expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestBaseRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
