"""Tests for pad.rules.eval_"""

import unittest

try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock

import pad.errors
import pad.rules.eval_


class TestEvalRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_msg = Mock()
        self.eval_rules = {}
        self.mock_ruleset = Mock(**{"ctxt.eval_rules": self.eval_rules})

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        mock_method = Mock(return_value=True)
        rule = pad.rules.eval_.EvalRule("TEST", "test_rule()")
        rule.eval_rule = mock_method

        result = rule.match(self.mock_msg)
        mock_method.assert_called_with(self.mock_msg)
        self.assertEqual(result, True)

    def test_not_match(self):
        mock_method = Mock(return_value=False)
        rule = pad.rules.eval_.EvalRule("TEST", "test_rule()")
        rule.eval_rule = mock_method

        result = rule.match(self.mock_msg)
        mock_method.assert_called_with(self.mock_msg)
        self.assertEqual(result, False)

    def test_extract_args(self):
        rule = pad.rules.eval_.EvalRule("TEST", "test_rule(1, '2')")

        self.assertEqual(rule.eval_args, (1, '2'))
        self.assertEqual(rule.eval_rule_name, "test_rule")

    def test_extract_args_invalid_rule_name(self):
        self.assertRaises(pad.errors.InvalidRule, pad.rules.eval_.EvalRule,
                          "TEST", "1test_rule(1, '2')")

    def test_extract_args_invalid_args(self):
        self.assertRaises(pad.errors.InvalidRule, pad.rules.eval_.EvalRule,
                          "TEST", "test_rule(1, '2)")

    def test_preprocess(self):
        mock_eval = Mock()
        self.eval_rules["test_rule"] = mock_eval
        rule = pad.rules.eval_.EvalRule("TEST", "test_rule(1, '2')")
        rule.preprocess(self.mock_ruleset)

        rule.match(self.mock_msg)
        mock_eval.assert_called_with(self.mock_msg, 1, '2', target=None)

    def test_preprocess_target(self):
        mock_eval = Mock()
        self.eval_rules["test_rule"] = mock_eval
        rule = pad.rules.eval_.EvalRule("TEST", "test_rule(1, '2')",
                                        target="body")
        rule.preprocess(self.mock_ruleset)

        rule.match(self.mock_msg)
        mock_eval.assert_called_with(self.mock_msg, 1, '2', target="body")

    def test_preprocess_missing_rule(self):
        rule = pad.rules.eval_.EvalRule("TEST", "test_rule(1, '2')")
        self.assertRaises(pad.errors.InvalidRule,
                          rule.preprocess, self.mock_ruleset)

    def test_get_rule_kwargs(self):
        data = {"value": "eval:test_rule()"}
        expected = {"eval_rule": "test_rule()"}
        kwargs = pad.rules.eval_.EvalRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_target(self):
        data = {"value": "eval:test_rule()",
                "target": "header"}
        expected = {"eval_rule": "test_rule()", "target": "header"}
        kwargs = pad.rules.eval_.EvalRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_no_eval_modifier(self):
        data = {"value": "test_rule()"}
        expected = {"eval_rule": "test_rule()"}
        kwargs = pad.rules.eval_.EvalRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestEvalRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
