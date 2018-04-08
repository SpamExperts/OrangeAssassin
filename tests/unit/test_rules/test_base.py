"""Tests for pad.rules.base"""

import unittest

try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock


import oa.errors
import oa.rules.base


class TestBaseRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_msg = Mock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_init_base(self):
        rule = oa.rules.base.BaseRule("TEST", [0.75], "Some Rule", 0, ["nice"])
        self.assertEqual(rule.name, "TEST")
        self.assertEqual(rule._scores, [0.75])
        self.assertEqual(rule.description, "Some Rule")
        self.assertEqual(rule.tflags, ["nice"])

    def test_init_base_no_score(self):
        rule = oa.rules.base.BaseRule("TEST", None, "Some Rule")
        self.assertEqual(rule.name, "TEST")
        self.assertEqual(rule._scores, [1.0])
        self.assertEqual(rule.description, "Some Rule")

    def test_init_base_no_desc(self):
        rule = oa.rules.base.BaseRule("TEST", [0.75], None)
        self.assertEqual(rule.name, "TEST")
        self.assertEqual(rule._scores, [0.75])
        self.assertEqual(rule.description, "No description available.")

    def test_init_base_tflags_nice(self):
        rule = oa.rules.base.BaseRule("TEST", None, "Some Rule", 0, ["nice"])
        self.assertEqual(rule.name, "TEST")
        self.assertEqual(rule._scores, [-1.0])
        self.assertEqual(rule.description, "Some Rule")
        self.assertEqual(rule.tflags, ["nice"])
        self.assertEqual(rule.priority, 0)

    def test_init_base_invalid_score(self):
        self.assertRaises(oa.errors.InvalidRule, oa.rules.base.BaseRule,
                          "TEST", [0.75, 1.0])

    def test_init_base_value_error(self):
        rule = oa.rules.base.BaseRule("TEST", None, "Some Rule", "a")
        self.assertEqual(rule.priority, 0)

    def test_match(self):
        rule = oa.rules.base.BaseRule("TEST")
        self.assertRaises(NotImplementedError, rule.match, self.mock_msg)

    def test_should_check(self):
        rule = oa.rules.base.BaseRule("TEST")
        self.assertEqual(rule.should_check(), True)

    def test_should_check_dunderscore(self):
        rule = oa.rules.base.BaseRule("__TEST")
        self.assertEqual(rule.should_check(), False)

    def test_should_check_zero_score(self):
        rule = oa.rules.base.BaseRule("TEST", [0])
        self.assertEqual(rule.should_check(), False)

    def test_preprocess(self):
        rule = oa.rules.base.BaseRule("TEST")
        self.assertIsNone(rule.preprocess(None))
        self.assertEqual(rule.score, 1.0)

    def test_preprocess_advanced(self):
        mock_ruleset = Mock(conf={"use_bayes":True, "use_network":False})
        rule = oa.rules.base.BaseRule("TEST", [1.0, 2.0, 3.0, 4.0])
        rule.preprocess(mock_ruleset)
        self.assertEqual(rule.score, 3.0)

    def test_preprocess_tflags_net(self):
        mock_ruleset = Mock(conf={"use_network": False})
        rule = oa.rules.base.BaseRule("TEST", None, "Some Rule", 0, ["net"])
        rule.preprocess(mock_ruleset)
        self.assertEqual(rule.score, 0.0)

    def test_preprocess_tflags_noautolearn(self):
        mock_ruleset = Mock(conf={"use_network": False, "autolearn": True})
        rule = oa.rules.base.BaseRule("TEST", None, "Some Rule", 0,
                                      ["noautolearn"])
        rule.preprocess(mock_ruleset)
        self.assertEqual(rule.score, 0.0)

    def test_preprocess_tflags_learn(self):
        mock_ruleset = Mock(conf={"use_network": True, "autolearn": False,
                                  "training": False, "use_bayes": False})
        rule = oa.rules.base.BaseRule("TEST", None, "Some Rule", 0, ["learn"])
        rule.preprocess(mock_ruleset)
        self.assertEqual(rule.score, 0.0)

    def test_preprocess_tflags_userconf(self):
        mock_ruleset = Mock(conf={"use_network": False, "autolearn": False,
                                  "training": False, "user_config": False,
                                  "use_bayes": True})
        rule = oa.rules.base.BaseRule("TEST", None, "Some Rule", 0,
                                      ["userconf"])
        rule.preprocess(mock_ruleset)
        self.assertEqual(rule.score, 0.0)

    def test_postprocess(self):
        rule = oa.rules.base.BaseRule("TEST")
        self.assertIsNone(rule.postprocess(None))

    def test_get_rule_kwargs(self):
        data = {"score": "0.1 0.2 0.3",
                "describe": "Test",
                "tflags": ["nice"]}
        expected = {"score": [0.1, 0.2, 0.3],
                    "desc": "Test",
                    "tflags": ["nice"]}
        kwargs = oa.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_no_score(self):
        data = {"describe": "Test"}
        expected = {"desc": "Test"}
        kwargs = oa.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_no_desciptions(self):
        data = {"score": "0.1 0.2 0.3"}
        expected = {"score": [0.1, 0.2, 0.3]}
        kwargs = oa.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_no_tflags(self):
        data = {"score": "0.1 0.2 0.3"}
        expected = {"score": [0.1, 0.2, 0.3]}
        kwargs = oa.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_no_data(self):
        data = {}
        expected = {}
        kwargs = oa.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule(self):
        mock_get_kwargs = patch("oa.rules.base.BaseRule.get_rule_kwargs",
                                return_value={}).start()
        rule = oa.rules.base.BaseRule.get_rule("test", {})
        mock_get_kwargs.assert_called_with({})
        self.assertEqual(rule.name, "test")

    def test_str(self):
        expected = "* 0 TEST DESC"
        rule = oa.rules.base.BaseRule("TEST", [0], "DESC")
        self.assertEqual(str(rule), expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestBaseRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
