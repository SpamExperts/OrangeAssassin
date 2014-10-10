import unittest

try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock


import sa.rules.base


class TestBaseRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_msg = Mock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_init_base(self):
        rule = sa.rules.base.BaseRule("TEST", [0.75], "Some Rule")
        self.assertEqual(rule.name, "TEST")
        self.assertEqual(rule.score, [0.75])
        self.assertEqual(rule.description, "Some Rule")

    def test_init_base_no_score(self):
        rule = sa.rules.base.BaseRule("TEST", None, "Some Rule")
        self.assertEqual(rule.name, "TEST")
        self.assertEqual(rule.score, [1.0])
        self.assertEqual(rule.description, "Some Rule")

    def test_init_base_no_desc(self):
        rule = sa.rules.base.BaseRule("TEST", [0.75], None)
        self.assertEqual(rule.name, "TEST")
        self.assertEqual(rule.score, [0.75])
        self.assertEqual(rule.description, "No description available.")

    def test_match(self):
        rule = sa.rules.base.BaseRule("TEST")
        self.assertRaises(NotImplementedError, rule.match, self.mock_msg)

    def test_should_check(self):
        rule = sa.rules.base.BaseRule("TEST")
        self.assertEqual(rule.should_check(), True)

    def test_should_check_dunderscore(self):
        rule = sa.rules.base.BaseRule("__TEST")
        self.assertEqual(rule.should_check(), False)

    def test_should_check_zero_score(self):
        rule = sa.rules.base.BaseRule("TEST", [0])
        self.assertEqual(rule.should_check(), False)

    def test_preprocess(self):
        rule = sa.rules.base.BaseRule("TEST")
        self.assertIsNone(rule.preprocess(None))

    def test_postprocess(self):
        rule = sa.rules.base.BaseRule("TEST")
        self.assertIsNone(rule.postprocess(None))

    def test_get_rule_kwargs(self):
        data = {"score": "0.1 0.2 0.3",
                "describe": "Test"}
        expected = {"score": [0.1, 0.2, 0.3],
                    "desc": "Test"}
        kwargs = sa.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_no_score(self):
        data = {"describe": "Test"}
        expected = {"desc": "Test"}
        kwargs = sa.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_no_desciptions(self):
        data = {"score": "0.1 0.2 0.3"}
        expected = {"score": [0.1, 0.2, 0.3]}
        kwargs = sa.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule_kwargs_no_data(self):
        data = {}
        expected = {}
        kwargs = sa.rules.base.BaseRule.get_rule_kwargs(data)
        self.assertEqual(kwargs, expected)

    def test_get_rule(self):
        mock_get_kwargs = patch("sa.rules.base.BaseRule.get_rule_kwargs",
                                return_value={}).start()
        rule = sa.rules.base.BaseRule.get_rule("test", {})
        mock_get_kwargs.assert_called_with({})
        self.assertEqual(rule.name, "test")

    def test_str(self):
        expected = "* 0 TEST DESC"
        rule = sa.rules.base.BaseRule("TEST", [0], "DESC")
        self.assertEqual(str(rule), expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestBaseRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
