"""Tests for sa.rules.parser"""

import unittest

try:
    from unittest.mock import patch, Mock, mock_open, MagicMock
except ImportError:
    from mock import patch, Mock, mock_open, MagicMock

import sa.errors
import sa.rules.parser


class TestParseGetRuleset(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_results = {}
        self.mock_rules = {}

        self.mock_ruleset = patch("sa.rules.parser."
                                  "sa.rules.ruleset.RuleSet").start()
        patch("sa.rules.parser.RULES", self.mock_rules).start()
        self.parser = sa.rules.parser.SAParser()
        self.parser.results = self.mock_results

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_parse_get_rules(self):
        mock_body_rule = Mock()
        data = {"type": "body", "score": "1.0"}
        self.mock_results["TEST_RULE"] = data
        self.mock_rules["body"] = mock_body_rule

        ruleset = self.parser.get_ruleset()

        mock_body_rule.get_rule.assert_called_with("TEST_RULE", data)
        ruleset.add_rule.assert_called_with(
            mock_body_rule.get_rule("TEST_RULE", data))

    def test_parse_get_rules_no_type_defined(self):
        mock_body_rule = Mock()
        data = {"score": "1.0"}
        self.mock_results["TEST_RULE"] = data
        self.mock_rules["body"] = mock_body_rule

        ruleset = self.parser.get_ruleset()

        self.assertFalse(mock_body_rule.get_rule.called)
        self.assertFalse(ruleset.add_rule.called)

    def test_parse_get_rules_no_type_defined_paranoid(self):
        mock_body_rule = Mock()
        data = {"score": "1.0"}
        self.mock_results["TEST_RULE"] = data
        self.mock_rules["body"] = mock_body_rule
        self.parser.paranoid = True

        self.assertRaises(sa.errors.InvalidRule,
                          ruleset=self.parser.get_ruleset)

    def test_parse_get_rules_invalid_rule(self):
        mock_body_rule = Mock(**{"get_rule.side_effect":
                                 sa.errors.InvalidRule("TEST_RULE")})
        data = {"type": "body", "score": "1.0"}
        self.mock_results["TEST_RULE"] = data
        self.mock_rules["body"] = mock_body_rule

        ruleset = self.parser.get_ruleset()

        mock_body_rule.get_rule.assert_called_with("TEST_RULE", data)
        self.assertFalse(ruleset.add_rule.called)

    def test_parse_get_rules_invalid_rule_paranoid(self):
        mock_body_rule = Mock(**{"get_rule.side_effect":
                                 sa.errors.InvalidRule("TEST_RULE")})
        data = {"type": "body", "score": "1.0"}
        self.mock_results["TEST_RULE"] = data
        self.mock_rules["body"] = mock_body_rule
        self.parser.paranoid = True

        self.assertRaises(sa.errors.InvalidRule,
                          self.parser.get_ruleset)


class TestParseSALine(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def check_parse(self, rules, expected):
        parser = sa.rules.parser.SAParser()
        for line_no, line in enumerate(rules):
            parser._handle_line("filename", line, line_no)
        self.assertEqual(parser.results, expected)

    def test_parse_file(self):
        self.check_parse([b"body TEST_RULE /test/"],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_file_rule_options(self):
        self.check_parse([b"body TEST_RULE /test/",
                          b"score TEST_RULE 1.0"],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/",
                                        "score": "1.0"}})

    def test_parse_file_skip_comment(self):
        self.check_parse([b"body TEST_RULE /test/",
                          b" # body TEST_RULE2 /test/", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_file_skip_comment_inline(self):
        self.check_parse([b"body TEST_RULE /test/ # inline comment"],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_file_skip_empty(self):
        self.check_parse([b"body TEST_RULE /test/",
                          b"  ", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_file_skip_unknown(self):
        self.check_parse([b"body TEST_RULE /test/",
                          b"unknownbody TEST_RULE /test/", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_file_skip_single_word(self):
        self.check_parse([b"body TEST_RULE /test/",
                          b"rule", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_file_invalid_syntax(self):
        self.assertRaises(sa.errors.InvalidSyntax, self.check_parse,
                          [b"body TEST_RULE"], {})

    def test_parse_file_include(self):
        rules = [b"body TEST_RULE /test/",
                 b"include testf_2", ]
        expected = {"TEST_RULE": {"type": "body",
                                  "value": "/test/"},
                    "TEST_RULE2": {"type": "body",
                                   "value": "/test2/"}}
        open_name = "sa.rules.parser.open"
        with patch(open_name, create=True) as open_mock:
            open_mock.return_value = MagicMock()
            handle = open_mock.return_value.__enter__.return_value
            handle.__iter__.return_value = (b"body TEST_RULE2 /test2/",)

            self.check_parse(rules, expected)

    def test_parse_file_include_max_recursion(self):
        rules = Mock(**{"__iter__": Mock(return_value=iter([b"include testf_1"])),
                        "name": "testf_1"})
        expected = {}

        open_name = "sa.rules.parser.open"
        with patch(open_name, create=True) as open_mock:
            open_mock.return_value = MagicMock()
            handle = open_mock.return_value.__enter__.return_value
            handle.__iter__.return_value = (b"include testf2",)
            handle.__iter__.name = "testf_1"

            self.assertRaises(sa.errors.MaxRecursionDepthExceeded,
                              self.check_parse, rules, expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestParseGetRuleset, "test"))
    test_suite.addTest(unittest.makeSuite(TestParseSALine, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
