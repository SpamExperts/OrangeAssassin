"""Tests for sa.rules.parser"""

import unittest

try:
    from unittest.mock import patch, Mock, mock_open, MagicMock
except ImportError:
    from mock import patch, Mock, mock_open, MagicMock

import sa.errors
import sa.rules.parser


class TestParseSARules(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_results = {}
        self.mock_rules = {}

        def mock_parse_file(rulef, results):
            for name, data in self.mock_results.items():
                results[name] = data

        self.mock_ruleset = patch("sa.rules.parser."
                                  "sa.rules.ruleset.RuleSet").start()
        self.mock_parse = patch("sa.rules.parser.parse_sa_file",
                                side_effect=mock_parse_file).start()
        self.mock_open = patch("sa.rules.parser.open", mock_open(),
                               create=True).start()
        patch("sa.rules.parser.RULES", self.mock_rules).start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_parse(self):
        files = ["testf_1"]
        sa.rules.parser.parse_sa_rules(files)
        rulef, results = self.mock_parse.call_args[0]
        self.assertEqual(results, self.mock_results)
        self.assertEqual(rulef, self.mock_open("testf_1"))

    def test_parse_get_ruleset(self):
        ruleset = sa.rules.parser.parse_sa_rules([])
        self.assertEqual(ruleset, self.mock_ruleset())

    def test_parse_get_rules(self):
        mock_body_rule = Mock()
        data = {"type": "body", "score": "1.0"}
        self.mock_results["TEST_RULE"] = data
        self.mock_rules["body"] = mock_body_rule

        ruleset = sa.rules.parser.parse_sa_rules(["testf_1"])

        mock_body_rule.get_rule.assert_called_with("TEST_RULE", data)
        ruleset.add_rule.assert_called_with(
            mock_body_rule.get_rule("TEST_RULE", data))


class TestParseSAFile(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def check_parse(self, rules, expected):
        results = {}
        sa.rules.parser.parse_sa_file(rules, results)
        self.assertEqual(results, expected)

    def test_parse_file(self):
        self.check_parse(["body TEST_RULE /test/"],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_file_rule_options(self):
        self.check_parse(["body TEST_RULE /test/",
                          "score TEST_RULE 1.0"],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/",
                                        "score": "1.0"}})

    def test_parse_file_skip_comment(self):
        self.check_parse(["body TEST_RULE /test/",
                          " # body TEST_RULE2 /test/", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_file_skip_empty(self):
        self.check_parse(["body TEST_RULE /test/",
                          "  ", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_file_skip_unknown(self):
        self.check_parse(["body TEST_RULE /test/",
                          "unknownbody TEST_RULE /test/", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_file_skip_single_word(self):
        self.check_parse(["body TEST_RULE /test/",
                          "rule", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_file_invalid_syntax(self):
        mockf = Mock(**{"__iter__": Mock(return_value=iter(["body TEST_RULE"])),
                        "name": "testf_2"})
        self.assertRaises(sa.errors.InvalidSyntax, self.check_parse,
                          mockf, {})

    def test_parse_file_include(self):
        rules = ["body TEST_RULE /test/",
                 "include testf_2", ]
        expected = {"TEST_RULE": {"type": "body",
                                  "value": "/test/"},
                    "TEST_RULE2": {"type": "body",
                                   "value": "/test2/"}}
        open_name = "sa.rules.parser.open"
        with patch(open_name, create=True) as open_mock:
            open_mock.return_value = MagicMock()
            handle = open_mock.return_value.__enter__.return_value
            handle.__iter__.return_value = ("body TEST_RULE2 /test2/",)

            self.check_parse(rules, expected)

    def test_parse_file_include_max_recursion(self):
        rules = Mock(**{"__iter__": Mock(return_value=iter(["include testf_1"])),
                        "name": "testf_1"})
        expected = {}

        open_name = "sa.rules.parser.open"
        with patch(open_name, create=True) as open_mock:
            open_mock.return_value = MagicMock()
            handle = open_mock.return_value.__enter__.return_value
            handle.__iter__.return_value = ("include testf2",)
            handle.__iter__.name = "testf_1"

            self.assertRaises(sa.errors.MaxRecursionDepthExceeded,
                              self.check_parse, rules, expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestParseSARules, "test"))
    test_suite.addTest(unittest.makeSuite(TestParseSAFile, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
