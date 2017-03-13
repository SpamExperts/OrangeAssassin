"""Tests for pad.rules.parser"""

import logging
import unittest
from collections import OrderedDict
from builtins import UnicodeDecodeError

try:
    from unittest.mock import patch, Mock, mock_open, MagicMock
except ImportError:
    from mock import patch, Mock, mock_open, MagicMock

import pad.errors
import pad.rules.parser


class TestParseGetRuleset(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        logging.getLogger("pad-logger").handlers = [logging.NullHandler()]
        self.mock_results = {}
        self.mock_rules = {}
        self.mock_ruleset = patch("pad.rules.parser."
                                  "pad.rules.ruleset.RuleSet").start()
        patch("pad.rules.parser.RULES", self.mock_rules).start()
        self.parser = pad.rules.parser.PADParser()
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
        self.parser.ctxt.paranoid = True

        self.assertRaises(pad.errors.InvalidRule, self.parser.get_ruleset)

    def test_parse_get_rules_invalid_rule(self):
        mock_body_rule = Mock(**{"get_rule.side_effect":
                                     pad.errors.InvalidRule("TEST_RULE")})
        data = {"type": "body", "score": "1.0"}
        self.mock_results["TEST_RULE"] = data
        self.mock_rules["body"] = mock_body_rule

        ruleset = self.parser.get_ruleset()

        mock_body_rule.get_rule.assert_called_with("TEST_RULE", data)
        self.assertFalse(ruleset.add_rule.called)

    def test_parse_get_rules_invalid_rule_paranoid(self):
        mock_body_rule = Mock(**{"get_rule.side_effect":
                                     pad.errors.InvalidRule("TEST_RULE")})
        data = {"type": "body", "score": "1.0"}
        self.mock_results["TEST_RULE"] = data
        self.mock_rules["body"] = mock_body_rule
        self.parser.ctxt.paranoid = True

        self.assertRaises(pad.errors.InvalidRule,
                          self.parser.get_ruleset)

    def test_parse_get_rules_cmd_plugin(self):
        mock_body_rule = Mock()
        data = {"type": "new_body", "score": "1.0"}
        self.mock_results["TEST_RULE"] = data
        # This is not handle by the default rules, but rather
        # by a plugin that has been previously loaded.
        self.parser.ctxt.cmds["new_body"] = mock_body_rule

        ruleset = self.parser.get_ruleset()

        mock_body_rule.get_rule.assert_called_with("TEST_RULE", data)
        ruleset.add_rule.assert_called_with(
            mock_body_rule.get_rule("TEST_RULE", data))


class TestParsePADLine(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        logging.getLogger("pad-logger").handlers = [logging.NullHandler()]
        self.plugins = {}
        self.mock_ruleset = patch("pad.rules.parser."
                                  "pad.rules.ruleset.RuleSet").start()
        self.mock_ctxt = patch(
            "pad.rules.parser.pad.context.GlobalContext",
            **{"return_value.plugins": self.plugins,
               "return_value.hook_parse_config.return_value": False}).start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def check_parse(self, rules, expected):
        parser = pad.rules.parser.PADParser()
        for line_no, line in enumerate(rules):
            parser._handle_line("filename", line, line_no)
        self.assertEqual(parser.results, expected)
        return parser

    def test_parse_line(self):
        self.check_parse([b"body TEST_RULE /test/"],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_line_rule_options(self):
        self.check_parse([b"body TEST_RULE /test/",
                          b"score TEST_RULE 1.0"],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/",
                                        "score": "1.0"}})

    def test_parse_line_skip_comment(self):
        self.check_parse([b"body TEST_RULE /test/",
                          b" # body TEST_RULE2 /test/", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_line_skip_comment_inline(self):
        self.check_parse([b"body TEST_RULE /test/ # inline comment"],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_line_skip_empty(self):
        self.check_parse([b"body TEST_RULE /test/",
                          b"  ", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_line_skip_unknown(self):
        self.check_parse([b"body TEST_RULE /test/",
                          b"unknownbody TEST_RULE /test/", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_line_skip_single_word(self):
        self.check_parse([b"body TEST_RULE /test/",
                          b"rule", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_line_plugin_parse_config(self):
        parser = self.check_parse([b"unknownbody test_config", ], {})
        parser.ctxt.hook_parse_config.assert_called_with("unknownbody",
                                                         "test_config")

    def test_parse_line_invalid_syntax(self):
        self.assertRaises(pad.errors.InvalidSyntax, self.check_parse,
                          [b"body TEST_RULE"], {})

    def test_parse_line_decoding_error(self):
        error = UnicodeDecodeError("iso-8859-1", b'test', 0, 1, 'test error')
        mock_line = Mock(**{"decode.side_effect": error})
        self.assertRaises(pad.errors.InvalidSyntax, self.check_parse,
                          [mock_line], {})

    def test_parse_line_ifplugin_loaded(self):
        self.plugins["PyzorPlugin"] = Mock()
        parser = self.check_parse([b"ifplugin PyzorPlugin", ], {})
        self.assertEqual(parser._ignore, False)

    def test_parse_line_ifplugin_not_loaded(self):
        parser = self.check_parse([b"ifplugin PyzorPlugin", ], {})
        self.assertEqual(parser._ignore, True)

    def test_parse_line_skip_not_loaded(self):
        self.check_parse([b"ifplugin PyzorPlugin",
                          b"body TEST_RULE /test/", ], {})

    def test_parse_line_parse_loaded(self):
        self.plugins["PyzorPlugin"] = Mock()
        self.check_parse([b"ifplugin PyzorPlugin",
                          b"body TEST_RULE /test/", ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_line_endif(self):
        parser = self.check_parse([b"ifplugin PyzorPlugin", b"endif"], {})
        self.assertEqual(parser._ignore, False)

    def test_parse_line_ifelse_loaded(self):
        self.plugins["PyzorPlugin"] = Mock()
        self.check_parse([b"ifplugin PyzorPlugin",
                          b"body TEST_RULE /test/",
                          b"else",
                          b"body TEST_RULE2 /test2/",
                          b"endif"
                          ],
                         {"TEST_RULE": {"type": "body",
                                        "value": "/test/"}})

    def test_parse_line_ifelse_not_loaded(self):
        self.check_parse([b"ifplugin PyzorPlugin",
                          b"body TEST_RULE /test/",
                          b"else",
                          b"body TEST_RULE2 /test2/",
                          b"endif"
                          ],
                         {"TEST_RULE2": {"type": "body",
                                         "value": "/test2/"}})

    def test_parse_line_convert_evalrule(self):
        self.check_parse([b"body TEST_RULE eval:check_test()"],
                         {"TEST_RULE": {"type": "eval",
                                        "value": "eval:check_test()",
                                        "target": "body"}})

    def test_parse_line_convert_evalrule_pyversion(self):
        self.check_parse([b"eval TEST_RULE check_test()"],
                         {"TEST_RULE": {"type": "eval",
                                        "value": "check_test()",
                                        }})

    def test_parse_line_load_plugin(self):
        self.check_parse(
            [b"loadplugin DumpText /etc/pad/plugins/dump_text.py"],
            {})
        self.mock_ctxt.return_value.load_plugin.assert_called_with(
            "DumpText", "/etc/pad/plugins/dump_text.py")

    def test_parse_line_load_plugin_reimplemented(self):
        self.check_parse([b"loadplugin Mail::SpamAssassin::Plugin::DumpText"],
                         {})
        self.mock_ctxt.return_value.load_plugin.assert_called_with(
            "pad.plugins.dump_text.DumpText", None)

    def test_parse_line_load_plugin_no_path(self):
        self.check_parse([b"loadplugin pad.plugins.dump_text.DumpText"], {})
        self.mock_ctxt.return_value.load_plugin.assert_called_with(
            "pad.plugins.dump_text.DumpText", None)

    def test_parse_line_include(self):
        patch("pad.rules.parser.os.path.isfile", return_value=True).start()
        rules = [b"body TEST_RULE /test/",
                 b"include testf_2", ]
        expected = {"TEST_RULE": {"type": "body",
                                  "value": "/test/"},
                    "TEST_RULE2": {"type": "body",
                                   "value": "/test2/"}}
        open_name = "pad.rules.parser.open"
        with patch(open_name, create=True) as open_mock:
            open_mock.return_value = MagicMock()
            handle = open_mock.return_value.__enter__.return_value
            handle.__iter__.return_value = (b"body TEST_RULE2 /test2/",)

            self.check_parse(rules, expected)

    def test_parse_line_include_max_recursion(self):
        patch("pad.rules.parser.os.path.isfile", return_value=True).start()
        rules = Mock(
            **{"__iter__": Mock(return_value=iter([b"include testf_1"])),
               "name": "testf_1"})
        expected = {}

        open_name = "pad.rules.parser.open"
        with patch(open_name, create=True) as open_mock:
            open_mock.return_value = MagicMock()
            handle = open_mock.return_value.__enter__.return_value
            handle.__iter__.return_value = (b"include testf2",)
            handle.__iter__.name = "testf_1"

            self.assertRaises(pad.errors.MaxRecursionDepthExceeded,
                              self.check_parse, rules, expected)

    def test_parse_line_priority_order(self):
        rules = [b"body TEST_RULE1 /test/",
                 b"body TEST_RULE2 /test/",
                 b"body TEST_RULE3 /test/",
                 b"priority TEST_RULE3 1"]
        expected = {"TEST_RULE3": {"type": "body", "value": "/test/",
                                   "priority": "1"},
                    "TEST_RULE1": {"type": "body", "value": "/test/"},
                    "TEST_RULE2": {"type": "body", "value": "/test/"}
                    }
        self.check_parse(rules, expected)

    def test_parse_line_tflags(self):
        rules = [b"body TEST_RULE /test/",
                 b"tflags TEST_RULE net learn"]
        expected = {"TEST_RULE": {"type": "body", "value": "/test/",
                                  "tflags": ["net", "learn"]}}
        self.check_parse(rules, expected)

    def test_parse_line_lang_describe(self):
        rules = [b"lang en describe TEST_RULE1 /test/",
                 b"lang en describe TEST_RULE2 /test/",
                 b"lang en describe TEST_RULE3 /test/"]
        expected = {"TEST_RULE1": {"describe": "/test/"},
                    "TEST_RULE2": {"describe": "/test/"},
                    "TEST_RULE3": {"describe": "/test/"}
                    }
        self.check_parse(rules, expected)

    def test_parse_line_lang_describe_wrong_language(self):
        rules = [b"describe TEST_RULE1 /test/",
                 b"lang es describe TEST_RULE1 /test/es"]
        expected = {"TEST_RULE1": {"describe": "/test/"}}
        self.check_parse(rules, expected)

    def test_parse_line_lang_describe_as_locales(self):
        rules = [b"describe TEST_RULE1 /test/",
                 b"lang en describe TEST_RULE1 /test/es"]
        expected = {"TEST_RULE1": {"describe": "/test/es"}}
        self.check_parse(rules, expected)

    def test_parse_line_lang_report_as_locales(self):
        rules = [b"lang en report /test/report", ]
        parser = self.check_parse(rules, {})
        parser.ctxt.hook_parse_config.assert_called_with("report",
                                                         "/test/report")

    def test_parse_line_lang_report_wrong_language(self):
        rules = [b"lang en report /test/report",
                 b"lang es report /test/report/es", ]
        parser = self.check_parse(rules, {})
        parser.ctxt.hook_parse_config.assert_called_with("report",
                                                         "/test/report")

    def test_parse_line_priority(self):
        rules = [b"body TEST_RULE /test/",
                 b"priority TEST_RULE 10"]
        expected = {"TEST_RULE": {"type": "body", "value": "/test/",
                                  "priority": "10"}}
        self.check_parse(rules, expected)

    def test_parse_line_multiple_priority_order(self):
        rules = [b"body TEST_RULE1 /test/",
                 b"body TEST_RULE2 /test/",
                 b"body TEST_RULE3 /test/",
                 b"body TEST_RULE4 /test/",
                 b"priority TEST_RULE3 1",
                 b"priority TEST_RULE2 4"]
        expected = {"TEST_RULE2": {"type": "body", "value": "/test/",
                                   "priority": "4"},
                    "TEST_RULE3": {"type": "body", "value": "/test/",
                                   "priority": "1"},
                    "TEST_RULE1": {"type": "body", "value": "/test/"},
                    "TEST_RULE4": {"type": "body", "value": "/test/"}
                    }
        self.check_parse(rules, expected)

    def test_parse_line_negative_priority_order(self):
        rules = [b"body TEST_RULE1 /test/",
                 b"body TEST_RULE2 /test/",
                 b"body TEST_RULE3 /test/",
                 b"body TEST_RULE4 /test/",
                 b"priority TEST_RULE1 -2"]
        expected = {"TEST_RULE2": {"type": "body", "value": "/test/"},
                    "TEST_RULE3": {"type": "body", "value": "/test/"},
                    "TEST_RULE4": {"type": "body", "value": "/test/"},
                    "TEST_RULE1": {"type": "body", "value": "/test/",
                                   "priority": "-2"}
                    }
        self.check_parse(rules, expected)

    def test_parse_line_negative_and_positive_priority_order(self):
        rules = [b"body TEST_RULE1 /test/",
                 b"body TEST_RULE2 /test/",
                 b"body TEST_RULE3 /test/",
                 b"body TEST_RULE4 /test/",
                 b"priority TEST_RULE2 -1",
                 b"priority TEST_RULE3 -4",
                 b"priority TEST_RULE4 1"]
        expected = {"TEST_RULE4": {"type": "body", "value": "/test/",
                                   "priority": "1"},
                    "TEST_RULE1": {"type": "body", "value": "/test/"},
                    "TEST_RULE2": {"type": "body", "value": "/test/",
                                   "priority": "-1"},
                    "TEST_RULE3": {"type": "body", "value": "/test/",
                                   "priority": "-4"}
                    }
        self.check_parse(rules, expected)

    def test_parse_line_same_priority(self):
        rules = [b"body TEST_RULE1 /test/",
                 b"body TEST_RULE2 /test/",
                 b"body TEST_RULE3 /test/",
                 b"body TEST_RULE4 /test/",
                 b"priority TEST_RULE2 1",
                 b"priority TEST_RULE3 1"]
        expected = {"TEST_RULE2": {"type": "body", "value": "/test/",
                                   "priority": "1"},
                    "TEST_RULE3": {"type": "body", "value": "/test/",
                                   "priority": "1"},
                    "TEST_RULE1": {"type": "body", "value": "/test/"},
                    "TEST_RULE4": {"type": "body", "value": "/test/"}
                    }
        self.check_parse(rules, expected)

    def test_parse_line_same_with_multiple_priority(self):
        rules = [b"body TEST_RULE1 /test/",
                 b"body TEST_RULE2 /test/",
                 b"body TEST_RULE3 /test/",
                 b"body TEST_RULE4 /test/",
                 b"priority TEST_RULE2 1",
                 b"priority TEST_RULE3 1",
                 b"priority TEST_RULE4 2"]
        expected = {"TEST_RULE4": {"type": "body", "value": "/test/",
                                   "priority": "2"},
                    "TEST_RULE2": {"type": "body", "value": "/test/",
                                   "priority": "1"},
                    "TEST_RULE3": {"type": "body", "value": "/test/",
                                   "priority": "1"},
                    "TEST_RULE1": {"type": "body", "value": "/test/"}
                    }
        self.check_parse(rules, expected)


class TestParsePADRules(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        logging.getLogger("pad-logger").handlers = [logging.NullHandler()]
        self.mock_parser = patch("pad.rules.parser.PADParser").start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_paranoid(self):
        pad.rules.parser.parse_pad_rules([])
        self.mock_parser.assert_called_once_with(paranoid=False,
                                                 ignore_unknown=True)

    def test_paranoid_true(self):
        pad.rules.parser.parse_pad_rules([], paranoid=True)
        self.mock_parser.assert_called_once_with(paranoid=True,
                                                 ignore_unknown=True)

    def test_parse_files(self):
        pad.rules.parser.parse_pad_rules(["testf1.cf"])
        self.mock_parser.return_value.parse_file.assert_called_with(
            "testf1.cf")


class TestParsePADRules(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        logging.getLogger("pad-logger").handlers = [logging.NullHandler()]
        self.mock_parser = patch("pad.rules.parser.PADParser").start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_paranoid(self):
        pad.rules.parser.parse_pad_rules([])
        self.mock_parser.assert_called_once_with(paranoid=False,
                                                 ignore_unknown=True)

    def test_paranoid_true(self):
        pad.rules.parser.parse_pad_rules([], paranoid=True)
        self.mock_parser.assert_called_once_with(paranoid=True,
                                                 ignore_unknown=True)

    def test_parse_files(self):
        pad.rules.parser.parse_pad_rules(["testf1.cf"])
        self.mock_parser.return_value.parse_file.assert_called_with(
            "testf1.cf")


class TestParseYMLConfig(unittest.TestCase):
    """Test _handle_yaml_element method"""

    def setUp(self):
        logging.getLogger("pad-logger").handlers = [logging.NullHandler()]
        patch("pad.rules.parser.PADParser._handle_include").start()
        patch("pad.rules.parser.PADParser._handle_ifplugin").start()
        patch("pad.rules.parser.PADParser._handle_loadplugin").start()
        self.plugins = {}
        self.cmds = ["uri_detail"]
        self.mock_ctxt = patch(
            "pad.rules.parser.pad.context.GlobalContext",
            **{"return_value.plugins": self.plugins,
               "return_value.hook_parse_config.return_value": False,
               "return_value.cmds": self.cmds}).start()
        self.parser = pad.rules.parser.PADParser()
        patch("pad.rules.parser.locale.getlocale", return_value=["fr"]).start()

    def tearDown(self):
        patch.stopall()

    def test_handle_yaml_element_not_dict(self):
        """Test yaml element not dict"""
        yaml_dict = "string"
        res = self.parser._handle_yaml_element(yaml_dict, 0)
        self.res = None

    def test_handle_yaml_element_include(self):
        """Test include statement"""
        self.parser._handle_yaml_element({"include": "file"}, 0)
        self.parser._handle_include.assert_called_with("file", None, None, 0)

    def test_handle_yaml_element_loadplugin(self):
        """Test loadplugin statement"""
        self.parser._handle_yaml_element({"loadplugin": "plugin"}, 0)
        self.parser._handle_loadplugin.assert_called_with("plugin")

    def test_handle_yaml_element_report_lang(self):
        self.parser._handle_yaml_element({"lang": {"fr": "description"}}, 0)
        self.parser.ctxt.hook_parse_config.assert_called_with("report",
                                                              "description")

    def test_handle_yaml_element_rule_score_override(self):
        """Test if second score overrides the first one"""
        self.parser._handle_yaml_element({"RULE": {"score": "10"}}, 0)
        self.parser._handle_yaml_element({"RULE": {"score": "20"}}, 0)

        expected_results = OrderedDict([
            ("RULE", {"score": "20"})
        ])

        self.assertEqual(self.parser.results, expected_results)

    def test_handle_yaml_element_rule_description_override(self):
        """Test if second description overrides the first one"""

        self.parser._handle_yaml_element({"RULE": {"describe": "desc1"}}, 0)
        self.parser._handle_yaml_element({"RULE": {"describe": "desc2"}}, 0)

        expected_results = OrderedDict([
            ("RULE", {"describe": "desc2"})
        ])

        self.assertEqual(self.parser.results, expected_results)

    def test_handle_yaml_element_rule_type_override(self):
        """Test if second type overrides te first one"""
        self.parser._handle_yaml_element({"RULE": {"type": "body"}}, 0)
        self.parser._handle_yaml_element({"RULE": {"type": "header"}}, 0)

        expected_results = OrderedDict([
            ("RULE", {"type": "header"})
        ])

        self.assertEqual(self.parser.results, expected_results)

    def test_handle_yaml_element_rule_priority_override(self):
        """Test if second priority overrides the first one"""
        self.parser._handle_yaml_element({"RULE": {"priority": "-1"}}, 0)
        self.parser._handle_yaml_element({"RULE": {"priority": "1"}}, 0)

        expected_results = OrderedDict([
            ("RULE", {"priority": "1"})
        ])

        self.assertEqual(self.parser.results, expected_results)

    def test_handle_yaml_element_rule_value_override(self):
        """Test if second value overrides the first one"""
        self.parser._handle_yaml_element({"RULE": {"value": "value1"}}, 0)
        self.parser._handle_yaml_element({"RULE": {"value": "value2"}}, 0)

        expected_results = OrderedDict([
            ("RULE", {"value": "value2"})
        ])

        self.assertEqual(self.parser.results, expected_results)

    def test_handle_yaml_element_rule_tflags_override(self):
        """Test if second tflag overrides the first one"""
        self.parser._handle_yaml_element({"RULE": {"tflags": ["net", "nice"]}},
                                         0)
        self.parser._handle_yaml_element(
            {"RULE": {"tflags": ["autolearn", "nice"]}}, 0)

        expected_results = OrderedDict([
            ("RULE", {"tflags": ["autolearn", "nice"]})
        ])

        self.assertEqual(self.parser.results, expected_results)

    def test_handle_yaml_element_rule_lang_override(self):
        """Test if second lang element overrides the first one and they both
        override rule description"""
        """Test if second value overrides the first one"""
        self.parser._handle_yaml_element({"RULE": {"lang": {
            "fr": "fr first description",
            "en": "en first description"
        }}}, 0)
        self.parser._handle_yaml_element({"RULE": {"lang": {
            "fr": "fr second description",
            "en": "en second description"
        }}}, 0)

        expected_results = OrderedDict([
            ("RULE", {"describe": "fr second description"})
        ])

        self.assertEqual(self.parser.results, expected_results)

    def test_handle_yaml_element_eval_rule(self):
        """Test if eval rule is properly saved"""
        patch("pad.rules.parser.locale.getlocale", return_value=["fr"]).start()

        yaml_dict = {
            "RULE": {
                "score": "23",
                "priority": "24",
                "value": "eval::test()",
                "type": "body",
                "lang": {
                    "fr": "description"
                },
            }
        }
        self.parser._handle_yaml_element(yaml_dict, 0)

        expected_result = OrderedDict(
            [('RULE',
              {'describe': 'description',
               'priority': '24',
               'score': '23',
               'target': 'body',
               'type': 'eval',
               'value': 'eval::test()'})
             ])

        self.assertEqual(self.parser.results, expected_result)

    def test_handle_yaml_element_eval_rule_splitted_type_before_eval(self):
        """Test if an eval rule splitted in multiple parts in properly
        loaded, rule type comes before eval"""
        self.parser._handle_yaml_element({"RULE": {
            "type": "body",
        }}, 0)

        self.parser._handle_yaml_element({"RULE": {
            "value": "eval:test()"
        }}, 0)

        expected_result = OrderedDict([('RULE', {'target': 'body',
                                                 'type': 'eval',
                                                 'value': 'eval:test()'})])

        self.assertEqual(self.parser.results, expected_result)

    def test_handle_yaml_element_eval_rule_splitted_type_after_eval(self):
        """Test if an eval rule splitted in multiple parts in properly
        loaded, rule type comes after eval (target and type should not be
        overrided"""
        self.parser._handle_yaml_element({"RULE": {
            "value": "eval::test()"
        }}, 0)

        self.parser._handle_yaml_element({"RULE": {
            "type": "body",
        }}, 0)

        expected_result = OrderedDict([('RULE', {'target': 'body',
                                                 'type': 'eval',
                                                 'value': 'eval::test()'})])

        self.assertEqual(self.parser.results, expected_result)

    def test_handle_yaml_element_rule_uri_detail(self):
        patch("pad.rules.parser.locale.getlocale", return_value=["fr"]).start()

        self.parser._handle_yaml_element(
            {"RULE": {"uri_detail": "uri_detail_value"}}, 0)

        expected_result = OrderedDict(
            [('RULE',
              {'type': 'uri_detail',
               'value': 'uri_detail_value'})
             ])

        self.assertEqual(self.parser.results, expected_result)

    def test_handle_yaml_element_rule_uri_detail_case1(self):
        """Test when uri_detail, type and value come separate: uri, body, value"""
        self.parser._handle_yaml_element(
            {"RULE": {"uri_detail": "uri_detail_value"}}, 0)
        self.parser._handle_yaml_element({"RULE": {"type": "body", }}, 0)
        self.parser._handle_yaml_element({"RULE": {"value": "value", }}, 0)

        expected_result = OrderedDict(
            [('RULE',
              {'type': 'body',
               'value': 'value'})
             ])

        self.assertEqual(self.parser.results, expected_result)

    def test_handle_yaml_element_rule_uri_detail_case2(self):
        """Test when uri_detail, type and value come separate:body, value, uri """
        self.parser._handle_yaml_element({"RULE": {"type": "body", }}, 0)
        self.parser._handle_yaml_element({"RULE": {"value": "value", }}, 0)
        self.parser._handle_yaml_element(
            {"RULE": {"uri_detail": "uri_detail_value"}}, 0)

        expected_result = OrderedDict(
            [('RULE',
              {'type': 'uri_detail',
               'value': 'uri_detail_value'})
             ])

        self.assertEqual(self.parser.results, expected_result)

    def test_handle_yaml_element_rule_uri_detail_case3(self):
        """Test when uri_detail, type and value come separate:body, uri, value"""
        self.parser._handle_yaml_element({"RULE": {"type": "body", }}, 0)
        self.parser._handle_yaml_element(
            {"RULE": {"uri_detail": "uri_detail_value"}}, 0)
        self.parser._handle_yaml_element({"RULE": {"value": "value", }}, 0)

        expected_result = OrderedDict(
            [('RULE',
              {'type': 'uri_detail',
               'value': 'uri_detail_value'})
             ])

        self.assertEqual(self.parser.results, expected_result)

    @unittest.skip("Don't work as expected")
    def test_handle_yaml_element_rule_uri_detail_case3(self):
        """Test when uri_detail, type and value come separate:value, uri, type"""
        self.parser._handle_yaml_element({"RULE": {"value": "value", }}, 0)
        self.parser._handle_yaml_element(
            {"RULE": {"uri_detail": "uri_detail_value"}}, 0)
        self.parser._handle_yaml_element({"RULE": {"type": "body", }}, 0)

        expected_result = OrderedDict(
            [('RULE',
              {'type': 'uri_detail',
               'value': 'uri_detail_value'})
             ])

        self.assertEqual(self.parser.results, expected_result)

    def test_handle_yaml_element_rule_uri_detail_before_type(self):
        """Test if uri detail overrides rule type and value when
        uri_detail comes before type and value"""

        self.parser._handle_yaml_element(
            {"RULE": {"uri_detail": "uri_detail_value"}}, 0)
        self.parser._handle_yaml_element({"RULE":
            {
                "type": "body",
                "value": "value"
            }}, 0)
        expected_result = OrderedDict(
            [('RULE',
              {'type': 'body',
               'value': 'value'})
             ])

        self.assertEqual(self.parser.results, expected_result)

    def test_handle_yaml_element_rule_uri_detail_after_type(self):
        """Test if uri detail overrides rule type and value when
        uri_detail comes after type and value"""
        self.parser._handle_yaml_element({"RULE":
            {
                "type": "body",
                "value": "value"
            }}, 0)

        self.parser._handle_yaml_element({"RULE":
            {
                "uri_detail": "uri_detail_value"}},
            0)

        expected_result = OrderedDict(
            [('RULE',
              {'type': 'uri_detail',
               'value': 'uri_detail_value'})
             ])

        self.assertEqual(self.parser.results, expected_result)

    def test_handle_yaml_element_unknown_rule(self):
        yaml_dict = {
            "key": "value"
        }

        self.parser._handle_yaml_element(yaml_dict, 0)
        self.parser.ctxt.hook_parse_config.assert_called_with("key", "value")


class TestParseFileYML(unittest.TestCase):
    """Test parse_file method for YML case"""

    def setUp(self):
        logging.getLogger("pad-logger").handlers = [logging.NullHandler()]
        patch("pad.rules.parser.PADParser._handle_yaml_element").start()
        self.load_dict = {"key": "value"}
        patch("pad.rules.parser.yaml.safe_load",
              return_value=self.load_dict).start()
        self.mock_ctxt = patch(
            "pad.rules.parser.pad.context.GlobalContext",
            **{"return_value.plugins": {},
               "return_value.hook_parse_config.return_value": False,
               "return_value.cmds": []}).start()
        self.parser = pad.rules.parser.PADParser()
        patch("os.path.isfile", return_value=True).start()

    def tearDown(self):
        patch.stopall()

    @unittest.skip("Skip until fix")
    def test_parse_yml_file(self):

        content = ("key1:\n"
                   " key12: value1\n"
                   "key2:\n"
                   " key22: value2\n"
                   "key: value\n"
                   "#skipped line")

        patch("pad.rules.parser.open", mock_open(read_data=content)).start()
        self.parser.parse_file("test.yml", _depth=0)




def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestParseGetRuleset, "test"))
    test_suite.addTest(unittest.makeSuite(TestParsePADLine, "test"))
    test_suite.addTest(unittest.makeSuite(TestParsePADRules, "test"))
    test_suite.addTest(unittest.makeSuite(TestParseYMLConfig, "test"))
    test_suite.addTest(unittest.makeSuite(TestParseFileYML, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
