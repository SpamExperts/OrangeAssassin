"""Tests for pad.plugins.replace_tags."""

import unittest

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import oa.plugins.replace_tags


class TestReplaceTags(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.global_data = {
            "replace_start": "<",
            "replace_end": ">",
            "replace_pre": [],
            "replace_inter": [],
            "replace_post": [],
            "replace_tag": [],
            "replace_rules": [],
        }
        self.mock_ctxt = MagicMock()
        self.plugin = oa.plugins.replace_tags.ReplaceTags(self.mock_ctxt)
        self.plugin.set_global = self.global_data.__setitem__
        self.plugin.get_global = self.global_data.__getitem__
        self.mock_ruleset = MagicMock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_prepare_tags(self):
        expected = {
            "<A>": "[abcd]",
            "<B>": "[bcde]",
        }
        self.global_data["replace_tag"] = [
            "A [abcd]", "B [bcde]"
        ]
        self.plugin.prepare_tags("tag")
        self.assertEqual(self.global_data["replace_tag"], expected)

    def test_prepare_invalid(self):
        expected = {
            "<A>": "[abcd]",
        }
        self.global_data["replace_tag"] = [
            "A [abcd]", "B[bcde]"
        ]
        self.plugin.prepare_tags("tag")
        self.assertEqual(self.global_data["replace_tag"], expected)

    def test_prepare_tags_redefine(self):
        expected = {
            "<A>": "[bcde]",
        }
        self.global_data["replace_tag"] = [
            "A [abcd]", "A [bcde]"
        ]
        self.plugin.prepare_tags("tag")
        self.assertEqual(self.global_data["replace_tag"], expected)

    def test_prepare_pre(self):
        expected = {
            "<pre A>": "[abcd]",
            "<pre B>": "[bcde]",
        }
        self.global_data["replace_pre"] = [
            "A [abcd]", "B [bcde]"
        ]
        self.plugin.prepare_tags("pre")
        self.assertEqual(self.global_data["replace_pre"], expected)

    def test_prepare_post(self):
        expected = {
            "<post A>": "[abcd]",
            "<post B>": "[bcde]",
        }
        self.global_data["replace_post"] = [
            "A [abcd]", "B [bcde]"
        ]
        self.plugin.prepare_tags("post")
        self.assertEqual(self.global_data["replace_post"], expected)

    def test_prepare_inter(self):
        expected = {
            "<inter A>": "[abcd]",
            "<inter B>": "[bcde]",
        }
        self.global_data["replace_inter"] = [
            "A [abcd]", "B [bcde]"
        ]
        self.plugin.prepare_tags("inter")
        self.assertEqual(self.global_data["replace_inter"], expected)

    def test_get_metatags_pre(self):
        self.global_data["replace_pre"] = {
            "<pre P1>": "[abc]",
            "<pre P2>": "[def]",
        }
        rule = "/<pre P1>[1-9]/"
        expected = ("[abc]", "/[1-9]/")

        result = self.plugin.get_metatags(rule, "pre")
        self.assertEqual(result, expected)

    def test_get_metatags_post(self):
        self.global_data["replace_post"] = {
            "<post P1>": "[abc]",
            "<post P2>": "[def]",
        }
        rule = "/<post P1>[1-9]/"
        expected = ("[abc]", "/[1-9]/")

        result = self.plugin.get_metatags(rule, "post")
        self.assertEqual(result, expected)

    def test_get_metatags_inter(self):
        self.global_data["replace_inter"] = {
            "<inter P1>": "[abc]",
            "<inter P2>": "[def]",
        }
        rule = "/<inter P1>[1-9]/"
        expected = ("[abc]", "/[1-9]/")

        result = self.plugin.get_metatags(rule, "inter")
        self.assertEqual(result, expected)

    def test_replace_rule_simple(self):
        self.global_data["replace_tag"] = {
            "<TEXT>": "[a-zA-Z]",
            "<NR>": "[0-9]",
        }
        self.global_data["replace_pre"] = {}
        self.global_data["replace_post"] = {}
        self.global_data["replace_inter"] = {}

        rule = "/test<TEXT>+<NR>+/"
        expected = "/test[a-zA-Z]+[0-9]+/"

        result = self.plugin.replace_tags(rule)
        self.assertEqual(result, expected)

    def test_replace_rule_simple_last(self):
        self.global_data["replace_tag"] = {
            "<TEXT>": "[a-zA-Z]",
            "<NR>": "[0-9]",
        }
        self.global_data["replace_pre"] = {}
        self.global_data["replace_post"] = {}
        self.global_data["replace_inter"] = {}

        rule = "<TEXT><NR>"
        expected = "[a-zA-Z][0-9]"

        result = self.plugin.replace_tags(rule)
        self.assertEqual(result, expected)

    def test_replace_rule_with_pre(self):
        self.global_data["replace_tag"] = {
            "<TEXT>": "[a-zA-Z]",
            "<NR>": "[0-9]",
        }
        self.global_data["replace_pre"] = {
            "<pre P1>": r"\W"
        }
        self.global_data["replace_post"] = {}
        self.global_data["replace_inter"] = {}

        rule = "/<pre P1>test<TEXT>+<NR>+/"
        expected = r"/test\W[a-zA-Z]+\W[0-9]+/"

        result = self.plugin.replace_tags(rule)
        self.assertEqual(result, expected)

    def test_replace_rule_with_post(self):
        self.global_data["replace_tag"] = {
            "<TEXT>": "[a-zA-Z]",
            "<NR>": "[0-9]",
        }
        self.global_data["replace_pre"] = {}
        self.global_data["replace_post"] = {
            "<post P1>": r"{3}"
        }
        self.global_data["replace_inter"] = {}

        rule = "/<post P1>test<TEXT><NR>/"
        expected = r"/test[a-zA-Z]{3}[0-9]{3}/"

        result = self.plugin.replace_tags(rule)
        self.assertEqual(result, expected)

    def test_replace_rule_with_inter(self):
        self.global_data["replace_tag"] = {
            "<TEXT>": "[a-zA-Z]",
            "<NR>": "[0-9]",
        }
        self.global_data["replace_pre"] = {}
        self.global_data["replace_post"] = {}
        self.global_data["replace_inter"] = {
            "<inter I1>": r"\W"
        }

        rule = "/<inter I1>test<TEXT><NR>abc<NR>/"
        expected = r"/test[a-zA-Z]\W[0-9]abc[0-9]/"

        result = self.plugin.replace_tags(rule)
        self.assertEqual(result, expected)

    def test_replace_rule_with_pre_and_post(self):
        self.global_data["replace_tag"] = {
            "<TEXT>": "[a-zA-Z]",
            "<NR>": "[0-9]",
        }
        self.global_data["replace_pre"] = {
            "<pre P0>": r"\W"
        }
        self.global_data["replace_post"] = {
            "<post P1>": r"{3}"
        }
        self.global_data["replace_inter"] = {}

        rule = "/<pre P0><post P1>test<TEXT><NR>/"
        expected = r"/test\W[a-zA-Z]{3}\W[0-9]{3}/"

        result = self.plugin.replace_tags(rule)
        self.assertEqual(result, expected)

    def test_replace_rule_with_pre_and_post_and_inter(self):
        self.global_data["replace_tag"] = {
            "<TEXT>": "[a-zA-Z]",
            "<NR>": "[0-9]",
        }
        self.global_data["replace_pre"] = {
            "<pre P0>": r"\W"
        }
        self.global_data["replace_post"] = {
            "<post P1>": r"{3}"
        }
        self.global_data["replace_inter"] = {
            "<inter I1>": "[,.]"
        }

        rule = "/<pre P0><post P1><inter I1>test<TEXT><NR>/"
        expected = r"/test\W[a-zA-Z]{3}[,.]\W[0-9]{3}/"

        result = self.plugin.replace_tags(rule)
        self.assertEqual(result, expected)

    def test_finish_parsing_start_prepare(self):
        results = {
            "FUZZY_TEST_RULE1": {"value": "/test1/"},
            "FUZZY_TEST_RULE2": {"value": "/test2/"},
        }
        self.global_data["replace_rules"] = [
            "FUZZY_TEST_RULE1", "FUZZY_TEST_RULE2"
        ]

        mock_prepare = Mock()
        mock_replace = Mock()
        self.plugin.prepare_tags = mock_prepare
        self.plugin.replace_tags = mock_replace

        self.plugin.finish_parsing_start(results)

        calls = [
            call("pre"), call("inter"), call("post"), call("tag")
        ]
        mock_prepare.assert_has_calls(calls)

    def test_finish_parsing_start_replace(self):
        results = {
            "FUZZY_TEST_RULE1": {"value": "/test1/"},
            "FUZZY_TEST_RULE2": {"value": "/test2/"},
        }
        self.global_data["replace_rules"] = [
            "FUZZY_TEST_RULE1", "FUZZY_TEST_RULE2"
        ]

        mock_prepare = Mock()
        mock_replace = Mock()
        self.plugin.prepare_tags = mock_prepare
        self.plugin.replace_tags = mock_replace

        self.plugin.finish_parsing_start(results)

        calls = [
            call("/test1/"), call("/test2/")
        ]
        mock_replace.assert_has_calls(calls)

    def test_finish_parsing_start_result(self):
        results = {
            "FUZZY_TEST_RULE1": {"value": "/test1/"},
            "FUZZY_TEST_RULE2": {"value": "/test2/"},
        }
        self.global_data["replace_rules"] = [
            "FUZZY_TEST_RULE1", "FUZZY_TEST_RULE2"
        ]

        mock_prepare = Mock()
        mock_replace = Mock(return_value="/new_test/")
        self.plugin.prepare_tags = mock_prepare
        self.plugin.replace_tags = mock_replace

        self.plugin.finish_parsing_start(results)

        self.assertEqual(results["FUZZY_TEST_RULE1"]["value"], "/new_test/")
        self.assertEqual(results["FUZZY_TEST_RULE2"]["value"], "/new_test/")

    def test_finish_parsing_start_result_no_such_rule(self):
        results = {
            "FUZZY_TEST_RULE1": {"value": "/test1/"},
            "FUZZY_TEST_RULE3": {"value": "/test3/"},
        }
        self.global_data["replace_rules"] = [
            "FUZZY_TEST_RULE1", "FUZZY_TEST_RULE2"
        ]

        mock_prepare = Mock()
        mock_replace = Mock(return_value="/new_test/")
        self.plugin.prepare_tags = mock_prepare
        self.plugin.replace_tags = mock_replace

        self.plugin.finish_parsing_start(results)

        self.assertEqual(results["FUZZY_TEST_RULE1"]["value"], "/new_test/")
        self.assertEqual(results["FUZZY_TEST_RULE3"]["value"], "/test3/")
