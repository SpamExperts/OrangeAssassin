"""Tests for pad.plugins.replace_tags."""

import unittest
import collections

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.body_eval


class TestBodyEval(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.local_data = {
            "multiparts": [],
            "text_tokens": collections.Counter(),
            "html_tokens": collections.Counter(),
        }
        self.global_data = {}
        self.mock_ctxt = MagicMock()
        self.mock_msg = MagicMock()
        self.plugin = pad.plugins.body_eval.BodyEval(self.mock_ctxt)
        self.plugin.set_local = lambda m, k, v: self.local_data.__setitem__(k, v)
        self.plugin.get_local = lambda m, k: self.local_data.__getitem__(k)
        self.plugin.set_global = self.global_data.__setitem__
        self.plugin.get_global = self.global_data.__getitem__
        self.mock_ruleset = MagicMock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_start(self):
        del self.local_data["multiparts"]
        del self.local_data["text_tokens"]
        del self.local_data["html_tokens"]
        expected = {
            "multiparts": [],
            "text_tokens": collections.Counter(),
            "html_tokens": collections.Counter(),
        }
        self.plugin.check_start(self.mock_msg)
        self.assertEqual(self.local_data, expected)

    def test_extract_metadata_multipart(self):
        subparts = [Mock(), Mock()]
        part = MagicMock()
        part.get_content_type.return_value = "multipart/alternative"
        part.get_payload.return_value = subparts

        self.plugin.extract_metadata(self.mock_msg, "", None, part)

        self.assertEqual(self.local_data["multiparts"],
                         [id(subpart) for subpart in subparts])

    def test_extract_metadata_no_plain_or_html(self):
        part = MagicMock()
        self.local_data["multiparts"].append(id(part))
        part.get_content_type.return_value = "text/other"

        self.plugin.extract_metadata(self.mock_msg, "", None, part)

        self.assertEqual(dict(self.local_data["text_tokens"]), {})
        self.assertEqual(dict(self.local_data["html_tokens"]), {})

    def test_extract_metadata_id_not_in_multipart(self):
        part = MagicMock()
        part.get_content_type.return_value = "text/plain"

        self.plugin.extract_metadata(self.mock_msg, "", None, part)

        self.assertEqual(dict(self.local_data["text_tokens"]), {})
        self.assertEqual(dict(self.local_data["html_tokens"]), {})

    def test_extract_metadata_plain(self):
        part = MagicMock()
        self.local_data["multiparts"].append(id(part))
        part.get_content_type.return_value = "text/plain"

        self.plugin.extract_metadata(self.mock_msg,
                                     "Test token test",
                                     "Test token test", part)

        self.assertEqual(dict(self.local_data["text_tokens"]), {
            "test": 2,
            "token": 1,
        })
        self.assertEqual(dict(self.local_data["html_tokens"]), {})

    def test_extract_metadata_html(self):
        part = MagicMock()
        self.local_data["multiparts"].append(id(part))
        part.get_content_type.return_value = "text/html"

        self.plugin.extract_metadata(self.mock_msg,
                                     "<html><body>"
                                     "Test token test"
                                     "</body></html>",
                                     "Test token test", part)

        self.assertEqual(dict(self.local_data["text_tokens"]), {})
        self.assertEqual(dict(self.local_data["html_tokens"]), {
            "test": 2,
            "token": 1,
        })

    def test_parsed_metadata_check_diff_0(self):
        self.local_data["text_tokens"].update([
            "token1", "token2", "token1"
        ])
        self.local_data["html_tokens"].update([
            "token1", "token2", "token1"
        ])
        self.mock_msg.raw_text = "token1 token2 token1"

        self.plugin.parsed_metadata(self.mock_msg)
        self.assertEqual(self.local_data["madiff"], 0.0)

    def test_parsed_metadata_check_diff_50(self):
        self.local_data["text_tokens"].update([
            "token1", "token2", "token1"
        ])
        self.local_data["html_tokens"].update([
            "token1", "token4", "token1"
        ])
        self.mock_msg.raw_text = "token1 token2 token1"

        self.plugin.parsed_metadata(self.mock_msg)
        self.assertEqual(self.local_data["madiff"], 50.0)

    def test_parsed_metadata_check_diff_100(self):
        self.local_data["text_tokens"].update([
            "token1", "token2", "token1"
        ])
        self.local_data["html_tokens"].update([
            "token3", "token4", "token3"
        ])
        self.mock_msg.raw_text = "token1 token2 token1"

        self.plugin.parsed_metadata(self.mock_msg)
        self.assertEqual(self.local_data["madiff"], 100.0)

    def test_parsed_metadata_check_no_tokens(self):
        self.mock_msg.raw_text = "token1 token2 token1"
        self.plugin.parsed_metadata(self.mock_msg)
        self.assertEqual(self.local_data["madiff"], 0.0)

    def test_ma_diff_true(self):
        self.local_data["madiff"] = 42.0
        result = self.plugin.multipart_alternative_difference(
            self.mock_msg, 41.5, 42.5
        )
        self.assertTrue(result)

    def test_ma_diff_false(self):
        self.local_data["madiff"] = 42.0
        result = self.plugin.multipart_alternative_difference(
            self.mock_msg, 42.5, 43.5
        )
        self.assertFalse(result)

    def test_ma_diff_count_true(self):
        # The count ratio here is 0.66
        self.local_data["text_tokens"].update([
            "token1", "token2", "token1"
        ])
        self.local_data["html_tokens"].update([
            "token3", "token4", "token5"
        ])
        result = self.plugin.multipart_alternative_difference_count(
            self.mock_msg, 0.65, 1
        )
        self.assertTrue(result)

    def test_ma_diff_count_false(self):
        # The count ratio here is 0.66
        self.local_data["text_tokens"].update([
            "token1", "token2", "token1"
        ])
        self.local_data["html_tokens"].update([
            "token3", "token4", "token5"
        ])
        result = self.plugin.multipart_alternative_difference_count(
            self.mock_msg, 0.67, 1
        )
        self.assertFalse(result)

    def test_ma_diff_count_false_not_enough_html(self):
        # The count ratio here is 0.66
        self.local_data["text_tokens"].update([
            "token1", "token2", "token1"
        ])
        self.local_data["html_tokens"].update([
            "token3", "token4", "token5"
        ])
        result = self.plugin.multipart_alternative_difference_count(
            self.mock_msg, 0.67, 4
        )
        self.assertFalse(result)

    def test_ma_diff_count_false_no_tokens(self):
        # The count ratio here is 0.66
        result = self.plugin.multipart_alternative_difference_count(
            self.mock_msg, 0.67, 0
        )
        self.assertFalse(result)

    def test_blank_line_ratio_true(self):
        # The ratio here is 10%
        self.local_data["line_count"] = 100
        self.local_data["blank_line_count"] = 10

        result = self.plugin.check_blank_line_ratio(
            self.mock_msg, 9.9, 10.1, 1
        )
        self.assertTrue(result)

    def test_blank_line_ratio_false(self):
        # The ratio here is 10%
        self.local_data["line_count"] = 100
        self.local_data["blank_line_count"] = 10

        result = self.plugin.check_blank_line_ratio(
            self.mock_msg, 10.1, 10.2, 1
        )
        self.assertFalse(result)

    def test_blank_line_ratio_not_enough_lines(self):
        # The ratio here is 10%
        self.local_data["line_count"] = 100
        self.local_data["blank_line_count"] = 10

        result = self.plugin.check_blank_line_ratio(
            self.mock_msg, 10.1, 10.2, 101
        )
        self.assertFalse(result)

    def test_tvd_true(self):
        # The ratio of space to non/space is 27.2%
        self.mock_msg.raw_text = "This is a test"
        self.mock_msg.text = "This is a test"

        result = self.plugin.tvd_vertical_words(
            self.mock_msg, 26.9, 27.3, "rawbody"
        )
        self.assertTrue(result)

    def test_tvd_false(self):
        # The ratio of space to non/space is 27.2%
        self.mock_msg.raw_text = "This is a test"
        self.mock_msg.text = "This is a test"

        result = self.plugin.tvd_vertical_words(
            self.mock_msg, 26.9, 27.1, "body"
        )
        self.assertFalse(result)

    def test_tvd_false_zero_text(self):
        # The ratio of space to non/space is 27.2%
        self.mock_msg.raw_text = "This is a test"
        self.mock_msg.text = ""

        result = self.plugin.tvd_vertical_words(
            self.mock_msg, 26.9, 27.1, "body"
        )
        self.assertFalse(result)

    def test_stock_info_true(self):
        # 2 "stock" words
        self.mock_msg.raw_text = "This is high expectations company test"
        self.mock_msg.text = "This is high expectations company test"

        result = self.plugin.check_stock_info(
            self.mock_msg, 2, "rawbody"
        )
        self.assertTrue(result)

    def test_stock_info_false(self):
        # 2 "stock" words
        self.mock_msg.raw_text = "This is high expectations company test"
        self.mock_msg.text = "This is high expectations company test"

        result = self.plugin.check_stock_info(
            self.mock_msg, 3, "body"
        )
        self.assertFalse(result)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestBodyEval, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')