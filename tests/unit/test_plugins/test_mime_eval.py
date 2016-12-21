import unittest
import email.errors

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call


import pad.message
import pad.plugins
import pad.plugins.mime_eval

class TestMIMEEval(unittest.TestCase):

    def setUp(self):
        self.options = {}
        self.global_data = {}
        self.msg_data = {}
        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.
                                   setdefault(k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.
                                  setdefault(k, v),
        })

        self.plugin = pad.plugins.mime_eval.MIMEEval(self.mock_ctxt)

    def tearDown(self):
        patch.stopall()

    def test_check_for_mime_html(self):
        self.plugin.set_local(self.mock_msg, "mime_body_html_count", 1)
        self.assertTrue(self.plugin.check_for_mime_html(self.mock_msg))

    def test_check_for_mime_html_false(self):
        self.plugin.set_local(self.mock_msg, "mime_body_html_count", 0)
        self.assertFalse(self.plugin.check_for_mime_html(self.mock_msg))

    def test_check_for_mime_html_only(self):
        self.plugin.set_local(self.mock_msg, "mime_body_html_count", 1)
        self.plugin.set_local(self.mock_msg, "mime_body_text_count", 0)
        self.assertTrue(self.plugin.check_for_mime_html_only(self.mock_msg))

    def test_check_for_mime_html_only_false(self):
        self.plugin.set_local(self.mock_msg, "mime_body_html_count", 1)
        self.plugin.set_local(self.mock_msg, "mime_body_text_count", 1)
        self.assertFalse(self.plugin.check_for_mime_html_only(self.mock_msg))

    def test_check_parse_flags_missing_head_body_separator(self):
        self.mock_msg.msg.defects = [
            email.errors.MissingHeaderBodySeparatorDefect()
        ]
        self.assertTrue(self.plugin.check_msg_parse_flags(
            self.mock_msg, "missing_mime_head_body_separator"
        ))

    def test_check_parse_flags_missing_head_body_separator_false(self):
        self.mock_msg.msg.defects = []
        self.assertFalse(self.plugin.check_msg_parse_flags(
            self.mock_msg, "missing_mime_head_body_separator"
        ))

    def test_check_parse_flags_missing_mime_headers(self):
        self.mock_msg.msg.defects = [
            pad.message.MissingBoundaryHeaderDefect()
        ]
        self.assertTrue(self.plugin.check_msg_parse_flags(
            self.mock_msg, "missing_mime_headers"
        ))

    def test_check_parse_flags_missing_mime_headers_false(self):
        self.mock_msg.msg.defects = []
        self.assertFalse(self.plugin.check_msg_parse_flags(
            self.mock_msg, "missing_mime_headers"
        ))

    def test_check_parse_flags_mime_epilogue_exists(self):
        self.mock_msg.msg.epilogue = "Test"
        self.assertTrue(self.plugin.check_msg_parse_flags(
            self.mock_msg, "mime_epilogue_exists"
        ))

    def test_check_parse_flags_mime_epilogue_exists_False(self):
        self.mock_msg.msg.epilogue = None
        self.assertFalse(self.plugin.check_msg_parse_flags(
            self.mock_msg, "mime_epilogue_exists"
        ))

    def test_check_parse_flags_truncated_headers(self):
        self.mock_msg.raw_headers = {
            "a"*(pad.plugins.mime_eval.MAX_HEADER_KEY + 2):
                "b"*(pad.plugins.mime_eval.MAX_HEADER_VALUE + 2)}
        self.assertTrue(self.plugin.check_msg_parse_flags(
            self.mock_msg, "truncated_headers"
        ))

    def test_check_parse_flags_mime_truncated_headers_false(self):
        self.mock_msg.raw_headers = {"Test": "Value"}
        self.assertFalse(self.plugin.check_msg_parse_flags(
            self.mock_msg, "truncated_headers"
        ))

    def test_check_for_faraway_charset(self):
        self.plugin.set_local(self.mock_msg, "mime_faraway_charset", 1)
        self.assertTrue(self.plugin.check_for_faraway_charset(
            self.mock_msg
        ))

    def test_check_for_faraway_charset_false(self):
        self.plugin.set_local(self.mock_msg, "mime_faraway_charset", 0)
        self.assertFalse(self.plugin.check_for_faraway_charset(
            self.mock_msg
        ))

    def test_check_for_uppercase(self):
        self.mock_msg.text = ("U" * 200) + ("l" * 200)
        self.assertTrue(self.plugin.check_for_uppercase(
            self.mock_msg, 49, 51
        ))

    def test_check_for_uppercase_false(self):
        self.mock_msg.text = ("U" * 200) + ("l" * 250)
        self.assertFalse(self.plugin.check_for_uppercase(
            self.mock_msg, "49", "51"
        ))

    def test_check_mime_multipart_ratio(self):
        self.plugin.set_local(self.mock_msg, "mime_multipart_ratio",
                              0.5)
        self.assertTrue(self.plugin.check_mime_multipart_ratio,
                        )
