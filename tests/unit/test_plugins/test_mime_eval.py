import unittest
import email.errors

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call


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

