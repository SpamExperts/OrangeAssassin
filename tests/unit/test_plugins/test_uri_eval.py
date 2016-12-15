"""Tests for pad.plugins.uri_eval plugin"""
import collections
import unittest

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

try:
    from unittest.mock import patch, MagicMock, Mock, call
except ImportError:
    from mock import patch, MagicMock, Mock, call


import pad.context
import pad.message
import pad.plugins.uri_eval


def _get_basic_message(text=""):
    msg = MIMEMultipart()
    msg["from"] = "sender@example.com"
    msg["to"] = "recipient@example.com"
    msg["subject"] = "test"
    if text:
        msg.attach(MIMEText(text))
    return msg


class TestURIDetail(unittest.TestCase):
    """Tests for the URIDetail plugin"""
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        # self.global_data = {"geodb":"/innexistent/location/"}
        # self.cmds = {"uri_detail": pad.plugins.uri_detail.URIDetailRule}
        # patch("pad.plugins.uri_detail.URIDetailPlugin.options",
        #       self.options).start()
        # patch("pad.plugins.uri_detail.URIDetailPlugin.cmds",
        #       self.cmds).start()
        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
                                  )
        # self.plugin = pad.plugins.uri_detail.URIDetailPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    # def check_parse_link(self):