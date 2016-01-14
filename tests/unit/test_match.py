"""Tests for match script"""

import unittest
import argparse
from io import StringIO

try:
    from unittest.mock import patch, Mock, MagicMock, mock_open, call
except ImportError:
    from mock import patch, Mock, MagicMock, mock_open, call

import scripts.match
import pad.errors

EXAMPLE_EMAIL = ()

class TestRevokeReport(unittest.TestCase):
    raw_messages = [u"Message Stub 1",
                    u"Message Stub 2",
                    u"Message Stub 3",]

    def setUp(self):
        ruleset = patch("scripts.match.pad.rules."
                        "parser.parse_pad_rules").start()
        self.ctxt = ruleset.return_value.ctxt
        patch("scripts.match.MessageList").start()
        patch("scripts.match.pad.config.get_config_files").start()
        msg_class = patch("scripts.match.pad.message.Message").start()
        self.messages = [msg_class(self.ctxt, x) for x in self.raw_messages]

    def tearDown(self):
        patch.stopall()
        super(TestRevokeReport, self).tearDown()

    def test_report(self):
        options = scripts.match.parse_arguments(["--report",
                                                 "--siteconfigpath", ".",
                                                 "--configpath", "."])
        options.messages = [[StringIO(x) for x in self.raw_messages]]
        patch("scripts.match.parse_arguments",
              return_value=options).start()
        scripts.match.main()
        calls = [call(x) for x in self.messages]
        self.ctxt.hook_report.assert_has_calls(calls)
        self.ctxt.hook_revoke.assert_not_called()

    def test_revoke(self):
        options = scripts.match.parse_arguments(["--revoke",
                                                 "--siteconfigpath", ".",
                                                 "--configpath", "."])
        options.messages = [[StringIO(x) for x in self.raw_messages]]
        patch("scripts.match.parse_arguments",
              return_value=options).start()
        scripts.match.main()
        calls = [call(x) for x in self.messages]
        self.ctxt.hook_revoke.assert_has_calls(calls)
        self.ctxt.hook_report.assert_not_called()

    def test_max_recursion_exception(self):
        options = scripts.match.parse_arguments(["--revoke",
                                                 "--siteconfigpath", ".",
                                                 "--configpath", "."])
        options.messages = [[StringIO(x) for x in self.raw_messages]]
        patch("scripts.match.parse_arguments",
              return_value=options).start()
        self.mock_parse = patch(
            "pad.rules.parser.parse_pad_rules",
            side_effect=pad.errors.MaxRecursionDepthExceeded).start()
        with self.assertRaises(SystemExit):
            scripts.match.main()

    def test_parsing_error_exception(self):
        options = scripts.match.parse_arguments(["--revoke",
                                                 "--siteconfigpath", ".",
                                                 "--configpath", "."])
        options.messages = [[StringIO(x) for x in self.raw_messages]]
        patch("scripts.match.parse_arguments",
              return_value=options).start()
        self.mock_parse = patch(
            "pad.rules.parser.parse_pad_rules",
            side_effect=pad.errors.ParsingError).start()
        with self.assertRaises(SystemExit):
            scripts.match.main()

    def test_both(self):
        with self.assertRaises(SystemExit):
            with patch("sys.stderr"):
                scripts.match.parse_arguments(["--revoke", "--report", "-"])



def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestRevokeReport, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
