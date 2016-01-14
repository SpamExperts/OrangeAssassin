"""Tests for pad.protocol.base"""

import unittest
import collections

try:
    from unittest.mock import patch, Mock, call, MagicMock
except ImportError:
    from mock import patch, Mock, call, MagicMock

import pad
import pad.protocol.check


class TestCheckCommand(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        for klass in ("CheckCommand", "SymbolsCommand", "ReportCommand",
                      "ReportIfSpamCommand"):
            patch("pad.protocol.check.%s.get_and_handle" % klass).start()
        self.msg = Mock(score=0)
        self.mockr = Mock()
        self.mockw = Mock()
        self.mockrules = Mock(required_score=5)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check(self):
        cmd = pad.protocol.check.CheckCommand(self.mockr, self.mockw,
                                              self.mockrules)
        result = list(cmd.handle(self.msg, {}))
        self.mockrules.match.assert_called_with(self.msg)

    def test_check_score(self):
        cmd = pad.protocol.check.CheckCommand(self.mockr, self.mockw,
                                              self.mockrules)
        self.msg.score = 2442
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %s / %s\r\n" % (True, 2442, 5),
                                  ""])

    def test_check_score_not_spam(self):
        cmd = pad.protocol.check.CheckCommand(self.mockr, self.mockw,
                                              self.mockrules)
        self.msg.score = 1
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %s / %s\r\n" % (False, 1, 5),
                                  ""])

    def test_symbols_score(self):
        cmd = pad.protocol.check.SymbolsCommand(self.mockr, self.mockw,
                                                self.mockrules)
        self.msg.score = 2442
        self.msg.rules_checked = collections.OrderedDict()
        self.msg.rules_checked['TEST_RULE_1'] = True
        self.msg.rules_checked['TEST_RULE_2'] = False
        self.msg.rules_checked['TEST_RULE_3'] = True
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %s / %s\r\n" % (True, 2442, 5),
                                  "\r\n", "TEST_RULE_1,TEST_RULE_3"])

    def test_symbols_score_not_spam(self):
        cmd = pad.protocol.check.SymbolsCommand(self.mockr, self.mockw,
                                                self.mockrules)
        self.msg.score = 3
        self.msg.rules_checked = collections.OrderedDict()
        self.msg.rules_checked['TEST_RULE_1'] = True
        self.msg.rules_checked['TEST_RULE_2'] = False
        self.msg.rules_checked['TEST_RULE_3'] = True
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %s / %s\r\n" % (False, 3, 5),
                                  "\r\n", "TEST_RULE_1,TEST_RULE_3"])

    def test_report_score(self):
        cmd = pad.protocol.check.ReportCommand(self.mockr, self.mockw,
                                               self.mockrules)
        self.msg.score = 2442
        self.msg.rules_checked = collections.OrderedDict()
        self.msg.rules_checked['TEST_RULE_1'] = True
        self.msg.rules_checked['TEST_RULE_2'] = True

        self.mockrules.get_rule.side_effect = [
            MagicMock(__str__=lambda x: "test rule 1 desc"),
            MagicMock(__str__=lambda x: "test rule 2 desc"),
        ]
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %s / %s\r\n" % (True, 2442, 5),
                                  "\r\n", "test rule 1 desc", "\r\n",
                                  "test rule 2 desc", "\r\n"])

    def test_report_score_not_spam(self):
        cmd = pad.protocol.check.ReportCommand(self.mockr, self.mockw,
                                               self.mockrules)
        self.msg.score = 4
        self.msg.rules_checked = collections.OrderedDict()
        self.msg.rules_checked['TEST_RULE_1'] = True
        self.msg.rules_checked['TEST_RULE_2'] = True

        self.mockrules.get_rule.side_effect = [
            MagicMock(__str__=lambda x: "test rule 1 desc"),
            MagicMock(__str__=lambda x: "test rule 2 desc"),
        ]
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %s / %s\r\n" % (False, 4, 5),
                                  "\r\n", "test rule 1 desc", "\r\n",
                                  "test rule 2 desc", "\r\n"])

    def test_report_ifspam_score(self):
        cmd = pad.protocol.check.ReportIfSpamCommand(
                self.mockr, self.mockw, self.mockrules)
        self.msg.score = 2442
        self.msg.rules_checked = collections.OrderedDict()
        self.msg.rules_checked['TEST_RULE_1'] = True
        self.msg.rules_checked['TEST_RULE_2'] = True

        self.mockrules.get_rule.side_effect = [
            MagicMock(__str__=lambda x: "test rule 1 desc"),
            MagicMock(__str__=lambda x: "test rule 2 desc"),
        ]
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %s / %s\r\n" % (True, 2442, 5),
                                  "\r\n", "test rule 1 desc", "\r\n",
                                  "test rule 2 desc", "\r\n"])

    def test_report_ifspam_score_not_spam(self):
        cmd = pad.protocol.check.ReportIfSpamCommand(
                self.mockr, self.mockw, self.mockrules)
        self.msg.score = 4
        self.msg.rules_checked = collections.OrderedDict()
        self.msg.rules_checked['TEST_RULE_1'] = True
        self.msg.rules_checked['TEST_RULE_2'] = True

        self.mockrules.get_rule.side_effect = [
            MagicMock(__str__=lambda x: "test rule 1 desc"),
            MagicMock(__str__=lambda x: "test rule 2 desc"),
        ]
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %s / %s\r\n" % (False, 4, 5)])

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestCheckCommand, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
