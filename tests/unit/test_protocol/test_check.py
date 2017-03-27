"""Tests for pad.protocol.base"""

import unittest
import collections

try:
    from unittest.mock import patch, Mock, call, MagicMock
except ImportError:
    from mock import patch, Mock, call, MagicMock

import oa
import oa.protocol.check


class TestCheckCommand(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        for klass in ("CheckCommand", "SymbolsCommand", "ReportCommand",
                      "ReportIfSpamCommand"):
            patch("oa.protocol.check.%s.get_and_handle" % klass).start()
        self.msg = Mock(score=0)
        self.mockr = Mock()
        self.mockw = Mock()
        self.conf = {
            "required_score": 5
        }
        self.mockserver = Mock()
        self.mockrules = Mock(conf=self.conf)
        self.mockserver.get_user_ruleset.return_value = self.mockrules

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check(self):
        cmd = oa.protocol.check.CheckCommand(self.mockr, self.mockw,
                                             self.mockserver)
        result = list(cmd.handle(self.msg, {}))
        self.mockrules.match.assert_called_with(self.msg)

    def test_check_score(self):
        cmd = oa.protocol.check.CheckCommand(self.mockr, self.mockw,
                                             self.mockserver)
        self.msg.score = 2442
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %.1f / %s\r\n" % (True, 2442, 5),
                                  'Content-length: 0\r\n\r\n', ""])

    def test_check_score_not_spam(self):
        cmd = oa.protocol.check.CheckCommand(self.mockr, self.mockw,
                                             self.mockserver)
        self.msg.score = 1
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %.1f / %s\r\n" % (False, 1, 5),
                                  'Content-length: 0\r\n\r\n', ""])

    def test_symbols_score(self):
        cmd = oa.protocol.check.SymbolsCommand(self.mockr, self.mockw,
                                               self.mockserver)
        self.msg.score = 2442
        self.msg.rules_checked = collections.OrderedDict()
        self.msg.rules_checked['TEST_RULE_1'] = True
        self.msg.rules_checked['TEST_RULE_2'] = False
        self.msg.rules_checked['TEST_RULE_3'] = True
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %.1f / %s\r\n" % (True, 2442, 5),
                                  'Content-length: 23\r\n\r\n',
                                  "TEST_RULE_1,TEST_RULE_3"])

    def test_symbols_score_not_spam(self):
        cmd = oa.protocol.check.SymbolsCommand(self.mockr, self.mockw,
                                               self.mockserver)
        self.msg.score = 3
        self.msg.rules_checked = collections.OrderedDict()
        self.msg.rules_checked['TEST_RULE_1'] = True
        self.msg.rules_checked['TEST_RULE_2'] = False
        self.msg.rules_checked['TEST_RULE_3'] = True
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ["Spam: %s ; %.1f / %s\r\n" % (False, 3, 5),
                                  'Content-length: 23\r\n\r\n',
                                  "TEST_RULE_1,TEST_RULE_3"])

    def test_report_score(self):
        cmd = oa.protocol.check.ReportCommand(self.mockr, self.mockw,
                                              self.mockserver)
        self.msg.score = 2442
        self.mockrules.get_report.return_value = "Test report"
        result = list(cmd.handle(self.msg, {}))
        expected = ['Spam: True ; 2442.0 / 5\r\n',
                    'Content-length: 11\r\n\r\n', 'Test report']
        self.assertEqual(result, expected)

    def test_report_score_not_spam(self):
        cmd = oa.protocol.check.ReportCommand(self.mockr, self.mockw,
                                              self.mockserver)
        self.msg.score = 4
        self.mockrules.get_report.return_value = "Test report"
        result = list(cmd.handle(self.msg, {}))
        expected = ['Spam: False ; 4.0 / 5\r\n',
                    'Content-length: 11\r\n\r\n', 'Test report']
        self.assertEqual(result, expected)

    def test_report_ifspam_score(self):
        cmd = oa.protocol.check.ReportIfSpamCommand(
                self.mockr, self.mockw, self.mockserver)
        self.msg.score = 2442
        self.mockrules.get_report.return_value = "Test report"
        result = list(cmd.handle(self.msg, {}))
        expected = ['Spam: True ; 2442.0 / 5\r\n',
                    'Content-length: 11\r\n\r\n', 'Test report']
        self.assertEqual(result, expected)

    def test_report_ifspam_score_not_spam(self):
        cmd = oa.protocol.check.ReportIfSpamCommand(
                self.mockr, self.mockw, self.mockserver)
        self.msg.score = 4
        self.mockrules.get_report.return_value = "Test report"
        result = list(cmd.handle(self.msg, {}))
        expected = ['Spam: False ; 4.0 / 5\r\n', 'Content-length: '
                                                 '0\r\n\r\n', '']
        self.assertEqual(result, expected)

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestCheckCommand, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
