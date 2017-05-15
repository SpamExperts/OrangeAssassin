"""Tests for pad.protocol.base"""

import unittest

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

import oa
import oa.protocol.process


class TestProcessCommand(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mockr = Mock()
        self.mockw = Mock()
        self.conf = {
            "required_score": 5
        }
        self.mockserver = Mock()
        self.mockrules = Mock(conf=self.conf)
        self.mockserver.get_user_ruleset.return_value = self.mockrules
        for klass in ("ProcessCommand", "HeadersCommand"):
            patch("oa.protocol.process.%s.get_and_handle" % klass).start()
        self.msg = Mock(score=0)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_process(self):
        cmd = oa.protocol.process.ProcessCommand(self.mockr, self.mockw,
                                                 self.mockserver)
        self.mockrules.get_adjusted_message.return_value = "Test"
        result = list(cmd.handle(self.msg, {}))
        self.mockrules.match.assert_called_with(self.msg)

    def test_process_result(self):
        cmd = oa.protocol.process.ProcessCommand(self.mockr, self.mockw,
                                                 self.mockserver)
        self.mockrules.get_adjusted_message.return_value = "Test"
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ['Spam: False ; 0.0 / 5\r\n',
                                  'Content-length: 4\r\n\r\n', 'Test'])
        self.mockrules.get_adjusted_message.assert_called_with(self.msg)

    def test_headers(self):
        cmd = oa.protocol.process.HeadersCommand(self.mockr, self.mockw,
                                                 self.mockserver)
        self.mockrules.get_adjusted_message.return_value = "Test"
        result = list(cmd.handle(self.msg, {}))
        self.mockrules.match.assert_called_with(self.msg)

    def test_headers_result(self):
        cmd = oa.protocol.process.HeadersCommand(self.mockr, self.mockw,
                                                 self.mockserver)
        self.mockrules.get_adjusted_message.return_value = "Test"
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result, ['Spam: False ; 0.0 / 5\r\n',
                                  'Content-length: 4\r\n\r\n', 'Test'])
        self.mockrules.get_adjusted_message.assert_called_with(
            self.msg, header_only=True
        )


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestProcessCommand, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
