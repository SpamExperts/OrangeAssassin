"""Tests for pad.protocol.base"""

import unittest

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

import pad
import pad.protocol.process


class TestProcessCommand(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mockr = Mock()
        self.mockw = Mock()
        self.mockrules = Mock()
        for klass in ("ProcessCommand", "HeadersCommand"):
            patch("pad.protocol.process.%s.get_and_handle" % klass).start()
        self.msg = Mock(score=0)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_process(self):
        cmd = pad.protocol.process.ProcessCommand(self.mockr, self.mockw,
                                                  self.mockrules)
        result = list(cmd.handle(self.msg, {}))
        self.mockrules.match.assert_called_with(self.msg)

    def test_process_result(self):
        cmd = pad.protocol.process.ProcessCommand(self.mockr, self.mockw,
                                                  self.mockrules)
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(result,
                         [self.mockrules.get_adjusted_message(self.msg)])

    def test_headers(self):
        cmd = pad.protocol.process.HeadersCommand(self.mockr, self.mockw,
                                                  self.mockrules)
        result = list(cmd.handle(self.msg, {}))
        self.mockrules.match.assert_called_with(self.msg)

    def test_headers_result(self):
        cmd = pad.protocol.process.HeadersCommand(self.mockr, self.mockw,
                                                  self.mockrules)
        result = list(cmd.handle(self.msg, {}))
        self.assertEqual(
            result,
            [self.mockrules.get_adjusted_message(self.msg, headers_only=True)]
        )

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestProcessCommand, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
