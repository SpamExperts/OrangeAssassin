"""Tests for pad.protocol.base"""

import unittest

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

import oa
import oa.protocol.noop


class TestNoopCommand(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mockr = Mock()
        self.mockw = Mock()
        self.mockrules = Mock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_skip(self):
        oa.protocol.noop.SkipCommand(self.mockr, self.mockw, self.mockrules)
        self.assertFalse(self.mockw.called)

    def test_ping(self):
        oa.protocol.noop.PingCommand(self.mockr, self.mockw, self.mockrules)

        calls = [
            call(("SPAMD/%s 0 PONG\r\n" % oa.__version__).encode("utf8")),
        ]

        self.mockw.write.assert_has_calls(calls)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestNoopCommand, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
