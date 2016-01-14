"""Tests for pad.protocol.base"""

import unittest

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

import pad
import pad.protocol.base


class TestBaseCommand(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_h = patch("pad.protocol.base.BaseProtocol.handle").start()
        self.mock_m = patch("pad.protocol.base.pad.message.Message").start()
        self.mockr = Mock()
        self.mockw = Mock()
        self.mockrules = Mock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        pad.protocol.base.BaseProtocol.has_message = False
        pad.protocol.base.BaseProtocol.has_options = False
        patch.stopall()

    def get_base(self):
        return pad.protocol.base.BaseProtocol(self.mockr, self.mockw,
                                              self.mockrules)

    def test_init(self):
        """Test creating a new base protocol command."""
        base = self.get_base()
        self.mock_h.assert_called_with(None, dict())

    def test_init_options(self):
        """Test creating a new base protocol command."""
        pad.protocol.base.BaseProtocol.has_options = True
        self.mockr.readline.side_effect = ["Content-Length: 20", "User: Alex",
                                           ""]
        base = self.get_base()
        self.mock_h.assert_called_with(None, {"content-length": "20",
                                              "user": "Alex"})

    def test_init_message(self):
        """Test creating a new base protocol command."""
        message = "Subject: Test\n\nTest message"
        pad.protocol.base.BaseProtocol.has_message = True
        self.mockr.read.side_effect = [message, None]
        base = self.get_base()
        self.mock_h.assert_called_with(self.mock_m.return_value, {})
        self.mock_m.assert_called_with(self.mockrules.ctxt, message)

    def test_init_message_chunked(self):
        """Test creating a new base protocol command."""
        message = "Subject: Test\n\nTest message"
        pad.protocol.base.BaseProtocol.has_message = True
        self.mockr.read.side_effect = ["Subject: Test\n\nT", "est message",
                                       None]
        base = self.get_base()
        self.mock_h.assert_called_with(self.mock_m.return_value, {})
        self.mock_m.assert_called_with(self.mockrules.ctxt, message)

    def test_init_message_options(self):
        """Test creating a new base protocol command."""
        message = "Subject: Test\n\nTest message"
        pad.protocol.base.BaseProtocol.has_message = True
        pad.protocol.base.BaseProtocol.has_options = True
        self.mockr.readline.side_effect = ["Content-Length: 27", "User: Alex",
                                           ""]
        self.mockr.read.side_effect = [message, None]
        base = self.get_base()
        self.mock_h.assert_called_with(
            self.mock_m.return_value, {"content-length": "27", "user": "Alex"})
        self.mock_m.assert_called_with(self.mockrules.ctxt, message)

    def test_init_response(self):
        """Test creating a new base protocol command."""
        self.mock_h.return_value = ["Spam: True", "\r\n"]
        base = self.get_base()

        calls = [
            call("SPAMD/%s 0 EX_OK\r\n" % (pad.__version__)),
            call("Spam: True"),
            call("\r\n"),
        ]

        self.mockw.write.assert_has_calls(calls)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestBaseCommand, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
