"""Tests for pad.protocol.base"""

import unittest

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

import oa
import oa.protocol.base


class TestBaseCommand(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_h = patch("oa.protocol.base.BaseProtocol.handle").start()
        self.mock_m = patch("oa.protocol.base.oa.message.Message").start()
        self.mockr = Mock()
        self.mockw = Mock()
        self.mockserver = Mock()
        self.mockrules = Mock()
        self.mockserver.get_user_ruleset.return_value = self.mockrules

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        oa.protocol.base.BaseProtocol.has_message = False
        oa.protocol.base.BaseProtocol.has_options = False
        patch.stopall()

    def get_base(self):
        return oa.protocol.base.BaseProtocol(self.mockr, self.mockw,
                                             self.mockserver)

    def test_init(self):
        """Test creating a new base protocol command."""
        base = self.get_base()
        self.mock_h.assert_called_with(None, dict())

    def test_init_options(self):
        """Test creating a new base protocol command."""
        oa.protocol.base.BaseProtocol.has_options = True
        self.mockr.readline.side_effect = [b"Content-Length: 20", b"User: Alex",
                                           b""]
        base = self.get_base()
        self.mock_h.assert_called_with(None, {"content-length": "20",
                                              "user": "Alex"})

    def test_init_message(self):
        """Test creating a new base protocol command."""
        message = b"Subject: Test\n\nTest message"
        oa.protocol.base.BaseProtocol.has_message = True
        self.mockr.read.side_effect = [message, None]
        base = self.get_base()
        self.mock_h.assert_called_with(self.mock_m.return_value, {})
        self.mock_m.assert_called_with(self.mockrules.ctxt,
                                       message.decode("utf8"))

    def test_init_message_chunked(self):
        """Test creating a new base protocol command."""
        message = b"Subject: Test\n\nTest message"
        oa.protocol.base.BaseProtocol.has_message = True
        self.mockr.read.side_effect = [b"Subject: Test\n\nT", b"est message",
                                       None]
        base = self.get_base()
        self.mock_h.assert_called_with(self.mock_m.return_value, {})
        self.mock_m.assert_called_with(self.mockrules.ctxt,
                                       message.decode("utf8"))

    def test_init_message_options(self):
        """Test creating a new base protocol command."""
        message = b"Subject: Test\n\nTest message"
        oa.protocol.base.BaseProtocol.has_message = True
        oa.protocol.base.BaseProtocol.has_options = True
        self.mockr.readline.side_effect = [b"Content-Length: 27", b"User: Alex",
                                           b""]
        self.mockr.read.side_effect = [message, None]
        base = self.get_base()
        self.mock_h.assert_called_with(
            self.mock_m.return_value, {"content-length": "27", "user": "Alex"})
        self.mock_m.assert_called_with(self.mockrules.ctxt,
                                       message.decode("utf8"))

    def test_init_response(self):
        """Test creating a new base protocol command."""
        self.mock_h.return_value = ["Spam: True", "\r\n"]
        base = self.get_base()

        calls = [
            call(("SPAMD/%s 0 EX_OK\r\n" % (oa.__version__)).encode("utf8")),
            call(b"Spam: True"),
            call(b"\r\n"),
        ]

        self.mockw.write.assert_has_calls(calls)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestBaseCommand, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
