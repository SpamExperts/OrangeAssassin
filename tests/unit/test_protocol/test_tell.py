"""Tests for pad.protocol.base"""

import unittest

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

import oa
import oa.protocol.tell


class TestTellCommand(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mockr = Mock()
        self.mockw = Mock()
        self.mockserver = Mock()
        self.mockrules = Mock()
        self.mockserver.get_user_ruleset.return_value = self.mockrules
        for klass in ("TellCommand",):
            patch("oa.protocol.tell.%s.get_and_handle" % klass).start()
        self.msg = Mock(score=0)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_tell_set_spam_local(self):
        options = {
            "message-class": "spam",
            "set": "local"
        }
        expected = [
            "DidSet: local\r\n"
        ]
        cmd = oa.protocol.tell.TellCommand(self.mockr, self.mockw,
                                           self.mockserver)
        result = list(cmd.handle(self.msg, options))
        self.mockrules.ctxt.hook_report.assert_called_with(
            self.msg, True, True, False
        )
        self.assertEqual(result, expected)

    def test_tell_set_spam_remote(self):
        options = {
            "message-class": "spam",
            "set": "remote"
        }
        expected = [
            "DidSet: remote\r\n"
        ]
        cmd = oa.protocol.tell.TellCommand(self.mockr, self.mockw,
                                           self.mockserver)
        result = list(cmd.handle(self.msg, options))
        self.mockrules.ctxt.hook_report.assert_called_with(
            self.msg, True, False, True
        )
        self.assertEqual(result, expected)

    def test_tell_set_spam_both(self):
        options = {
            "message-class": "spam",
            "set": "local,remote"
        }
        expected = [
            "DidSet: local,remote\r\n"
        ]
        cmd = oa.protocol.tell.TellCommand(self.mockr, self.mockw,
                                           self.mockserver)
        result = list(cmd.handle(self.msg, options))
        self.mockrules.ctxt.hook_report.assert_called_with(
            self.msg, True, True, True
        )
        self.assertEqual(result, expected)

    def test_tell_remove_ham_local(self):
        options = {
            "message-class": "ham",
            "remove": "local"
        }
        expected = [
            "DidRemove: local\r\n"
        ]
        cmd = oa.protocol.tell.TellCommand(self.mockr, self.mockw,
                                           self.mockserver)
        result = list(cmd.handle(self.msg, options))
        self.mockrules.ctxt.hook_revoke.assert_called_with(
            self.msg, False, True, False
        )
        self.assertEqual(result, expected)

    def test_tell_remove_ham_remote(self):
        options = {
            "message-class": "ham",
            "remove": "remote"
        }
        expected = [
            "DidRemove: remote\r\n"
        ]
        cmd = oa.protocol.tell.TellCommand(self.mockr, self.mockw,
                                           self.mockserver)
        result = list(cmd.handle(self.msg, options))
        self.mockrules.ctxt.hook_revoke.assert_called_with(
            self.msg, False, False, True
        )
        self.assertEqual(result, expected)

    def test_tell_remove_ham_both(self):
        options = {
            "message-class": "ham",
            "remove": "local,remote"
        }
        expected = [
            "DidRemove: local,remote\r\n"
        ]
        cmd = oa.protocol.tell.TellCommand(self.mockr, self.mockw,
                                           self.mockserver)
        result = list(cmd.handle(self.msg, options))
        self.mockrules.ctxt.hook_revoke.assert_called_with(
            self.msg, False, True, True
        )
        self.assertEqual(result, expected)

    def test_tell_set_and_remove(self):
        options = {
            "message-class": "spam",
            "set": "remote",
            "remove": "local",
        }
        expected = [
            "DidSet: remote\r\n",
            "DidRemove: local\r\n"
        ]
        cmd = oa.protocol.tell.TellCommand(self.mockr, self.mockw,
                                           self.mockserver)
        result = list(cmd.handle(self.msg, options))
        self.mockrules.ctxt.hook_report.assert_called_with(
            self.msg, True, False, True
        )
        self.mockrules.ctxt.hook_revoke.assert_called_with(
            self.msg, True, True, False
        )
        self.assertEqual(result, expected)

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestTellCommand, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
