"""Unittest for scripts.oad"""

import signal
import logging
import unittest
import threading

try:
    from unittest.mock import patch, Mock, call, MagicMock, ANY
except ImportError:
    from mock import patch, Mock, call, MagicMock, ANY


import oa.server


class TestServer(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        logging.getLogger("oa-logger").handlers = [logging.NullHandler()]
        self.mock_socket = patch("oa.server.socket", create=True).start()
        self.mock_sock = patch("oa.server.Server.socket", create=True).start()
        patch("oa.server.oa.config.get_config_files").start()
        patch("oa.server.spoon.server").start()
        self.mock_bind = patch("oa.server.Server.server_bind").start()
        self.mock_active = patch("oa.server.Server.server_activate").start()
        # self.mock_signal = patch("oa.server.signal.signal",
        #                          create=True).start()
        # self.mock_thread = patch("oa.server.threading.Thread").start()
        self.mock_parser = patch("oa.server."
                                 "oa.rules.parser.PADParser").start()
        self.mock_rules = patch("oa.server."
                                "oa.rules.parser.parse_pad_rules").start()
        self.mainset = self.mock_rules.return_value.get_ruleset.return_value
        self.conf = {
            "allow_user_rules": False
        }
        self.mainset.conf = self.conf

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_init_ruleset(self):
        server = oa.server.Server(("0.0.0.0", 783), "/dev/null",
                                   "/etc/spamassassin/")
        self.assertEqual(server._parser_results,
                         self.mock_rules.return_value.results)
        self.assertEqual(server._ruleset, self.mainset)

    def test_handler(self):
        mock_check = MagicMock()
        mock_rfile = MagicMock()
        mock_rfile.readline.return_value = b"CHECK SPAMC/1.2"
        mock_request = MagicMock()
        mock_request.makefile.return_value = mock_rfile
        mock_server = MagicMock()

        patch("oa.server.COMMANDS", {"CHECK": mock_check}, create=True).start()
        oa.server.RequestHandler(mock_request, ("127.0.0.1", 47563),
                                 mock_server)
        mock_check.assert_called_with(mock_rfile, ANY,
                                      mock_server)

    def test_server(self):
        server = oa.server.Server(("0.0.0.0", 783), "/dev/null",
                                   "/etc/spamassassin/")
        self.mock_bind.assert_called_with()
        self.mock_active.assert_called_with()

    def test_user_ruleset_none(self):
        server = oa.server.Server(("0.0.0.0", 783), "/dev/null",
                                   "/etc/spamassassin/")
        result = server.get_user_ruleset(user=None)
        self.assertEqual(result, self.mainset)

    def test_user_ruleset_user_not_allowed(self):
        server = oa.server.Server(("0.0.0.0", 783), "/dev/null",
                                   "/etc/spamassassin/")
        result = server.get_user_ruleset(user="alex")
        self.assertEqual(result, self.mainset)

    def test_user_ruleset_user_no_pref(self):
        self.conf["allow_user_rules"] = True
        server = oa.server.Server(("0.0.0.0", 783), "/dev/null",
                                   "/etc/spamassassin/")
        with patch("oa.server.os.path.exists", return_value=False):
            result = server.get_user_ruleset(user="alex")
        self.assertEqual(result, self.mainset)

    def test_user_ruleset_user(self):
        self.conf["allow_user_rules"] = True
        server = oa.server.Server(("0.0.0.0", 783), "/dev/null",
                                   "/etc/spamassassin/")
        with patch("oa.server.os.path.exists", return_value=True):
            result = server.get_user_ruleset(user="alex")
        parser = self.mock_parser.return_value
        self.assertEqual(result, parser.get_ruleset.return_value)

    def test_user_ruleset_user_file_parsed(self):
        self.conf["allow_user_rules"] = True
        server = oa.server.Server(("0.0.0.0", 783), "/dev/null",
                                   "/etc/spamassassin/")
        with patch("oa.server.os.path.exists", return_value=True):
            result = server.get_user_ruleset(user="alex")
        parser = self.mock_parser.return_value
        parser.parse_file.assert_called_with(
            "/home/alex/.spamassassin/user_prefs"
        )

    def test_user_ruleset_user_cached(self):
        self.conf["allow_user_rules"] = True
        server = oa.server.Server(("0.0.0.0", 783), "/dev/null",
                                   "/etc/spamassassin/")
        cached_result = Mock()
        server._user_rulesets["alex"] = cached_result

        result = server.get_user_ruleset(user="alex")
        self.assertEqual(result, cached_result)



def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestServer, "test"))
    test_suite.addTest(unittest.makeSuite(TestPreForkServer, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
