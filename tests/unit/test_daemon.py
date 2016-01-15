"""Unittest for scripts.padd"""

import signal
import unittest

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call


import scripts.padd


class TestDaemon(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        patch("scripts.padd.pad.config.setup_logging").start()
        self.mock_pfs = patch("scripts.padd.pad.server.PreForkServer").start()
        self.mock_s = patch("scripts.padd.pad.server.Server").start()
        self.argv = ["padd.py"]
        patch("scripts.padd.sys.exit", create=True).start()
        patch("scripts.padd.sys.argv", self.argv, create=True).start()
        patch("scripts.padd.pad.config.get_default_configs",
              return_value={"default": "/etc/mail/spamassassin",
                            "required": False}).start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_normal(self):
        scripts.padd.main()
        self.mock_s.assert_called_with(
            ("0.0.0.0", 783), '/etc/mail/spamassassin',
            '/etc/mail/spamassassin', paranoid=False,
            ignore_unknown=True,
        )
        self.mock_s.return_value.serve_forever.assert_called_with()

    def test_preforked(self):
        self.argv.append("--prefork=6")
        scripts.padd.main()
        self.mock_pfs.assert_called_with(
            ("0.0.0.0", 783), '/etc/mail/spamassassin',
            '/etc/mail/spamassassin', paranoid=False,
            ignore_unknown=True, prefork=6
        )
        self.mock_pfs.return_value.serve_forever.assert_called_with()


class TestAction(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_kill = patch("scripts.padd.os.kill").start()
        patch("scripts.padd.pad.config.setup_logging").start()
        patch("scripts.padd.os.path.exists", return_value=True).start()
        self.argv = ["padd.py"]
        patch("scripts.padd.sys.exit", create=True).start()
        patch("scripts.padd.sys.argv", self.argv, create=True).start()
        mock_o = patch("scripts.padd.open", create=True).start()
        fh = mock_o.return_value.__enter__.return_value
        fh.read.return_value = "1001"

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_reload(self):
        self.argv.append("reload")
        scripts.padd.main()
        self.mock_kill.assert_called_with(1001, signal.SIGUSR1)

    def test_stop(self):
        self.argv.append("stop")
        scripts.padd.main()
        self.mock_kill.assert_called_with(1001, signal.SIGTERM)




def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestDaemon, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
