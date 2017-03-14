"""Unittest for scripts.padd"""

import signal
import unittest

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call


import scripts.oad


class TestDaemon(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        patch("scripts.padd.oa.config.setup_logging").start()
        self.mock_pfs = patch("scripts.padd.oa.server.PreForkServer").start()
        self.mock_s = patch("scripts.padd.oa.server.Server").start()
        self.argv = ["oad.py"]
        patch("scripts.padd.sys.exit", create=True).start()
        patch("scripts.padd.sys.argv", self.argv, create=True).start()
        patch("scripts.padd.oa.config.get_default_configs",
              return_value={"default": "/etc/mail/spamassassin",
                            "required": False}).start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_normal(self):
        scripts.oad.main()
        self.mock_s.assert_called_with(
            ("0.0.0.0", 783), '/etc/mail/spamassassin',
            '/etc/mail/spamassassin', paranoid=False,
            ignore_unknown=True,
        )
        self.mock_s.return_value.serve_forever.assert_called_with()

    def test_preforked(self):
        self.argv.append("--prefork=6")
        scripts.oad.main()
        self.mock_pfs.assert_called_with(
            ("0.0.0.0", 783), '/etc/mail/spamassassin',
            '/etc/mail/spamassassin', paranoid=False,
            ignore_unknown=True
        )
        self.assertEqual(self.mock_pfs.return_value.prefork, 6)
        self.mock_pfs.return_value.serve_forever.assert_called_with()


class TestAction(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_send = patch("scripts.padd.spoon.daemon.send_action").start()
        patch("scripts.padd.oa.config.setup_logging").start()
        patch("scripts.padd.os.path.exists", return_value=True).start()
        self.argv = ["oad.py"]
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
        scripts.oad.main()
        self.mock_send.assert_called_with("reload", "/var/run/padd.pid")

    def test_stop(self):
        self.argv.append("stop")
        scripts.oad.main()
        self.mock_send.assert_called_with("stop", "/var/run/padd.pid")




def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestDaemon, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
