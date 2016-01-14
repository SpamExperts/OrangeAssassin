"""Unittest for scripts.padd"""

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

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_normal(self):
        scripts.padd.main()
        self.mock_s.assert_called_with(
            ("0.0.0.0", 783), '/etc/mail/spamassassin',
            '/usr/share/spamassassin', paranoid=False,
            ignore_unknown=True,
        )
        self.mock_s.return_value.serve_forever.assert_called_with()

    def test_preforked(self):
        self.argv.append("--prefork=6")
        scripts.padd.main()
        self.mock_pfs.assert_called_with(
            ("0.0.0.0", 783), '/etc/mail/spamassassin',
            '/usr/share/spamassassin', paranoid=False,
            ignore_unknown=True, prefork=6
        )
        self.mock_pfs.return_value.serve_forever.assert_called_with()


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestDaemon, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
