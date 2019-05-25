"""Tests for the Bayes plug-in."""

import email
import hashlib
import unittest

import mock
from mock import MagicMock

from oa.plugins.bayes import BayesPlugin


class BayesTests(unittest.TestCase):
    """Test cases for the BayesPlugin class."""

    def setUp(self):
        self.global_data = {}
        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)})
        engine = {
            "hostname":"",
            "user":"",
            "password":"",
            "db_name":"",
        }
        mock.patch("pad.plugins.bayes.BayesPlugin.get_engine", return_value=engine).start()

    def tearDown(self):
        mock.patch.stopall()


    def test_get_msgid(self):
        """Test the get_msgid method when there is a Message-ID header."""
        msg_id = "test-id"
        msg = email.message_from_string("Message-ID: <%s>\n\nTest" % msg_id)
        found_id = BayesPlugin(self.mock_ctxt).get_msgid(msg)
        self.assertEqual(msg_id, found_id)

    def test_get_msgid_generated(self):
        """Test the get_msgid method when there is no Message-ID header."""
        text = "Hello world!"
        msg = email.message_from_string("Subject: test\n\n%s" % text)
        found_id = BayesPlugin(self.mock_ctxt).get_msgid(msg)
        combined = "None\x00%s" % text
        msg_id = "%s@sa_generated" % hashlib.sha1(combined.encode('utf-8')).hexdigest()
        self.assertEqual(msg_id, found_id)

    def test_learn_message(self):
        """Test the learn_message method."""
        msgdata = {}
        b = BayesPlugin(self.mock_ctxt)
        b.get_body_from_msg = lambda x: msgdata
        b.store.tie_db_writeable = lambda: True
        ret = "test"
        msg = "test message"
        isspam = True
        b._learn_trapped = mock.MagicMock(return_value=ret)
        b.learn_caller_will_untie = True
        result = b.learn_message(msg, isspam)
        self.assertEqual(ret, result)
        b._learn_trapped.assert_called_once_with(isspam, msg, msgdata, None)

    def test_learn_message_no_bayes(self):
        """Test the learn_message method when bayes is not enabled."""
        b = BayesPlugin(self.mock_ctxt)
        b["use_bayes"] = False
        result = b.learn_message(None, None)
        self.assertEqual(result, None)

    def test_receive_date(self):
        """Test the receive_date method."""
        msg = email.message_from_string("""Received: from server6.seinternal.com ([178.63.74.9])
 by mx99.antispamcloud.com with esmtps (TLSv1.2:DHE-RSA-AES128-SHA:128)
 (Exim 4.85) id 1azjrM-000RwX-P5
 for spam@mx99.antispamcloud.com; Mon, 09 May 2016 14:00:25 +0200\n\nHello world!""")
        expected = 1462795225
        result = BayesPlugin(self.mock_ctxt).receive_date(msg)
        self.assertEqual(expected, result)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(BayesTests, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
