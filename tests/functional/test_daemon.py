"""Test the daemon protocol."""
import os
import time
import email
import socket
import shutil
import unittest
import subprocess

PRE_CONFIG = r"""
# Plugins and settings here
loadplugin Mail::SpamAssassin::Plugin::Check
"""

CONFIG = r"""
# Rule definitions here
body GTUBE      /XJS\*C4JDBQADN1\.NSBN3\*2IDNEN\*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL\*C\.34X/
describe GTUBE  Generic Test for Unsolicited Bulk Email
score GTUBE     1000
"""

GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"

MULTIPART_MSG = r"""From: Marco Antonio Islas Cruz <marco@seinternal.com>
Content-Type: multipart/alternative;
    boundary="Apple-Mail=_9311E301-2E56-423D-B730-30A522F3844C"
X-Smtp-Server: smtp.gmail.com:marco@seinternal.com
Subject: Non text email
X-Universally-Unique-Identifier: 6c318f30-bec6-49cf-a37c-e651b9ce970e
Message-Id: <FC768970-9D08-4702-B0BF-9ED7A21F9D97@islascruz.org>
To: Marco antonio Islas Cruz <marco@seinternal.com>
Mime-Version: 1.0 (Apple Message framework v1257)


--Apple-Mail=_9311E301-2E56-423D-B730-30A522F3844C
Content-Type: multipart/related;
    type="text/html";
    boundary="Apple-Mail=_7F2342CA-8904-478A-B198-D63EE91D8288"


--Apple-Mail=_7F2342CA-8904-478A-B198-D63EE91D8288
Content-Transfer-Encoding: 7bit
Content-Type: text/html;
    charset=us-ascii

<html><head></head><body style="word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; "><div>This is a test?</div><div><br></div><img id="7c666adc-282a-46d4-9f3c-adce8a02b0be" height="339" width="530" apple-width="yes" apple-height="yes" src="cid:40808429-84C6-4DB6-982E-451F05730FE0@ubuntu"><br><br>
Testing rule one-two-three
<br></body></html>
--Apple-Mail=_9311E301-2E56-423D-B730-30A522F3844C--
"""


class TestDaemon(unittest.TestCase):

    daemon_script = "scripts/padd.py"
    # Uncomment this to test under spamd
    # daemon_script = "spamd"
    test_conf = os.path.abspath("tests/test_padd_conf/")
    pre_config = PRE_CONFIG
    port = 30783
    config = CONFIG
    padd_procs = []
    content_len = len(GTUBE)
    multipart_content_len = len(MULTIPART_MSG)

    @classmethod
    def setUpClass(cls):
        super(TestDaemon, cls).setUpClass()
        cls.padd_procs =[]
        try:
            os.makedirs(cls.test_conf)
        except:
            pass
        with open(os.path.join(cls.test_conf, "v320.pre"), "w") as pref:
            pref.write(cls.pre_config)
        with open(os.path.join(cls.test_conf, "10.cf"), "w") as conf:
            conf.write(cls.config)
        args = [cls.daemon_script, "-D", "-C", cls.test_conf, "--siteconfigpath",
                cls.test_conf, "-i", "127.0.0.1", "-p", str(cls.port)]
        if cls.daemon_script == "scripts/padd.py":
            args.append("--log-file")
            args.append(os.path.abspath("padd.log"))
        cls.padd_procs.append(subprocess.Popen(args))
        # Allow time for server to initialize
        time.sleep(1.0)

    @classmethod
    def tearDownClass(cls):
        super(TestDaemon, cls).tearDownClass()
        for padd_proc in cls.padd_procs:
            padd_proc.terminate()
            padd_proc.wait()
        shutil.rmtree(cls.test_conf, True)

    def setUp(self):
        unittest.TestCase.setUp(self)

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def send_to_proc(self, text):
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(5)
        connection.connect(("localhost", self.port))
        connection.send(text.encode("utf8"))
        response = []
        while True:
            try:
                data = connection.recv(1024)
            except socket.error as e:
                self.fail(e)
            if not data:
                break
            response.append(data.decode("utf8"))
        connection.close()
        # Strip the SPAMD/<version> part of the response
        return "".join(response).split(None, 1)[1]

    def test_ping(self):
        """Return a confirmation that padd.py/spamd is alive."""
        process = "PING"
        command = "%s SPAMC/1.2\r\n" % process
        result = self.send_to_proc(command)
        self.assertEqual(result, "0 PONG\r\n")

    def test_process(self):
        """Process this message as described above and return modified message"""
        expected_headers = ['message/rfc882; x-spam-type="original"', "inline", "original message before SpamPAD"]
        process_row = "PROCESS"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = "%s SPAMC/1.2\r\n" % process_row + content_row + "\r\n" + GTUBE
        result = self.send_to_proc(command).split("\r\n", 4)[4]
        msg = email.message_from_string(result)
        first_msg = list(msg.walk())[2]["Content-Type"]
        sec_msg = list(msg.walk())[2]["Content-Disposition"]
        third_msg = list(msg.walk())[2]["Content-Description"]
        body = list(msg.walk())[3].get_payload(decode=True)
        self.assertEqual(first_msg, expected_headers[0])
        self.assertEqual(sec_msg, expected_headers[1])
        self.assertEqual(third_msg, expected_headers[2])
        self.assertEqual(body, GTUBE)

    def test_check_spam(self):
        """Just check if the passed message is spam and verify the result"""
        msg = "Subject: test\n\n%s" % GTUBE

        process_row = "CHECK"
        content_row = "Content-length: %s\r\n" % len(msg)
        command = "%s SPAMC/1.2\r\n" % process_row + content_row + "\r\n" + msg
        result = self.send_to_proc(command).split("\r\n", 4)
        expected = [u'0 EX_OK', u'Spam: True ; 1000.0 / 5', u'Content-length: 0', u'', u'']
        self.assertEqual(result, expected)

    def test_symbols(self):
        """Check if message is spam or not, and return score plus list of symbols hit"""
        process_row = "SYMBOLS"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = "%s SPAMC/1.2\r\n" % process_row + content_row + "\r\n" + GTUBE
        result = self.send_to_proc(command).split("\r\n")
        expected = [u'0 EX_OK', u'Spam: True ; 1000.0 / 5', u'Content-length: 5', u'', u'GTUBE']
        self.assertEqual(result, expected)

    def test_report(self):
        """Check if message is spam or not, and return score plus report"""
        process_row = "REPORT"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = "%s SPAMC/1.2\r\n" % process_row + content_row + "\r\n" + GTUBE
        result = self.send_to_proc(command).split("\r\n")
        expected = [u'0 EX_OK',
                    u'Spam: True ; 1000.0 / 5',
                    u'Content-length: 28',
                    u'',
                    u'\n(no report template found)\n']
        self.assertEqual(expected, result)

    def test_report_if_spam(self):
        """Check if message is spam or not, and return score plus report if the message is spam"""
        process_row = "REPORT_IFSPAM"
        content_row = "Content-length: %s\r\n" % self.multipart_content_len
        command = "%s SPAMC/1.2\r\n" % process_row + content_row + "\r\n" + MULTIPART_MSG
        result = self.send_to_proc(command).split("\r\n")
        expected = [u'0 EX_OK', u'Spam: False ; 0 / 5', u'Content-length: 0', u'', u'']
        self.assertEqual(expected, result)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestDaemon, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
