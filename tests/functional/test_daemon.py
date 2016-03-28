"""Test the daemon protocol."""
from __future__ import print_function

import os
import sys
import time
import email
import socket
import shutil
import getpass
import unittest
import platform
import subprocess

PRE_CONFIG = r"""
# Plugins and settings here
loadplugin Mail::SpamAssassin::Plugin::Check
allow_user_rules True
"""

CONFIG = r"""
# Rule definitions here
body GTUBE      /XJS\*C4JDBQADN1\.NSBN3\*2IDNEN\*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL\*C\.34X/
describe GTUBE  Generic Test for Unsolicited Bulk Email
score GTUBE     1000
"""

GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"

TEST_MSG = """Subject: Email Flow Test
From: Geo <test@example.com>
To: jimi@example.com


This is a test message.


"""

GTUBE_MSG = """Subject: test

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X
"""

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

<html><head></head><body style="word-wrap: break-word; -webkit-nbsp-mode:
space; -webkit-line-break: after-white-space; "><div>This is a
test?</div><div><br></div><img id="7c666adc-282a-46d4-9f3c-adce8a02b0be"
height="339" width="530" apple-width="yes" apple-height="yes"
src="cid:40808429-84C6-4DB6-982E-451F05730FE0@ubuntu"><br><br>
Testing rule one-two-three
<br></body></html>
--Apple-Mail=_9311E301-2E56-423D-B730-30A522F3844C--
"""

USER_CONFIG = r"""
body CUSTOM_RULE /abcdef123456/
score CUSTOM_RULE 5
"""

USER_TEST_MSG = """Subject: Email Flow Test
From: Geo <test@example.com>
To: jimi@example.com

This is a abcdef123456 test message.

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
    content_len = len(GTUBE_MSG) + 2
    multipart_content_len = len(MULTIPART_MSG)
    len_test_msg = len(TEST_MSG)

    @classmethod
    def setUpClass(cls):
        super(TestDaemon, cls).setUpClass()
        cls.padd_procs = []
        try:
            os.makedirs(cls.test_conf)
        except:
            pass
        with open(os.path.join(cls.test_conf, "v320.pre"), "w") as pref:
            pref.write(cls.pre_config)
        with open(os.path.join(cls.test_conf, "10.cf"), "w") as conf:
            conf.write(cls.config)
        args = [cls.daemon_script, "-D", "-C", cls.test_conf,
                "--siteconfigpath", cls.test_conf, "--allow-tell",
                "-i", "127.0.0.1", "-p", str(cls.port)]
        if cls.daemon_script == "scripts/padd.py":
            args.append("--log-file")
            args.append(os.path.abspath("padd.log"))
        cls.padd_procs.append(subprocess.Popen(args))
        # Allow time for server to initialize
        sleep_time = 1.0
        if platform.python_implementation().lower() == "pypy":
            # PyPy is much slower at initialization, so allow
            # for more time. This is only ran once so the impact
            # is minimal anyway.
            # This should prevent random test failures on PyPy.
            sleep_time = 2.0
        time.sleep(sleep_time)

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
        try:
            # Strip the SPAMD/<version> part of the response
            return "".join(response).split(None, 1)[1]
        except IndexError:
            self.fail("Failed to parse response: %r" % response)

    def test_ping(self):
        """Return a confirmation that padd.py/spamd is alive."""
        process = "PING"
        command = "%s SPAMC/1.2\r\n" % process
        result = self.send_to_proc(command)
        self.assertEqual(result, "0 PONG\r\n")

    def test_ping_error(self):
        """Check unknown process input error"""
        process = "PINasdfG"
        command = "%s SPAMC/1.2\r\n" % process
        result = self.send_to_proc(command)
        self.assertEqual(result, u'76 Bad header line: PINasdfG SPAMC/1.2\r\n')

    def test_process_content_type(self):
        """Process this message as described above and return modified
        message"""
        process_row = "PROCESS"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command).split("\r\n\r\n", 1)[1]
        msg = email.message_from_string(result)

        first_msg = list(msg.walk())[2]["Content-Type"]
        self.assertEqual(first_msg, 'message/rfc882; x-spam-type="original"')

    def test_process_content_type_non_spam(self):
        """Process this multipart-message and return the content-type
        message"""
        process_row = "PROCESS"
        content_row = "Content-length: %s\r\n" % self.multipart_content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, MULTIPART_MSG))
        result = self.send_to_proc(command).split("\r\n\r\n", 1)[1]
        msg = email.message_from_string(result)

        content_type = list(msg.walk())[1]["Content-Type"]
        content_type = [part.strip() for part in content_type.split(";")]
        self.assertEqual(content_type, [
            'multipart/related',
            'type="text/html"',
            'boundary="Apple-Mail=_7F2342CA-8904-478A-B198-D63EE91D8288"'
        ])

    def test_process_content_disposition(self):
        """Process this message as described above and return content
        disposition """
        process_row = "PROCESS"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command).split("\r\n\r\n", 1)[1]
        msg = email.message_from_string(result)

        sec_msg = list(msg.walk())[2]["Content-Disposition"]

        self.assertEqual(sec_msg, "inline")

    def test_process_content_encoding_non_spam(self):
        """Process this multi-part message and return the content transfer
         encoding"""
        process_row = "PROCESS"
        content_row = "Content-length: %s\r\n" % self.multipart_content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, MULTIPART_MSG))
        result = self.send_to_proc(command).split("\r\n\r\n", 1)[1]
        msg = email.message_from_string(result)

        sec_msg = list(msg.walk())[2]["Content-Transfer-Encoding"]

        self.assertEqual(sec_msg, "7bit")

    def test_process_content_disposition2_spam(self):
        process_row = "PROCESS"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command).split("\r\n\r\n", 1)[1]
        msg = email.message_from_string(result)

        third_msg = list(msg.walk())[2]["Content-Description"]

        self.assertEqual(third_msg, "original message before SpamPAD")

    def test_process_content_body_spam(self):
        process_row = "PROCESS"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command).split("\r\n\r\n", 1)[1]
        msg = email.message_from_string(result)

        body = list(msg.walk())[3].get_payload(decode=True)
        self.assertEqual(body.strip(), GTUBE.encode("utf8"))

    def test_process_content_len_error(self):
        """Check invalid content-length input error"""
        process_row = "PROCESS"
        missing = ''
        content_row = "Content-length: %s\r\n" % missing
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command)
        expected = u'76 Bad header line: (Content-Length contains non-numeric bytes)\r\n'
        self.assertEqual(result, expected)

    def test_process_content_body_non_spam(self):
        process_row = "PROCESS"
        content_row = "Content-length: %s\r\n" % self.len_test_msg
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, TEST_MSG))
        result = self.send_to_proc(command).split("\r\n\r\n", 1)[1]
        msg = email.message_from_string(result)

        body = list(msg.walk())[0].get_payload(decode=True)
        self.assertEqual(body, b"\nThis is a test message.\n\n\n")

    def test_check_spam(self):
        """Just check if the passed message is spam and verify the result"""
        process_row = "CHECK"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command).split("\r\n", 4)
        expected = [u'0 EX_OK', u'Spam: True ; 1000.0 / 5.0',
                    u'Content-length: 0', u'', u'']
        self.assertEqual(result, expected)

    def test_check_content_len_error(self):
        """Check invalid content-length input error"""
        process_row = "CHECK"
        content_row = "Content-length: %s\r\n" % '-100000'
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command)
        expected = u'76 Bad header line: (Content-Length contains non-numeric bytes)\r\n'
        self.assertEqual(result, expected)

    def test_check_non_spam(self):
        """Just check if the passed message isn't spam and verify the result"""
        process_row = "CHECK"
        content_row = "Content-length: %s\r\n" % self.len_test_msg
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, TEST_MSG))
        result = self.send_to_proc(command).split("\r\n", 4)
        expected = [u'0 EX_OK',
                    u'Spam: False ; 0 / 5.0',
                    u'Content-length: 0',
                    u'',
                    u'']
        self.assertEqual(result, expected)

    def test_symbols_spam(self):
        """Check if message is spam or not, and return score plus list of
        symbols hit"""
        process_row = "SYMBOLS"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command).split("\r\n")
        expected = [u'0 EX_OK',
                    u'Spam: True ; 1000.0 / 5.0',
                    u'Content-length: 5',
                    u'', u'GTUBE']
        self.assertEqual(result, expected)

    def test_symbols_missing_key_content_error(self):
        """Check missing ":" in content-length input error"""

        process_row = "SYMBOLS"
        content_row = "Content-length %s\r\n" % self.content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command)
        expected = u"76 Bad header line: (header not in 'Name: value' format)\r\n"
        self.assertEqual(result, expected)

    def test_symbols_bad_header_line(self):
        """Check bad command sent scenario """
        process_row = "SYMBOL"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command)
        expected = u"76 Bad header line: SYMBOL SPAMC/1.2\r\n"
        self.assertEqual(result, expected)

    def test_symbols_non_spam(self):
        """Check if message is spam or not, and return score plus list of
        symbols hit"""
        process_row = "SYMBOLS"
        content_row = "Content-length: %s\r\n" % self.len_test_msg
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, TEST_MSG))
        result = self.send_to_proc(command).split("\r\n")
        expected = [u'0 EX_OK',
                    u'Spam: False ; 0 / 5.0',
                    u'Content-length: 0',
                    u'',
                    u'']
        self.assertEqual(result, expected)

    def test_report_spam(self):
        """Check if message is spam or not, and return score plus report"""
        process_row = "REPORT"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command)
        expected = [u'0 EX_OK',
                    u'Spam: True ; 1000.0 / 5.0',
                    u'Content-length: 28',
                    u'',
                    u'\n(no report template found)\n']
        expected = "\r\n".join(expected)
        self.assertEqual(expected, result)

    def test_report_if_spam(self):
        """Check if message is not spam, and see no score plus report"""
        process_row = "REPORT_IFSPAM"
        content_row = "Content-length: %s\r\n" % self.multipart_content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, MULTIPART_MSG))
        result = self.send_to_proc(command).split("\r\n")
        expected = [u'0 EX_OK',
                    u'Spam: False ; 0 / 5.0',
                    u'Content-length: 0',
                    u'', u'']
        self.assertEqual(expected, result)

    def test_report_if_spam_true(self):
        """Check if message is spam, and return score plus report if
        the message is spam"""
        process_row = "REPORT_IFSPAM"
        content_row = "Content-length: %s\r\n" % self.content_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, GTUBE_MSG))
        result = self.send_to_proc(command)
        expected = [u'0 EX_OK',
                    u'Spam: True ; 1000.0 / 5.0',
                    u'Content-length: 28',
                    u'',
                    u'\n(no report template found)\n']
        expected = "\r\n".join(expected)
        self.assertEqual(expected, result)

    def test_tell_spam(self):
        command = ("TELL SPAMC/1.2\r\n"
                   "Message-class: spam\r\n"
                   "Set: local\r\n"
                   "Content-length: %s\r\n\r\n%s\r\n" %
                   (self.content_len, GTUBE_MSG))
        result = self.send_to_proc(command)
        expected = u"0 EX_OK\r\nDidSet: local\r\n"
        self.assertEqual(expected, result)

    def test_tell_remove_spam(self):
        command = ("TELL SPAMC/1.2\r\n"
                   "Message-class: spam\r\n"
                   "Remove: local\r\n"
                   "Content-length: %s\r\n\r\n%s\r\n" %
                   (self.content_len, GTUBE_MSG))
        result = self.send_to_proc(command)
        expected = u"0 EX_OK\r\nDidRemove: local\r\n"
        self.assertEqual(expected, result)

    def test_tell_report_spam(self):
        command = ("TELL SPAMC/1.2\r\n"
                   "Message-class: spam\r\n"
                   "Set: local, remove\r\n"
                   "Content-length: %s\r\n\r\n%s\r\n" %
                   (self.content_len, GTUBE_MSG))
        result = self.send_to_proc(command)
        expected = u"0 EX_OK\r\nDidSet: local, remove\r\n"
        self.assertEqual(expected, result)

    def test_tell_revoke_ham(self):
        command = ("TELL SPAMC/1.2\r\n"
                   "Message-class: spam\r\n"
                   "Set: local\r\n"
                   "Remove: remote\r\n"
                   "Content-length: %s\r\n\r\n%s\r\n" %
                   (self.content_len, GTUBE_MSG))
        result = self.send_to_proc(command)
        expected = u'0 EX_OK\r\nDidSet: local\r\nDidRemove: remote\r\n'
        self.assertEqual(expected, result)


class TestUserConfigDaemon(TestDaemon):
    """This runs the ALL the tests from TestDaemon but
    appends always send the User: with each request.

    Apart from the tests from TestDaemon this also has some tests
    specific to the User Preferences.
    """

    username = getpass.getuser()
    user_pref = USER_CONFIG
    user_dir = os.path.join("/home", username, ".spamassassin")
    user_msg_len = len(USER_TEST_MSG) + 2

    @classmethod
    def setUpClass(cls):
        super(TestUserConfigDaemon, cls).setUpClass()
        try:
            os.makedirs(cls.user_dir)
        except OSError as e:
            print(e, file=sys.stderr)
        with open(os.path.join(cls.user_dir, "user_prefs"), "w") as userf:
            userf.write(cls.user_pref)

    @classmethod
    def tearDownClass(cls):
        super(TestUserConfigDaemon, cls).tearDownClass()
        try:
            shutil.rmtree(cls.user_dir)
        except OSError:
            pass

    def send_to_proc(self, text):
        """Like the super method but also add the username to
        the request.
        """
        try:
            command, body = text.split("\r\n\r\n", 1)
            text = "%s\r\nUser: %s\r\n\r\n%s" % (command, self.username, body)
        except ValueError:
            text = "%s\r\nUser: %s\r\n" % (text.strip(), self.username)

        return super(TestUserConfigDaemon, self).send_to_proc(text)

    def test_user_msg_symbols_spam(self):
        """Check if message is spam or not, and return score plus list of
        symbols hit"""
        process_row = "SYMBOLS"
        content_row = "Content-length: %s\r\n" % self.user_msg_len
        command = ("%s SPAMC/1.2\r\n%s\r\n%s\r\n" %
                   (process_row, content_row, USER_TEST_MSG))
        result = self.send_to_proc(command).split("\r\n")
        expected = [u'0 EX_OK',
                    u'Spam: True ; 5.0 / 5.0',
                    u'Content-length: 11',
                    u'', u'CUSTOM_RULE']
        self.assertEqual(result, expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestDaemon, "test"))
    test_suite.addTest(unittest.makeSuite(TestUserConfigDaemon, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
