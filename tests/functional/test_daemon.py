"""Test the daemon protocol."""
import os
import time
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


class TestDaemon(unittest.TestCase):

    daemon_script = "padd.py"
    # Uncomment this to test under spamd
    #daemon_script = "spamd"
    test_conf = os.path.abspath("test_padd_conf/")
    pre_config = PRE_CONFIG
    port = 784
    config = CONFIG
    padd_procs = []

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
        args = [cls.daemon_script, "-C", cls.test_conf, "--siteconfigpath",
                cls.test_conf, "-p", str(cls.port)]
        cls.padd_procs.append(subprocess.Popen(args))
        # Allow time for server to initialize
        time.sleep(0.5)

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
        connection.send(text)
        response = []
        while True:
            try:
                data = connection.recv(1024)
            except socket.error as e:
                return
            if not data:
                break
            response.append(data)
        # Strip the SPAMD/<version> part of the response
        return "".join(response).split(None, 1)[1]

    def test_ping(self):
        command = "PING SPAMC/1.2\r\n"
        result = self.send_to_proc(command)
        self.assertEqual(result, "0 PONG\r\n")


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestDaemon, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')