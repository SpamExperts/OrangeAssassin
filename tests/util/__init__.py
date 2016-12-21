"""Utilities for tests."""
from __future__ import print_function
from __future__ import absolute_import

import os
import sys
import shutil
import unittest
import subprocess


DEFAULT_PRE_CONFIG = ""
SYMBOLS_PRE_CONFIG = r"""
# report the matched TESTS and score
report _SCORE_
report _TESTS_
"""
DEFAULT_CONFIG = r"""
# Just a simple rule for GTUBE.
body GTUBE      /XJS\*C4JDBQADN1\.NSBN3\*2IDNEN\*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL\*C\.34X/
describe GTUBE  Generic Test for Unsolicited Bulk Email
score GTUBE     1000
"""

GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"


class TestBase(unittest.TestCase):
    match_script = "scripts/match.py"
    compile_script = "scripts/compile.py"
    # Uncomment this to test under SA
    # match_script = "spamassassin"
    test_conf = os.path.abspath("tests/test_match_conf/")
    # Add this at the beginning of the report to
    # easily split the message from the report.
    report_start = "---=PAD report start=---"

    def setUp(self):
        unittest.TestCase.setUp(self)
        try:
            os.makedirs(self.test_conf)
        except OSError:
            pass
        try:
            os.makedirs(os.path.expanduser("~/.spamassassin"))
        except OSError:
            pass

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        try:
            shutil.rmtree(self.test_conf, True)
        except OSError:
            pass

    def setup_conf(self, config=DEFAULT_CONFIG, pre_config=DEFAULT_PRE_CONFIG):
        """Setup the configuration folder with the specified
        options
        """
        with open(os.path.join(self.test_conf, "v310.pre"), "w") as conf:
            conf.write("loadplugin Mail::SpamAssassin::Plugin::Check\n")
            conf.write("report %s\n" % self.report_start)
        with open(os.path.join(self.test_conf, "v320.pre"), "w") as pref:
            pref.write(pre_config)
        with open(os.path.join(self.test_conf, "20.cf"), "w") as conf:
            conf.write(config)

    def check_pad(self, message, message_only=False, report_only=True,
                  extra_args=None, debug=False, expect_failure=False, env=None):
        """Run the match script and return the result.

        :param message: Pipe this message to the script
        :param report_only: If set to True then only return the
         report only. Otherwise return the message and report.
        :param my_env: Used for setting environment variables to subprocess
        :return: The result of the script.
        """

        if debug:
            args = [self.match_script, "-D", "-t", "-C", self.test_conf,
                    "--siteconfigpath", self.test_conf]
        else:
            args = [self.match_script, "-t", "-C", self.test_conf,
                    "--siteconfigpath", self.test_conf]

        if os.environ.get("USE_PICKLES") == "1":
            compile_args = [self.compile_script, "-t", "-C", self.test_conf,
                    "--siteconfigpath", self.test_conf]
            args.append("-se")

        if extra_args is not None:
            args.extend(extra_args)

        if os.environ.get("USE_PICKLES") == "1":
            proc_compile = subprocess.Popen(compile_args,
                                            stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE,
                                            env=env)
            stdout, stderr = proc_compile.communicate()
            if stderr or proc_compile.returncode:
                self.fail(stderr)

        proc = subprocess.Popen(args,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                env=env)

        stdout, stderr = proc.communicate(message.encode("utf8"))


        if not debug and not expect_failure and stderr:
            self.fail(stderr)

        result = stdout.decode("utf8")
        if report_only:
            try:
                return result.rsplit(self.report_start, 1)[1].strip()
            except IndexError:
                self.fail("Failed: %s %s" % (stdout, stderr))
        if message_only:
            try:
                return result.rsplit(self.report_start, 1)[0].strip()
            except IndexError:
                self.fail("Failed: %s %s" % (stdout, stderr))
        return result.strip()

    def profile_pad(self, name, short_name, msg, ptype="memory",
                    ilimit=None, elimit=None, plimit=None,
                    inclimit=None):
        match_args = ["--test-mode", "-C", self.test_conf,
                      "--siteconfigpath", self.test_conf]
        args = [
            sys.executable, "-m",
            "se_profile.profile",
            "-n", name,
            "-s", short_name,
            "-t", ptype,
            # "--debug"
            # "--per-file",
        ]
        if ilimit:
            args.extend([
                "--import-limit", str(ilimit)
            ])
        if elimit:
            args.extend([
                "--end-limit", str(elimit)
            ])
        if plimit:
            args.extend([
                "--peak-limit", str(plimit)
            ])
        if inclimit:
            args.extend([
                "--increment-limit", str(inclimit)
            ])

        args.extend([
            "-m", "scripts.match",
            "-p", " ".join(match_args)
        ])
        env = os.environ.copy()
        if "PYTHONPATH" not in env:
            ppath = [os.getcwd()]
        else:
            ppath = env["PYTHONPATH"].split(os.pathsep)
            ppath.append(os.getcwd())
        env["PYTHONPATH"] = os.pathsep.join(ppath)

        p = subprocess.Popen(args, env=env,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(msg.encode("utf8"))
        p.wait()
        print(stdout, file=sys.__stdout__)
        if p.returncode:
            self.fail(stdout + b'\n' + stderr)

    def check_report(self, result, expected_score=None, expected_symbols=None):
        """Check the report SYMBOLS_PRE_CONFIG for score
        and symbols.
        """
        try:
            score, symbols = result.split("\n", 1)
            score = float(score)
            symbols = [symbol for symbol in symbols.split(",")
                       if symbol.lower() != "none"]
        except ValueError:
            try:
                score = float(result.strip())
            except ValueError:
                self.fail("Unable to parse report: %r" % result)
            symbols = []
        if expected_score is not None:
            self.assertEqual(score, expected_score)
        if expected_symbols is not None:
            # The order is not important
            self.assertEqual(set(symbols), set(expected_symbols))

    def check_symbols(self, message, config=DEFAULT_CONFIG,
                      score=None, symbols=None):
        """Run the match script with the specified message
        and config. Uses the default TESTS and SCORE as
        report.

        Check that the match script returns the correct score
        and symbols.
        """
        self.setup_conf(config, SYMBOLS_PRE_CONFIG)
        result = self.check_pad(message)
        # print(result)
        self.check_report(result, score, symbols)
