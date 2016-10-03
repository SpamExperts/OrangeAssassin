"""Functional tests tflags option"""

from __future__ import absolute_import
import unittest
import tests.util

PRE_CONFIG = """report _SCORE_
report _TESTS_
"""

CONFIG = """full    LOOK_FOR_TEST   /test/
describe LOOK_FOR_TEST This rule check for word 'test' in the whole email
"""


class TestFunctionalTflags(tests.util.TestBase):
    """Class containing functional tests for tflags option"""

    def test_tflags_nice_option_with_default_score(self):

        my_conf="""tflags LOOK_FOR_TEST nice"""

        email = """This is a test"""

        self.setup_conf(config=CONFIG + my_conf, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, -1, ['LOOK_FOR_TEST'])

    def test_tflags_nice_option_with_custom_score(self):

        my_conf="""tflags LOOK_FOR_TEST nice
        \nscore LOOK_FOR_TEST 5"""

        email = """This is a test"""

        self.setup_conf(config=CONFIG + my_conf, pre_config=PRE_CONFIG )
        result = self.check_pad(email)
        self.check_report(result, 5, ['LOOK_FOR_TEST'])

    def test_tflags_net_option_with_local_check(self):
        opt = """use_network 0\n"""

        my_conf="""tflags LOOK_FOR_TEST net"""

        email = """This is a test"""

        self.setup_conf(config=CONFIG + opt + my_conf, pre_config=PRE_CONFIG )
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_tflags_net_option_with_network_check(self):
        opt = """use_network 1\n"""

        my_conf="""tflags LOOK_FOR_TEST net"""

        email = """This is a test"""

        self.setup_conf(config=CONFIG + opt + my_conf, pre_config=PRE_CONFIG )
        result = self.check_pad(email)
        self.check_report(result, 1, ['LOOK_FOR_TEST'])



    def suite():
        """Gather all the tests from this package in a test suite."""
        test_suite = unittest.TestSuite()
        test_suite.addTest(unittest.makeSuite(TestFunctionalTflags, "test"))
        return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
