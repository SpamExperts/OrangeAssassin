"""Test the image_info plugin"""
import email
import os
import unittest
import tests.util

TESTDATA_DIR = os.path.join(os.getcwd(), "tests", "data")

CONFIG = r"""
body        MPART_ALT_DIFF      eval:multipart_alternative_difference('99', '100')
describe    MPART_ALT_DIFF      HTML and text parts are different

body        MPART_ALT_DIFF_COUNT    eval:multipart_alternative_difference_count('3', '1')
describe    MPART_ALT_DIFF_COUNT    HTML and text parts are different

body        MPART_CHECK_BLANK_LINE      eval:check_blank_line_ratio('10', '20', minlines=1)
body        MPART_TVD_VERT_WORDS      eval:tvd_vertical_words(2, 15)
body        MPART_CHECK_STOCK_INFO      eval:check_stock_info('10')
"""


class TestBodyEval(tests.util.TestBase):
    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    def test_real_msg_with_errors(self):
        """Check real multipart message"""
        self.setup_conf(CONFIG + "\n",
                pre_config="loadplugin pad.plugins.body_eval.BodyEval\n"
                "report _SCORE_")
        with open(os.path.join(TESTDATA_DIR, "testmail.eml")) as m:
            msg = email.message_from_file(m)
            result = self.check_pad(msg.as_string())
        self.assertEqual(result, '0.0')


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestBodyEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
