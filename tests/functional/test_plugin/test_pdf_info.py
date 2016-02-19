"""Test the image_info plugin"""
import email
import os
import unittest
import tests.util

TESTDATA_DIR = os.path.join(os.getcwd(), "tests", "functional",
                            "test_plugin", "test_data")

CONFIG = r"""
body PDF_COUNT  eval:pdf_count(1,5)
body PDF_IMAGE_COUNT  eval:pdf_image_count(2,5)
body PDF_PIXEL_COVERAGE  eval:pdf_pixel_coverage(100,150)
body PDF_NAMED  eval:pdf_named("test")
body PDF_NAME_REGEX  eval:pdf_name_regex(".*test,*")
body PDF_MATCH_MD5  eval:pdf_match_md5("test")
body PDF_MATCH_DETAILS  eval:pdf_match_details(<detail>,<regex>);
body PDF_ENCRYPTED eval:pdf_is_encrypted()
body PDF_EMPTY_BODY eval:pdf_is_empty_body(10)
"""


class TestPDFInfoPlugin(tests.util.TestBase):
    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    @unittest.SkipTest
    def test_real_msg_with_errors(self):
        """Check real multipart message"""
        cwd = os.path.join(os.getcwd(), "pad", "plugins", "pdf_info.py")
        self.setup_conf(CONFIG + "\n",
                pre_config="loadplugin PDFInfoPlugin {0}\n"
                "report _SCORE_".format(cwd))
        with open(os.path.join(TESTDATA_DIR, "testmail.eml")) as m:
            msg = email.message_from_file(m)
            result = self.check_pad(msg.as_string())
        self.assertEqual(result, '0.0')


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestPDFInfoPlugin, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
