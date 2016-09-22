"""Functional tests the FreeMail Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

# Load FreeMail plugin and report SCORE and matching RULES
PRE_CONFIG = """loadplugin pad.plugins.free_mail.FreeMail
report _SCORE_
report _TESTS_
"""

# Define rules used for testing
CONFIG = """
header CHECK_FREEMAIL_FROM          eval:check_freemail_from()
header CHECK_FREEMAIL_FROM_REGEX    eval:check_freemail_from('\d@')

header CHECK_FREEMAIL_BODY          eval:check_freemail_body()
header CHECK_FREEMAIL_BODY_REGEX    eval:check_freemail_body('\d@')

header CHECK_FREEMAIL_HEADER        eval:check_freemail_header('From')
header CHECK_FREEMAIL_HEADER_REGEX  eval:check_freemail_header('From', '\d@')
"""

class TestFunctionalFreeMaill(tests.util.TestBase):

	def test_check_freemail_match_domain(self):
		lists = """freemail_domains example.com"""

		email = """From: sender@example.com
		\nBody contains sender@example.com"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 3, ['CHECK_FREEMAIL_FROM', 'CHECK_FREEMAIL_BODY',
            'CHECK_FREEMAIL_HEADER'])

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalFreeMail, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
