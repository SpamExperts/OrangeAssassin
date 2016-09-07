"""Functional tests the SPF Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

# Load plugin and report matched RULES and SCORE
PRE_CONFIG = """
loadplugin pad.plugins.spf.SpfPlugin
report _SCORE_
report _TESTS_
"""

# Define rules for plugin
CONFIG = """
header SPF_PASS             eval:check_for_spf_pass()
header SPF_NEUTRAL          eval:check_for_spf_neutral()
header SPF_NONE             eval:check_for_spf_none()
header SPF_FAIL             eval:check_for_spf_fail()
header SPF_SOFTFAIL         eval:check_for_spf_softfail()
header SPF_PERMERROR        eval:check_for_spf_permerror()
header SPF_TEMPERROR        eval:check_for_spf_temperror()

header SPF_HELO_PASS        eval:check_for_spf_helo_pass()
header SPF_HELO_NEUTRAL     eval:check_for_spf_helo_neutral()
header SPF_HELO_NONE        eval:check_for_spf_helo_none()
header SPF_HELO_FAIL        eval:check_for_spf_helo_fail()
header SPF_HELO_SOFTFAIL    eval:check_for_spf_helo_softfail()
header SPF_HELO_PERMERROR   eval:check_for_spf_helo_permerror()
header SPF_HELO_TEMPERROR   eval:check_for_spf_helo_temperror()

header CHECK_FOR_SPF_WHITELIST        eval:check_for_spf_whitelist_from()
header CHECK_FOR_DEF_SPF_WHITELIST    eval:check_for_def_spf_whitelist_from()
"""

class TestFunctionalSPF(tests.util.TestBase):
	"""Class containing functional tests for the FreeMail Plugin"""

	def test_spf_pass(self):
		#check_for_spf_pass in Received-SPF header

		email="""Received-SPF: pass (example.com: domain of test@example.com)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_PASS'])

	def test_spf_neutral(self):
		#check_for_spf_neutral in Received-SPF header

		email="""Received-SPF: neutral (example.com: domain of test@example.com)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_NEUTRAL'])

	def test_spf_none(self):
		#check_for_spf_none in Received-SPF header

		email="""Received-SPF: none (example.com: domain of test@example.com)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_NONE'])

	def test_spf_fail(self):
		#check_for_spf_fail in Received-SPF header

		email="""Received-SPF: fail (example.com: domain of test@example.com)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_FAIL'])

	def test_spf_softfail(self):
		#check_for_spf_softfail in Received-SPF header

		email="""Received-SPF: softfail (example.com: domain of test@example.com)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_SOFTFAIL'])

	def test_spf_permerror(self):
		#check_for_spf_permerror in Received-SPF header

		email="""Received-SPF: permerror (example.com: domain of test@example.com)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_PERMERROR'])

	def test_spf_temperror(self):
		#check_for_spf_temperror in Received-SPF header

		email="""Received-SPF: temperror (example.com: domain of test@example.com)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_TEMPERROR'])

	def test_spf_no_spf_result(self):

		email="""Received-SPF:(example.com: domain of test@example.com)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 0, [])

	def test_spf_helo_pass(self):
		#check_for_spf_helo_pass in Received-SPF header

		email="""Received-SPF: pass (example.com: domain of test@example.com) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_PASS'])

	def test_spf_helo_neutral(self):
		#check_for_spf_helo_neutral in Received-SPF header

		email="""Received-SPF: neutral (example.com: domain of test@example.com) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_NEUTRAL'])

	def test_spf_helo_none(self):
		#check_for_spf_helo_none in Received-SPF header

		email="""Received-SPF: none (example.com: domain of test@example.com) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_NONE'])

	def test_spf_helo_fail(self):
		#check_for_spf_helo_fail in Received-SPF header

		email="""Received-SPF: fail (example.com: domain of test@example.com) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_FAIL'])

	def test_spf_helo_softfail(self):
		#check_for_spf_helo_softfail in Received-SPF header

		email="""Received-SPF: softfail (example.com: domain of test@example.com) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_SOFTFAIL'])

	def test_spf_helo_permerror(self):
		#check_for_spf_helo_permerror in Received-SPF header

		email="""Received-SPF: permerror (example.com: domain of test@example.com) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_PERMERROR'])

	def test_spf_helo_temperror(self):
		#check_for_spf_helo_temperror in Received-SPF header

		email="""Received-SPF: temperror (example.com: domain of test@example.com) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_TEMPERROR'])

	def test_spf_pass_incorrect_helo(self):
		#check_for_spf_helo_pass in Received-SPF header

		email="""Received-SPF: pass (example.com: domain of test@example.com) identitate=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_PASS'])

	def test_spf_pass_with_newest_received_spf_method(self):

		lists = """use_newest_received_spf_header 1"""

		email="""Received-SPF: fail (example.com: domain of test@example.com) 
Received-SPF: pass (example.com: domain of test@example.com)
Received-SPF: none (example.com: domain of test@example.com)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_FAIL'])

	def test_spf_pass_with_default_newest_received_spf_method(self):

		lists = """use_newest_received_spf_header 0"""

		email="""Received-SPF: fail (example.com: domain of test@example.com) 
Received-SPF: pass (example.com: domain of test@example.com) 
Received-SPF: none (example.com: domain of test@example.com)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_NONE'])

	def test_spf_helo_pass_with_newest_received_spf_method(self):

		lists = """use_newest_received_spf_header 1"""

		email="""Received-SPF: fail (example.com: domain of test@example.com) identity=helo, 
Received-SPF: pass (example.com: domain of test@example.com) identity=helo
Received-SPF: none (example.com: domain of test@example.com) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_FAIL'])

	def test_spf_helo_pass_with_default_newest_received_spf_method(self):

		lists = """use_newest_received_spf_header 0"""

		email="""Received-SPF: fail (example.com: domain of test@example.com) identity=helo, 
Received-SPF: pass (example.com: domain of test@example.com) identity=helo
Received-SPF: none (example.com: domain of test@example.com) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_NONE'])

	def test_spf_helo_pass_with_incorrect_identity(self):

		email="""Received-SPF: fail (example.com: domain of test@example.com) identity=helo, 
Received-SPF: pass (example.com: domain of test@example.com) identity=hel"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_FAIL'])

	def test_spf_helo_pass_with_incorrect_identity_and_newest_received_spf_method(self):

		lists = """use_newest_received_spf_header 1"""

		email="""Received-SPF: fail (example.com: domain of test@example.com) identity=hel, 
Received-SPF: pass (example.com: domain of test@example.com) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_PASS'])

	def test_spf_multiple_match(self):

		email="""Received-SPF: fail (example.com: domain of test@example.com) 
Received-SPF: pass (example.com: domain of test@example.com) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_HELO_PASS', 'SPF_FAIL'])

	def test_spf_pass_other_identity(self):

		email="""Received-SPF: pass (example.com: domain of test@example.com) identity=mailfrom"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_PASS'])

	def test_spf_pass_invalid_identity(self):

		email="""Received-SPF: pass (example.com: domain of test@example.com) identity=mailfro"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 0, [])

	def test_spf_with_ignore_received_spf_header_method(self):

		lists="""ignore_received_spf_header 1"""

		email="""Received-SPF: pass (example.org: domain of test@example.org) 
Received-SPF: softfail (example.org: domain of test@example.org) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 0, [])

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalSPF, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')