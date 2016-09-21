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

		email="""Received-SPF: pass (example.org: domain of test@example.org) identity=helo
Received-SPF: none (example.org: domain of test@example.org) 
Received-SPF: softfail (example.org: domain of test@example.org) 
Received-SPF: fail (example.org: domain of test@example.org) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_HELO_FAIL', 'SPF_SOFTFAIL'])

	def test_spf_multiple_match_with_use_newest_received_spf_header_method(self):

		lists="""use_newest_received_spf_header 1"""

		email="""Received-SPF: pass (example.org: domain of test@example.org) identity=helo
Received-SPF: none (example.org: domain of test@example.org) 
Received-SPF: softfail (example.org: domain of test@example.org) 
Received-SPF: fail (example.org: domain of test@example.org) identity=helo"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_HELO_PASS', 'SPF_NONE'])

	def test_spf_pass_mailfrom_identity(self):

		email="""Received-SPF: pass (example.com: domain of test@example.com) identity=mailfrom"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_PASS'])

	def test_spf_pass_mfrom_identity(self):

		email="""Received-SPF: pass (example.com: domain of test@example.com) identity=mfrom"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_PASS'])

	def test_spf_pass_none_identity(self):

		email="""Received-SPF: pass (example.com: domain of test@example.com) identity=None"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 0, [])

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

	def test_spf_with_ignore_received_spf_header_method_pass_helo_and_ident(self):

		lists="""ignore_received_spf_header 1"""

		email="""Received-SPF: fail (example.org: domain of test@example.org) identity=helo
Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_PASS'])

	def test_spf_with_no_receive_spf_header_pass_helo_and_ident(self):

		email="""Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_PASS'])

	def test_spf_with_no_receive_spf_header_ident_not_matching_ip(self):

		email="""Received: from google.com ([1.2.3.4]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_SOFTFAIL', 'SPF_HELO_SOFTFAIL'])	

	def test_spf_with_no_receive_spf_header_ident_not_matching_ip_and_fail_on_helo(self):

		email="""Received: from example.com ([1.2.3.4]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_SOFTFAIL', 'SPF_HELO_FAIL'])	

	def test_spf_with_no_receive_spf_header_ident_matching_ip_and_fail_on_helo(self):

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_FAIL'])	

	def test_spf_with_no_receive_spf_header_ident_not_matching_ip_and_pass_on_helo(self):

		email="""Received:from spamexperts.com ([5.79.73.204]) by example.com 
	(envelope-from <envfrom@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_SOFTFAIL', 'SPF_HELO_PASS'])

	def test_spf_with_no_receive_spf_header_with_two_ips(self):

		email="""Received:from slack.com ([167.89.125.30] [2a00:1450:4017:804::200e]) by example.com 
	(envelope-from <envfrom@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_FAIL'])

	def test_spf_with_no_receive_spf_header_invalid_ip(self):

		lists="""ignore_received_spf_header 1"""

		email="""Received: from google.com ([1.2.3333.4]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 0, [])

	def test_spf_with_no_receive_spf_header_invalid_helo(self):

		email="""Received: from google ([2a00:1450:4017:803::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_PASS'])

	def test_spf_with_no_receive_spf_header_no_ident(self):

		email="""Received: from google.com ([2a00:1450:4017:803::200e]) by test.com"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_PASS'])

	def test_spf_with_no_receive_spf_header_with_ignore_received_spf_method_no_ident(self):

		lists="""ignore_received_spf_header 1"""

		email="""Received: from google.com ([2a00:1450:4017:803::200e]) by test.com"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_PASS'])

	def test_spf_with_no_receive_spf_header_no_ident_invalid_helo(self):

		lists="""ignore_received_spf_header 1"""

		email="""Received: from google ([2a00:1450:4017:803::200e]) by test.com"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 0, [])

	def test_spf_with_no_receive_spf_header_no_ident_no_helo(self):

		lists="""ignore_received_spf_header 1"""

		email="""Received: from ([2a00:1450:4017:803::200e]) by test.com"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 0, [])

	def test_spf_with_ip_in_trusted_network(self):

		lists="""trusted_networks 2a00:1450:4017:804::200e"""

		email="""Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 0, [])

	def test_spf_with_ip_in_untrusted_network(self):

		lists="""trusted_networks !2a00:1450:4017:804::200e"""

		email="""Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_PASS'])

	def test_spf_with_ip_in_trusted_network_and_two_receive_headers(self):

		lists="""trusted_networks 2a00:1450:4017:804::200e"""

		email="""Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)
Received:from example.net (example.com [1.2.3.4]) by example.com 
	(envelope-from <envfrom@spamexperts.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_SOFTFAIL', 'SPF_HELO_FAIL'])

	def test_spf_with_no_receive_spf_header_with_invalid_spf_timeout_method(self):
		#should ignore spf_timeout and take default

		lists="""ignore_received_spf_header 1
				 spf_timeout a"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_FAIL'])

	def test_spf_with_no_receive_spf_header_with_negative_spf_timeout_method(self):
		#should ignore spf_timeout and take default

		lists="""ignore_received_spf_header 1
				 spf_timeout -2"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_FAIL'])

	def test_spf_with_no_receive_spf_header_with_null_spf_timeout_method(self):

		lists="""ignore_received_spf_header 1
				 spf_timeout 0"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 0, [])

	def test_spf_with_no_receive_spf_header_with_float_spf_timeout_method(self):

		lists="""ignore_received_spf_header 0
				 spf_timeout 0.5"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_FAIL'])

	def test_spf_with_no_receive_spf_header_with_empty_spf_timeout_method(self):

		lists="""ignore_received_spf_header 0
				 spf_timeout"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_FAIL'])

	def test_spf_helo_with_both_receive_spf_and_receive_header(self):

		lists="""use_newest_received_spf_header 0"""

		email="""Received-SPF: fail (example.org: domain of test@example.org) identity=helo
Received-SPF: pass (example.org: domain of test@example.org) identity=helo
Received: from example.com ([1.2.3.4]) by mx37.antispamcloud.com 
	(envelope-from <serban@example.com>)
Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_FAIL', 'SPF_HELO_PASS'])

	def test_spf_helo_with_both_receive_spf_and_receive_header_and_use_newest_received_spf_header_method(self):

		lists="""use_newest_received_spf_header 1"""

		email="""Received-SPF: fail (example.org: domain of test@example.org) identity=helo
Received-SPF: pass (example.org: domain of test@example.org) identity=helo
Received: from example.com ([1.2.3.4]) by mx37.antispamcloud.com 
	(envelope-from <serban@example.com>)
Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_FAIL', 'SPF_HELO_FAIL'])

	def test_spf_with_both_receive_spf_and_receive_header(self):

		lists="""use_newest_received_spf_header 0"""

		email="""Received-SPF: fail (example.org: domain of test@example.org) 
Received-SPF: pass (example.org: domain of test@example.org) 
Received: from example.com ([1.2.3.4]) by mx37.antispamcloud.com 
	(envelope-from <serban@example.com>)
Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_FAIL'])

	def test_spf_with_both_receive_spf_and_receive_header_and_use_newest_received_spf_header_method(self):

		lists="""use_newest_received_spf_header 1"""

		email="""Received-SPF: neutral (example.org: domain of test@example.org) 
Received-SPF: pass (example.org: domain of test@example.org) 
Received: from example.com ([1.2.3.4]) by mx37.antispamcloud.com 
	(envelope-from <serban@example.com>)
Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_NEUTRAL', 'SPF_HELO_FAIL'])

	def test_spf_with_two_receive_header_and_no_ident_in_first(self):

		email="""Received: from example.com ([1.2.3.4]) by mx37.antispamcloud.com 
Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_HELO_FAIL'])

	def test_spf_with_two_receive_header_and_no_helo_in_first(self):

		email="""Received: from ceva ([1.2.3.4]) by mx37.antispamcloud.com 
	(envelope-from <serban@example.com>)
Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 1, ['SPF_FAIL'])

	def test_spf_with_dot_in_receive(self):

		email="""Received: from . ([1.2.3.4]) by mx37.antispamcloud.com 
	(envelope-from <serban@example.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_FAIL', 'SPF_HELO_NONE'])

	def test_spf_with_invalid_ip_in_first_receive(self):
		#should ignore the invalid ip and check the next receive

		email="""Received: from  example.com ([1.2.3333.4]) by mx37.antispamcloud.com 
Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_PASS'])

	def test_spf_with_invalid_helo_in_first_receive(self):
		#should ignore the invalid ip and check the next receive

		email="""Received: from example ([1.2.3.4]) by mx37.antispamcloud.com 
Received: from google.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
		result = self.check_pad(email)
		self.check_report(result, 0, [])

	#test for check_for_spf_whitelist_from()
	def test_whitelist_from_spf_full_address(self):
		
		lists="""whitelist_from_spf test@google.com"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 3, ['SPF_PASS', 'SPF_HELO_FAIL', 'CHECK_FOR_SPF_WHITELIST'])

	def test_whitelist_from_spf_with_wild_local_part(self):
		
		lists="""whitelist_from_spf *@g?ogle.com"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 3, ['SPF_PASS', 'SPF_HELO_FAIL', 'CHECK_FOR_SPF_WHITELIST'])

	def test_whitelist_from_spf_with_full_domain(self):
		
		lists="""whitelist_from_spf google.com"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 3, ['SPF_PASS', 'SPF_HELO_FAIL', 'CHECK_FOR_SPF_WHITELIST'])

	def test_whitelist_from_spf_with_regex(self):
		
		lists="""whitelist_from_spf .*.com"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_FAIL'])

	def test_whitelist_from_spf_with_wild_domain(self):
		
		lists="""whitelist_from_spf *goog?e.com"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 3, ['SPF_PASS', 'SPF_HELO_FAIL', 'CHECK_FOR_SPF_WHITELIST'])

	def test_whitelist_from_spf_with_empty_list(self):
		
		lists="""whitelist_from_spf"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_FAIL'])

	def test_whitelist_from_spf_with_invalid_list(self):
		
		lists="""whitelist_from_spf google"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PASS', 'SPF_HELO_FAIL'])

	def test_whitelist_from_spf_with_combined_lists(self):
		
		lists="""whitelist_from_spf *google.net *@google.com"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 3, ['SPF_PASS', 'SPF_HELO_FAIL', 'CHECK_FOR_SPF_WHITELIST'])

	def test_whitelist_from_spf_with_split_lists(self):
		
		lists="""whitelist_from_spf *google.net 
				 whitelist_from_spf *@google.com"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@google.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 3, ['SPF_PASS', 'SPF_HELO_FAIL', 'CHECK_FOR_SPF_WHITELIST'])

	def test_whitelist_from_spf_with_spf_fail(self):
		
		lists="""whitelist_from_spf *example.com"""

		email="""Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@example.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_FAIL', 'SPF_HELO_FAIL'])

	def test_whitelist_from_spf_with_spf_softfail(self):
		
		lists="""whitelist_from_spf *spamexperts.com"""

		email="""Received: from example.com ([1.2.3.4]) by test.com
	(envelope-from <test@spamexperts.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_SOFTFAIL', 'SPF_HELO_FAIL'])

	def test_whitelist_from_spf_with_spf_neutral(self):
		
		lists="""whitelist_from_spf *spamexperts.com"""

		email="""Received-SPF: neutral (example.com: domain of test@example.com)
Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@spamexperts.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_NEUTRAL', 'SPF_HELO_FAIL'])

	def test_whitelist_from_spf_with_spf_none(self):
		
		lists="""whitelist_from_spf *spamexperts.com"""

		email="""Received-SPF: none (example.com: domain of test@example.com)
Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@spamexperts.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_NONE', 'SPF_HELO_FAIL'])

	def test_whitelist_from_spf_with_spf_permerror(self):
		
		lists="""whitelist_from_spf *spamexperts.com"""

		email="""Received-SPF: permerror (example.com: domain of test@example.com)
Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@spamexperts.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_PERMERROR', 'SPF_HELO_FAIL'])

	def test_whitelist_from_spf_with_spf_temperror(self):
		
		lists="""whitelist_from_spf *spamexperts.com"""

		email="""Received-SPF: temperror (example.com: domain of test@example.com)
Received: from example.com ([2a00:1450:4017:804::200e]) by test.com
	(envelope-from <test@spamexperts.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_TEMPERROR', 'SPF_HELO_FAIL'])

	def test_whitelist_from_spf_with_spf_pass_and_ip_missmatch_ident(self):
		
		lists="""whitelist_from_spf *spamexperts.com"""

		email="""Received-SPF: pass (example.com: domain of test@example.com)
Received: from example.com ([1.2.3.4]) by test.com
	(envelope-from <test@spamexperts.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 3, ['SPF_PASS', 'SPF_HELO_FAIL', 'CHECK_FOR_SPF_WHITELIST'])

	def test_whitelist_from_spf_with_ignore_received_spf_header_method(self):
		
		lists="""whitelist_from_spf *spamexperts.com
				 ignore_received_spf_header 1"""

		email="""Received-SPF: pass (example.com: domain of test@example.com)
Received: from example.com ([1.2.3.4]) by test.com
	(envelope-from <test@spamexperts.com>)"""

		self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
		result = self.check_pad(email)
		self.check_report(result, 2, ['SPF_SOFTFAIL', 'SPF_HELO_FAIL'])

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalSPF, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')