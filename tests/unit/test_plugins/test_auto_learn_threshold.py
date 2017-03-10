"""Tests the pad.plugins.auto_learn_threshold.AutoLearnThreshold Plugin"""

import unittest

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.auto_learn_threshold

class TestAutoLearnThresholdPlugin(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.local_data = {}
        self.global_data = {
            "bayes_auto_learn_threshold_nonspam": 0.1,
            "bayes_auto_learn_threshold_spam": 12.0,
            "bayes_auto_learn_on_error": True
        }
        self.mock_ctxt = MagicMock()
        self.mock_msg = MagicMock(msg={})
        self.plugin = pad.plugins.auto_learn_threshold.AutoLearnThreshold(self.mock_ctxt)
        self.plugin.set_local = lambda m, k, v: self.local_data.__setitem__(k,
                                                                            v)
        self.plugin.get_local = lambda m, k: self.local_data.__getitem__(k)
        self.plugin.set_global = self.global_data.__setitem__
        self.plugin.get_global = self.global_data.__getitem__
        self.mock_ruleset = MagicMock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_bayes_agrees_with_ham(self):
        self.local_data['learner_thinks_spam'] = False
        self.local_data['bayes_thinks_ham'] = True
        self.local_data['bayes_thinks_spam'] = False
        self.assertTrue(self.plugin.bayes_agrees(self.mock_msg))

    def test_bayes_agrees_with_spam(self):
        self.local_data['learner_thinks_spam'] = True
        self.local_data['bayes_thinks_ham'] = False
        self.local_data['bayes_thinks_spam'] = True
        self.assertTrue(self.plugin.bayes_agrees(self.mock_msg))

    def test_bayes_disagrees_with_spam(self):
        self.local_data['learner_thinks_spam'] = True
        self.local_data['bayes_thinks_ham'] = False
        self.local_data['bayes_thinks_spam'] = False
        self.assertFalse(self.plugin.bayes_agrees(self.mock_msg))

    def test_bayes_disagrees_with_ham(self):
        self.local_data['learner_thinks_spam'] = False
        self.local_data['bayes_thinks_ham'] = False
        self.local_data['bayes_thinks_spam'] = True
        self.assertFalse(self.plugin.bayes_agrees(self.mock_msg))

    def test_valid_tests_generator(self):
        tests = {
            "valid": MagicMock(score=3, tflags=None),
            "noautolearn": MagicMock(score=3, tflags=['noautolearn']),
            "userconf": MagicMock(score=3, tflags=['userconf']),
            "zero": MagicMock(score=0, tflags=None),
        }
        result = list(self.plugin.valid_tests(tests))
        self.assertListEqual(result, [('valid',tests['valid'])])

    def test_prepare_learning_metadata(self):
        tests = {
            "HEADER": MagicMock(score=3, tflags=None, rule_type='header'),
            "BODY": MagicMock(score=5, tflags=None, rule_type='body'),
            "META": MagicMock(score=7, tflags=None, rule_type='meta'),
            "META_NET": MagicMock(score=11, tflags=None, rule_type='meta'),
            "LEARN": MagicMock(score=13, tflags=['learn'], rule_type='body'),
            "URI": MagicMock(score=17, tflags=['learn'], rule_type='uri'),
        }
        self.plugin.prepare_learning_metadata(self.mock_msg, tests)
        expected_local_data = {'bayes_thinks_spam': False,
                               'bayes_thinks_ham': False,
                               'autolearn_points': 26,
                               'header_points': 21,
                               'body_points': 53,
                               'learned_points': 30,
                               'min_body_points': 3,
                               'min_header_points': 3,
                               'autolearn_forced': False,
                               'learner_thinks_spam': True,
                               'learner_thinks_ham': False}

        self.assertEqual(self.local_data, expected_local_data)

    def test_prepare_learning_metadata_global(self):
        tests = {
            "HEADER": MagicMock(score=3, tflags=None, rule_type='header'),
            "BODY": MagicMock(score=5, tflags=None, rule_type='body'),
            "META": MagicMock(score=7, tflags=None, rule_type='meta'),
            "META_NET": MagicMock(score=11, tflags=None, rule_type='meta'),
            "LEARN": MagicMock(score=13, tflags=['learn'], rule_type='body'),
            "URI": MagicMock(score=17, tflags=['learn'], rule_type='uri'),
        }
        self.plugin.prepare_learning_metadata(self.mock_msg, tests)
        expected_global_data = {'bayes_auto_learn_threshold_nonspam': 0.1,
                                'bayes_auto_learn_threshold_spam': 12.0,
                                'bayes_auto_learn_on_error': True,
                                }

        self.assertEqual(self.global_data, expected_global_data)

    def test_prepare_learning_metadata_global_forced(self):
        tests = {
            "HEADER": MagicMock(score=3, tflags=['autolearn_force'], rule_type='header'),
            "BODY": MagicMock(score=5, tflags=None, rule_type='body'),
            "META": MagicMock(score=7, tflags=None, rule_type='meta'),
            "META_NET": MagicMock(score=11, tflags=None, rule_type='meta'),
            "LEARN": MagicMock(score=13, tflags=['learn'], rule_type='body'),
            "URI": MagicMock(score=17, tflags=['learn'], rule_type='uri'),
        }

        self.plugin.prepare_learning_metadata(self.mock_msg, tests)
        expected_global_data = {'bayes_auto_learn_threshold_nonspam': 0.1,
                                'bayes_auto_learn_threshold_spam': 12.0,
                                'bayes_auto_learn_on_error': True,
                                }

        self.assertEqual(self.global_data, expected_global_data)

    def test_should_learn_false_1(self):
        self.mock_msg.score = 4
        self.mock_ctxt.conf = {'required_score': 5}
        self.global_data = {'bayes_auto_learn_threshold_nonspam': 0.1,
                            'bayes_auto_learn_threshold_spam': 12.0,
                            'bayes_auto_learn_on_error': True,}

        self.local_data = {'bayes_thinks_spam': False,
                           'bayes_thinks_ham': False,
                           'autolearn_points': 26,
                           'header_points': 21,
                           'body_points': 53,
                           'min_body_points': 3,
                           'min_header_points': 3,
                           'learned_points': 30,
                           'autolearn_forced': False,
                           'learner_thinks_spam': True,
                           'learner_thinks_ham': False}

        self.assertFalse(self.plugin.should_learn(self.mock_msg))


    def test_should_learn_false_spam_few_header_points(self):
        self.mock_msg.score = 6
        self.mock_ctxt.conf = {'required_score': 5}
        self.global_data = {'bayes_auto_learn_threshold_nonspam': 0.1,
                            'bayes_auto_learn_threshold_spam': 12.0,
                            'bayes_auto_learn_on_error': True}

        self.local_data = {'bayes_thinks_spam': False,
                           'bayes_thinks_ham': False,
                           'autolearn_points': 26,
                           'header_points': 2,
                           'body_points': 53,
                           'min_body_points': 3,
                           'min_header_points': 3,
                           'learned_points': 30,
                           'autolearn_forced': False,
                           'learner_thinks_spam': True,
                           'learner_thinks_ham': False}

        self.assertFalse(self.plugin.should_learn(self.mock_msg))

    def test_should_learn_false_spam_few_body_points(self):
        self.mock_msg.score = 6
        self.mock_ctxt.conf = {'required_score': 5}
        self.global_data = {'bayes_auto_learn_threshold_nonspam': 0.1,
                            'bayes_auto_learn_threshold_spam': 12.0,
                            'bayes_auto_learn_on_error': True}

        self.local_data = {'bayes_thinks_spam': False,
                           'bayes_thinks_ham': False,
                           'autolearn_points': 26,
                           'header_points': 33,
                           'body_points': 2,
                           'min_body_points': 3,
                           'min_header_points': 3,
                           'learned_points': 30,
                           'autolearn_forced': False,
                           'learner_thinks_spam': True,
                           'learner_thinks_ham': False}

        self.assertFalse(self.plugin.should_learn(self.mock_msg))


    def test_should_learn_false_spam_few_learned_points(self):
        self.mock_msg.score = 6
        self.mock_ctxt.conf = {'required_score': 5}
        self.global_data = {'bayes_auto_learn_threshold_nonspam': 0.1,
                            'bayes_auto_learn_threshold_spam': 12.0,
                            'bayes_auto_learn_on_error': True}

        self.local_data = {'bayes_thinks_spam': False,
                           'bayes_thinks_ham': False,
                           'autolearn_points': 26,
                           'header_points': 33,
                           'body_points': 5,
                           'min_body_points': 3,
                           'min_header_points': 3,
                           'learned_points': -5,
                           'autolearn_forced': False,
                           'learner_thinks_spam': True,
                           'learner_thinks_ham': False}

        self.assertFalse(self.plugin.should_learn(self.mock_msg))

    def test_should_learn_false_ham_few_learned_points(self):
        self.mock_msg.score = 4
        self.mock_ctxt.conf = {'required_score': 5}
        self.global_data = {'bayes_auto_learn_threshold_nonspam': 0.1,
                            'bayes_auto_learn_threshold_spam': 12.0,
                            'bayes_auto_learn_on_error': True}

        self.local_data = {'bayes_thinks_spam': False,
                           'bayes_thinks_ham': False,
                           'autolearn_points': 26,
                           'header_points': 33,
                           'body_points': 5,
                           'min_body_points': 3,
                           'min_header_points': 3,
                           'learned_points': 5,
                           'autolearn_forced': False,
                           'learner_thinks_spam': False,
                           'learner_thinks_ham': True}

        self.assertFalse(self.plugin.should_learn(self.mock_msg))


    def test_should_learn_false_ham_instead_of_spam(self):
        self.mock_msg.score = 6
        self.mock_ctxt.conf = {'required_score': 5}
        self.global_data = {'bayes_auto_learn_threshold_nonspam': 0.1,
                            'bayes_auto_learn_threshold_spam': 12.0,
                            'bayes_auto_learn_on_error': True}

        self.local_data = {'bayes_thinks_spam': False,
                           'bayes_thinks_ham': False,
                           'autolearn_points': 26,
                           'header_points': 33,
                           'body_points': 5,
                           'min_body_points': 3,
                           'min_header_points': 3,
                           'learned_points': 0,
                           'autolearn_forced': False,
                           'learner_thinks_spam': False,
                           'learner_thinks_ham': True}

        self.assertFalse(self.plugin.should_learn(self.mock_msg))

    def test_should_learn_false_unsure(self):
        self.mock_msg.score = 6
        self.mock_ctxt.conf = {'required_score': 5}
        self.global_data = {'bayes_auto_learn_threshold_nonspam': 0.1,
                            'bayes_auto_learn_threshold_spam': 12.0,
                            'bayes_auto_learn_on_error': True}

        self.local_data = {'bayes_thinks_spam': False,
                           'bayes_thinks_ham': False,
                           'autolearn_points': 5,
                           'header_points': 33,
                           'body_points': 5,
                           'min_body_points': 3,
                           'min_header_points': 3,
                           'learned_points': 0,
                           'autolearn_forced': False,
                           'learner_thinks_spam': False,
                           'learner_thinks_ham': False}

        self.assertFalse(self.plugin.should_learn(self.mock_msg))

    def test_should_learn_false_bayes_agrees(self):
        self.mock_msg.score = 6
        self.mock_ctxt.conf = {'required_score': 5}
        self.global_data = {'bayes_auto_learn_threshold_nonspam': 0.1,
                            'bayes_auto_learn_threshold_spam': 12.0,
                            'bayes_auto_learn_on_error': True}

        self.local_data = {'bayes_thinks_spam': True,
                           'bayes_thinks_ham': False,
                           'autolearn_points': 50,
                           'header_points': 33,
                           'body_points': 5,
                           'min_body_points': 3,
                           'min_header_points': 3,
                           'learned_points': 0,
                           'autolearn_forced': False,
                           'learner_thinks_spam': True,
                           'learner_thinks_ham': False}

        self.assertFalse(self.plugin.should_learn(self.mock_msg))

    def test_should_learn_True(self):
        self.mock_msg.score = 6
        self.mock_ctxt.conf = {'required_score': 5}
        self.global_data = {'bayes_auto_learn_threshold_nonspam': 0.1,
                            'bayes_auto_learn_threshold_spam': 12.0,
                            'bayes_auto_learn_on_error': True}

        self.local_data = {'bayes_thinks_spam': False,
                           'bayes_thinks_ham': False,
                           'autolearn_points': 50,
                           'header_points': 33,
                           'body_points': 5,
                           'min_body_points': 3,
                           'min_header_points': 3,
                           'learned_points': 0,
                           'autolearn_forced': False,
                           'learner_thinks_spam': True,
                           'learner_thinks_ham': False}

        self.assertTrue(self.plugin.should_learn(self.mock_msg))
