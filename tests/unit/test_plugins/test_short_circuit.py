"""Tests for pad.plugins.short_circuit."""

import unittest

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.errors
import pad.plugins.short_circuit


class TestShortCircuit(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.global_data = {
            "shortcircuit_spam_score": 100,
            "shortcircuit_ham_score": -100,
            "shortcircuit": [],
        }
        self.mock_ctxt = MagicMock()
        self.plugin = pad.plugins.short_circuit.ShortCircuit(self.mock_ctxt)
        self.plugin.set_global = self.global_data.__setitem__
        self.plugin.get_global = self.global_data.__getitem__
        self.mock_ruleset = MagicMock()
        self.mock_msg = MagicMock(plugin_tags={}, score=0, rules_checked={})
        self.mock_rule = MagicMock(score=5)
        # "name" is an argument of Mock, need to treat it
        # separately here
        self.mock_rule.configure_mock(name="TEST")

        self.mock_ruleset.get_rule.return_value = self.mock_rule

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_parse_metadata(self):
        self.plugin.parsed_metadata(self.mock_msg)
        self.assertEqual(self.mock_msg.plugin_tags, {
            "SCRULE": "none",
            "SCTYPE": "no",
            "SC": "no"
        })

    def test_short_no_match_on(self):
        self.mock_rule.match.return_value = False

        wrapped = self.plugin.get_wrapped_method(self.mock_rule, "on")
        result = wrapped(self.mock_msg)

        self.assertFalse(result)

    def test_short_no_match_spam(self):
        self.mock_rule.match.return_value = False

        wrapped = self.plugin.get_wrapped_method(self.mock_rule, "spam")
        result = wrapped(self.mock_msg)

        self.assertFalse(result)

    def test_short_no_match_ham(self):
        self.mock_rule.match.return_value = False

        wrapped = self.plugin.get_wrapped_method(self.mock_rule, "ham")
        result = wrapped(self.mock_msg)

        self.assertFalse(result)

    def test_short_match_on_tags(self):
        self.mock_rule.match.return_value = True

        wrapped = self.plugin.get_wrapped_method(self.mock_rule, "on")
        with self.assertRaises(pad.errors.StopProcessing):
            wrapped(self.mock_msg)

        self.assertEqual(self.mock_msg.plugin_tags, {
            "SCRULE": "TEST",
            "SCTYPE": "on",
            "SC": "TEST (on)"
        })

    def test_short_match_on_score(self):
        self.mock_rule.match.return_value = True

        wrapped = self.plugin.get_wrapped_method(self.mock_rule, "on")
        with self.assertRaises(pad.errors.StopProcessing):
            wrapped(self.mock_msg)

        self.assertEqual(self.mock_msg.score, 5)
        self.assertTrue(self.mock_msg.rules_checked["TEST"])

    def test_short_match_spam_tags(self):
        self.mock_rule.match.return_value = True

        wrapped = self.plugin.get_wrapped_method(self.mock_rule, "spam")
        with self.assertRaises(pad.errors.StopProcessing):
            wrapped(self.mock_msg)

        self.assertEqual(self.mock_msg.plugin_tags, {
            "SCRULE": "TEST",
            "SCTYPE": "spam",
            "SC": "TEST (spam)"
        })

    def test_short_match_spam_score(self):
        self.mock_rule.match.return_value = True

        wrapped = self.plugin.get_wrapped_method(self.mock_rule, "spam")
        with self.assertRaises(pad.errors.StopProcessing):
            wrapped(self.mock_msg)

        self.assertEqual(self.mock_msg.score, 105)
        self.assertTrue(self.mock_msg.rules_checked["TEST"])

    def test_short_match_ham_tags(self):
        self.mock_rule.match.return_value = True

        wrapped = self.plugin.get_wrapped_method(self.mock_rule, "ham")
        with self.assertRaises(pad.errors.StopProcessing):
            wrapped(self.mock_msg)

        self.assertEqual(self.mock_msg.plugin_tags, {
            "SCRULE": "TEST",
            "SCTYPE": "ham",
            "SC": "TEST (ham)"
        })

    def test_short_match_ham_score(self):
        self.mock_rule.match.return_value = True

        wrapped = self.plugin.get_wrapped_method(self.mock_rule, "ham")
        with self.assertRaises(pad.errors.StopProcessing):
            wrapped(self.mock_msg)

        self.assertEqual(self.mock_msg.score, -95)
        self.assertTrue(self.mock_msg.rules_checked["TEST"])

    def test_finish_parsing_on(self):
        mock_wrap = MagicMock()
        self.plugin.get_wrapped_method = mock_wrap
        self.global_data["shortcircuit"] = [
            "TEST on"
        ]

        self.plugin.finish_parsing_end(self.mock_ruleset)
        mock_wrap.assert_called_with(self.mock_rule, "on")
        self.assertEqual(self.mock_rule.match, mock_wrap.return_value)

    def test_finish_parsing_spam(self):
        mock_wrap = MagicMock()
        self.plugin.get_wrapped_method = mock_wrap
        self.global_data["shortcircuit"] = [
            "TEST spam"
        ]

        self.plugin.finish_parsing_end(self.mock_ruleset)
        mock_wrap.assert_called_with(self.mock_rule, "spam")
        self.assertEqual(self.mock_rule.match, mock_wrap.return_value)

    def test_finish_parsing_ham(self):
        mock_wrap = MagicMock()
        self.plugin.get_wrapped_method = mock_wrap
        self.global_data["shortcircuit"] = [
            "TEST ham"
        ]

        self.plugin.finish_parsing_end(self.mock_ruleset)
        mock_wrap.assert_called_with(self.mock_rule, "ham")
        self.assertEqual(self.mock_rule.match, mock_wrap.return_value)

    def test_finish_parsing_off(self):
        mock_wrap = MagicMock()
        self.plugin.get_wrapped_method = mock_wrap
        self.global_data["shortcircuit"] = [
            "TEST off"
        ]

        self.assertFalse(mock_wrap.called)

    def test_finish_parsing_invalid(self):
        mock_wrap = MagicMock()
        self.plugin.get_wrapped_method = mock_wrap
        self.global_data["shortcircuit"] = [
            "TESTham"
        ]

        self.assertFalse(mock_wrap.called)

    def test_finish_parsing_no_rule(self):
        self.mock_ruleset.get_rule.side_effect = KeyError
        mock_wrap = MagicMock()
        self.plugin.get_wrapped_method = mock_wrap
        self.global_data["shortcircuit"] = [
            "TEST ham"
        ]

        self.assertFalse(mock_wrap.called)

    def test_finish_parsing_invalid_stype(self):
        mock_wrap = MagicMock()
        self.plugin.get_wrapped_method = mock_wrap
        self.global_data["shortcircuit"] = [
            "TEST spam-ham"
        ]

        self.assertFalse(mock_wrap.called)
