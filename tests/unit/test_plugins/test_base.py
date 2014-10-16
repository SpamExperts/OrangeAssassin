"""Tests for sa.plugins.base."""

import unittest

try:
    from unittest.mock import patch, Mock, MagicMock
except ImportError:
    from mock import patch, Mock, MagicMock

import sa.errors
import sa.plugins.base


class TestBasePlugin(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        patch("sa.plugins.base.BasePlugin.options", self.options).start()
        self.mock_ctxt = MagicMock()
        self.mock_msg = MagicMock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_init_options_defaults(self):
        self.options["test_bool"] = ("bool", False)

        sa.plugins.base.BasePlugin(self.mock_ctxt)
        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test_bool", False)

    def test_set_global(self):
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.set_global("test", "value")
        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", "value")

    def test_get_global(self):
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.get_global("test")
        self.mock_ctxt.get_plugin_data.assert_called_with("BasePlugin", "test")

    def test_del_global(self):
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.del_global("test")
        self.mock_ctxt.del_plugin_data.assert_called_with("BasePlugin", "test")

    def test_set_local(self):
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.set_local(self.mock_msg, "test", "value")
        self.mock_msg.set_plugin_data.assert_called_with("BasePlugin",
                                                         "test", "value")

    def test_get_local(self):
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.get_local(self.mock_msg, "test")
        self.mock_msg.get_plugin_data.assert_called_with("BasePlugin", "test")

    def test_del_local(self):
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.del_local(self.mock_msg, "test")
        self.mock_msg.del_plugin_data.assert_called_with("BasePlugin", "test")

    def test_parse_config_int(self):
        self.options["test"] = ("int", 0)
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(sa.errors.InhibitCallbacks, plugin.parse_config,
                          "test", "1")

        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", 1)

    def test_parse_config_int_invalid(self):
        self.options["test"] = ("int", 0)
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(sa.errors.PluginError, plugin.parse_config, "test",
                          "abc")

    def test_parse_config_float(self):
        self.options["test"] = ("float", 0)
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(sa.errors.InhibitCallbacks, plugin.parse_config,
                          "test", "1.1")

        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", 1.1)

    def test_parse_config_float_invalid(self):
        self.options["test"] = ("float", 0)
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(sa.errors.PluginError, plugin.parse_config, "test",
                          "abc")

    def test_parse_config_bool(self):
        self.options["test"] = ("bool", False)
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(sa.errors.InhibitCallbacks, plugin.parse_config,
                          "test", "true")

        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", True)

    def test_parse_config_str(self):
        self.options["test"] = ("str", "def_value")
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(sa.errors.InhibitCallbacks, plugin.parse_config,
                          "test", "value")

        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", "value")

    def test_parse_config_list(self):
        self.options["test"] = ("list", [])
        plugin = sa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(sa.errors.InhibitCallbacks, plugin.parse_config,
                          "test", "value1,value2")

        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", ["value1",
                                                                   "value2"])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestBasePlugin, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
