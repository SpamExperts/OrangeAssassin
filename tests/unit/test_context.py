"""Tests for pad.context"""

import logging
import unittest

try:
    from unittest.mock import patch, Mock, MagicMock, mock_open
except ImportError:
    from mock import patch, Mock, MagicMock, mock_open

import pad.errors
import pad.context


class TestContext(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        logging.getLogger("pad-logger").handlers = [logging.NullHandler()]

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_set_plugin_data(self):
        context = pad.context._Context()
        context.set_plugin_data("test_plugins", "test", "value")
        self.assertEqual(context.plugin_data,
                         {"test_plugins": {"test": "value"}})

    def test_get_plugin_data(self):
        context = pad.context._Context()
        context.plugin_data["test_plugins"]["test"] = "value"
        result = context.get_plugin_data("test_plugins", "test")
        self.assertEqual(result, "value")

    def test_get_plugin_data_all(self):
        context = pad.context._Context()
        context.plugin_data["test_plugins"]["test"] = "value"
        result = context.get_plugin_data("test_plugins")
        self.assertEqual(result, {"test": "value"})

    def test_del_plugin_data(self):
        context = pad.context._Context()
        context.plugin_data["test_plugins"]["test"] = "value"
        context.del_plugin_data("test_plugins", "test")
        self.assertEqual(context.plugin_data,
                         {"test_plugins": {}})

    def test_del_plugin_data_all(self):
        context = pad.context._Context()
        context.plugin_data["test_plugins"]["test"] = "value"
        context.del_plugin_data("test_plugins")
        self.assertEqual(context.plugin_data, {})

    def test_pop_plugin_data(self):
        context = pad.context._Context()
        context.plugin_data["test_plugins"]["test"] = "value"
        result = context.pop_plugin_data("test_plugins", "test")
        self.assertEqual(context.plugin_data, {"test_plugins": {}})
        self.assertEqual(result, "value")

    def test_pop_plugin_data_all(self):
        context = pad.context._Context()
        context.plugin_data["test_plugins"]["test"] = "value"
        result = context.pop_plugin_data("test_plugins")
        self.assertEqual(context.plugin_data, {})
        self.assertEqual(result, {"test": "value"})


class TestGlobalContextLoadPlugin(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)
        logging.getLogger("pad-logger").handlers = [logging.NullHandler()]
        self.mock_module = MagicMock()
        self.mock_import = patch("pad.context.importlib").start()
        self.mock_load2 = patch("pad.context.GlobalContext._load_module_py2",
                                return_value=self.mock_module).start()
        self.mock_load3 = patch("pad.context.GlobalContext._load_module_py3",
                                return_value=self.mock_module).start()
        self.mock_unload = patch("pad.context.GlobalContext."
                                 "unload_plugin").start()
        self.mock_issubclass = patch("pad.context.issubclass",
                                     create=True).start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_load_plugin_load_module(self):
        ctxt = pad.context.GlobalContext()
        ctxt.load_plugin("pad.plugins.test_plugins.TestPlugin")
        self.mock_import.import_module.assert_called_with("pad.plugins.test_plugins")

    def test_load_plugin_load_module_already_loaded(self):
        ctxt = pad.context.GlobalContext()
        ctxt.plugins["TestPlugin"] = Mock()
        ctxt.load_plugin("pad.plugins.test_plugins.TestPlugin")
        self.mock_unload.assert_called_once_with("TestPlugin")
        self.mock_import.import_module.assert_called_with("pad.plugins.test_plugins")

    def test_load_plugin_load_module_import_error(self):
        self.mock_import.import_module.side_effect = ImportError()
        ctxt = pad.context.GlobalContext()
        self.assertRaises(pad.errors.PluginLoadError, ctxt.load_plugin,
                          "pad.plugins.test_plugins.TestPlugin")

    def test_load_plugin_from_path_py3(self):
        patch("pad.context.sys.version_info", (3, 4, 0)).start()
        ctxt = pad.context.GlobalContext()
        ctxt.load_plugin("TestPlugin", "/etc/pad/plugins/test_plugins.py")
        self.assertFalse(self.mock_import.import_module.called)
        self.assertFalse(self.mock_load2.called)
        self.mock_load3.assert_called_with("/etc/pad/plugins/test_plugins.py")

    def test_load_plugin_from_path_py32(self):
        patch("pad.context.sys.version_info", (3, 2, 4)).start()
        ctxt = pad.context.GlobalContext()
        ctxt.load_plugin("TestPlugin", "/etc/pad/plugins/test_plugins.py")
        self.assertFalse(self.mock_import.import_module.called)
        self.assertFalse(self.mock_load3.called)
        self.mock_load2.assert_called_with("/etc/pad/plugins/test_plugins.py")

    def test_load_plugin_from_path_py2(self):
        patch("pad.context.sys.version_info", (2, 7, 9)).start()
        ctxt = pad.context.GlobalContext()
        ctxt.load_plugin("TestPlugin", "/etc/pad/plugins/test_plugins.py")
        self.assertFalse(self.mock_import.import_module.called)
        self.assertFalse(self.mock_load3.called)
        self.mock_load2.assert_called_with("/etc/pad/plugins/test_plugins.py")

    def test_load_plugin_load_module_missing_plugin_class(self):
        ctxt = pad.context.GlobalContext()
        self.mock_module.TestPlugin = None
        self.assertRaises(pad.errors.PluginLoadError, ctxt.load_plugin,
                          "TestPlugin", "/etc/pad/plugins/test_plugins.py")

    def test_load_plugin_load_module_not_subclass(self):
        ctxt = pad.context.GlobalContext()
        self.mock_issubclass.return_value = False
        self.assertRaises(pad.errors.PluginLoadError, ctxt.load_plugin,
                          "TestPlugin", "/etc/pad/plugins/test_plugins.py")

    def test_load_plugin_register_rules(self):
        plugin_obj = self.mock_module.TestPlugin.return_value
        plugin_obj.eval_rules = ("test_eval_rule",)
        ctxt = pad.context.GlobalContext()
        ctxt.load_plugin("TestPlugin", "/etc/pad/plugins/test_plugins.py")

        self.assertEqual(ctxt.eval_rules["test_eval_rule"],
                         plugin_obj.test_eval_rule)

    def test_load_plugin_register_rules_redefined(self):
        plugin_obj = self.mock_module.TestPlugin.return_value
        plugin_obj.eval_rules = ("test_eval_rule",)
        ctxt = pad.context.GlobalContext()
        ctxt.eval_rules["test_eval_rule"] = Mock()

        ctxt.load_plugin("TestPlugin", "/etc/pad/plugins/test_plugins.py")
        self.assertEqual(ctxt.eval_rules["test_eval_rule"],
                         plugin_obj.test_eval_rule)

    def test_load_plugin_register_rules_undefined(self):
        plugin_obj = self.mock_module.TestPlugin.return_value
        plugin_obj.eval_rules = ("test_eval_rule",)
        plugin_obj.test_eval_rule = None

        ctxt = pad.context.GlobalContext()
        self.assertRaises(pad.errors.PluginLoadError, ctxt.load_plugin,
                          "TestPlugin", "/etc/pad/plugins/test_plugins.py")

    def test_load_plugin_register_cmd_rules(self):
        new_rule = MagicMock()
        plugin_obj = self.mock_module.TestPlugin.return_value
        plugin_obj.cmds = {"new_rtype": new_rule}
        ctxt = pad.context.GlobalContext()
        ctxt.load_plugin("TestPlugin", "/etc/pad/plugins/test_plugins.py")

        self.assertEqual(ctxt.cmds["new_rtype"], new_rule)

    def test_load_plugin_register_cmd_rules_redefined(self):
        new_rule = MagicMock()
        plugin_obj = self.mock_module.TestPlugin.return_value
        plugin_obj.cmds = {"new_rtype": new_rule}
        ctxt = pad.context.GlobalContext()
        ctxt.cmds["new_rtype"] = Mock()
        ctxt.load_plugin("TestPlugin", "/etc/pad/plugins/test_plugins.py")

        self.assertEqual(ctxt.cmds["new_rtype"], new_rule)


class TestGlobalContextLoadModule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        logging.getLogger("pad-logger").handlers = [logging.NullHandler()]
        self.mock_machinery = patch("pad.context.importlib.machinery",
                                    create=True).start()
        self.mock_imp = patch("pad.context.imp.load_module", create=True).start()
        self.mock_open = patch("pad.context.open", mock_open(),
                               create=True).start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_py3(self):
        ctxt = pad.context.GlobalContext()
        result = ctxt._load_module_py3("/etc/pad/plugins/test_plugins.py")
        self.mock_machinery.SourceFileLoader.assert_called_with(
            "test_plugins", "/etc/pad/plugins/test_plugins.py")
        expected = self.mock_machinery.SourceFileLoader(
            "test_plugins", "/etc/pad/plugins/test_plugins.py").load_module()
        self.assertEqual(result, expected)

    def test_py2(self):
        ctxt = pad.context.GlobalContext()
        result = ctxt._load_module_py2("/etc/pad/plugins/test_plugins.py")
        mock_openf = self.mock_open("/etc/pad/plugins/test_plugins.py", "U")
        expected = self.mock_imp("test_plugins", mock_openf,
                                 "/etc/pad/plugins/test_plugins.py",
                                 ('.py', 'U', 1))
        self.assertEqual(result, expected)

    def test_py2_no_valid_suffix(self):
        ctxt = pad.context.GlobalContext()
        self.assertRaises(pad.errors.PluginLoadError, ctxt._load_module_py2,
                          "/etc/pad/plugins/test_plugins.pyx")


class TestGlobalContextUnloadPlugin(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        logging.getLogger("pad-logger").handlers = [logging.NullHandler()]

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_unload(self):
        ctxt = pad.context.GlobalContext()
        ctxt.plugins["TestPlugin"] = MagicMock()

        ctxt.unload_plugin("TestPlugin")
        self.assertNotIn("TestPlugin", ctxt.plugins)

    def test_unload_not_loaded(self):
        ctxt = pad.context.GlobalContext()
        self.assertRaises(pad.errors.PluginLoadError, ctxt.unload_plugin,
                          "TestPlugin")

    def test_unload_delete_eval_rules(self):
        ctxt = pad.context.GlobalContext()
        ctxt.plugins["TestPlugin"] = MagicMock(eval_rules=["test_eval_rule"])
        ctxt.eval_rules["test_eval_rule"] = MagicMock()

        ctxt.unload_plugin("TestPlugin")
        self.assertEqual(ctxt.eval_rules, {})

    def test_unload_delete_cmd_rules(self):
        ctxt = pad.context.GlobalContext()
        ctxt.plugins["TestPlugin"] = MagicMock(cmds={"new_rtype": Mock()})
        ctxt.cmds["new_rtype"] = MagicMock()

        ctxt.unload_plugin("TestPlugin")
        self.assertEqual(ctxt.cmds, {})

    def test_unload_remove_plugin_data(self):
        ctxt = pad.context.GlobalContext()
        ctxt.plugins["TestPlugin"] = MagicMock()
        ctxt.plugin_data["TestPlugin"]["test"] = "value"

        ctxt.unload_plugin("TestPlugin")
        del ctxt.plugin_data["PADConf"]
        self.assertEqual(ctxt.plugin_data, {})


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestContext, "test"))
    test_suite.addTest(unittest.makeSuite(TestGlobalContextLoadPlugin, "test"))
    test_suite.addTest(unittest.makeSuite(TestGlobalContextLoadModule, "test"))
    test_suite.addTest(unittest.makeSuite(TestGlobalContextUnloadPlugin, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
