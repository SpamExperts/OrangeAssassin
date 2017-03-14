"""Tests for pad.plugins.base."""

import unittest

try:
    from unittest.mock import patch, Mock, MagicMock
except ImportError:
    from mock import patch, Mock, MagicMock

import oa.errors
import oa.context
import oa.plugins.base


class TestBasePlugin(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        oa.plugins.base.BasePlugin.dsn_name = None
        patch("oa.plugins.base.BasePlugin.options", self.options).start()
        self.mock_create_engine = patch("oa.plugins.base.create_engine",
                                        create=True).start()
        self.mock_session_maker = patch("oa.plugins.base.sessionmaker",
                                        create=True).start()
        self.conf = {
            "use_bayes": True,
            "use_network": True,
        }
        self.mock_ctxt = MagicMock()
        self.mock_msg = MagicMock()
        self.mock_ruleset = MagicMock(conf=self.conf)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_init_options_defaults(self):
        self.options["test_bool"] = ("bool", False)

        oa.plugins.base.BasePlugin(self.mock_ctxt)
        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test_bool", False)

    def test_init_options_dsn_defaults(self):
        oa.plugins.base.BasePlugin.dsn_name = "test_plugin"
        oa.plugins.base.BasePlugin(self.mock_ctxt)

        self.assertIn("test_plugin_dsn", self.options)
        self.assertIn("test_plugin_sql_password", self.options)
        self.assertIn("test_plugin_sql_username", self.options)

    def test_set_global(self):
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.set_global("test", "value")
        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", "value")

    def test_get_global(self):
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.get_global("test")
        self.mock_ctxt.get_plugin_data.assert_called_with("BasePlugin", "test")

    def test_del_global(self):
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.del_global("test")
        self.mock_ctxt.del_plugin_data.assert_called_with("BasePlugin", "test")

    def test_set_local(self):
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.set_local(self.mock_msg, "test", "value")
        self.mock_msg.set_plugin_data.assert_called_with("BasePlugin",
                                                         "test", "value")

    def test_get_local(self):
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.get_local(self.mock_msg, "test")
        self.mock_msg.get_plugin_data.assert_called_with("BasePlugin", "test")

    def test_del_local(self):
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)

        plugin.del_local(self.mock_msg, "test")
        self.mock_msg.del_plugin_data.assert_called_with("BasePlugin", "test")

    def test_parse_config_int(self):
        self.options["test"] = ("int", 0)
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(oa.errors.InhibitCallbacks, plugin.parse_config,
                          "test", "1")

        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", 1)

    def test_parse_config_int_invalid(self):
        self.options["test"] = ("int", 0)
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(oa.errors.PluginError, plugin.parse_config, "test",
                          "abc")

    def test_parse_config_float(self):
        self.options["test"] = ("float", 0)
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(oa.errors.InhibitCallbacks, plugin.parse_config,
                          "test", "1.1")

        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", 1.1)

    def test_parse_config_float_invalid(self):
        self.options["test"] = ("float", 0)
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(oa.errors.PluginError, plugin.parse_config, "test",
                          "abc")

    def test_parse_config_bool(self):
        self.options["test"] = ("bool", False)
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(oa.errors.InhibitCallbacks, plugin.parse_config,
                          "test", "true")

        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", True)

    def test_parse_config_str(self):
        self.options["test"] = ("str", "def_value")
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(oa.errors.InhibitCallbacks, plugin.parse_config,
                          "test", "value")

        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", "value")

    def test_parse_config_list(self):
        self.options["test"] = ("list", [])
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)
        self.assertRaises(oa.errors.InhibitCallbacks, plugin.parse_config,
                          "test", "value1,value2")

        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "test", ["value1",
                                                                   "value2"])

    def test_create_engine_from_dbi(self):
        dbi = "DBI:mysql:spamassassin:localhost"
        alchemy = "mysql://testuser:password@localhost/spamassassin"
        mock_dbi = patch("oa.plugins.base.dbi_to_alchemy",
                         return_value=alchemy).start()

        oa.plugins.base.BasePlugin.dsn_name = "test_plugin"
        plugin = oa.plugins.base.BasePlugin(self.mock_ctxt)

        expected = self.mock_create_engine(alchemy)
        plugin.finish_parsing_end(self.mock_ruleset)
        self.mock_ctxt.set_plugin_data.assert_called_with("BasePlugin",
                                                          "engine", expected)

    def test_create_engine_from_dbi_real_context(self):
        dbi = "DBI:mysql:spamassassin:localhost"
        alchemy = "mysql://testuser:password@localhost/spamassassin"
        mock_dbi = patch("oa.plugins.base.dbi_to_alchemy",
                         return_value=alchemy).start()
        context = oa.context.GlobalContext()

        oa.plugins.base.BasePlugin.dsn_name = "test_plugin"
        plugin = oa.plugins.base.BasePlugin(context)

        plugin_data = context.plugin_data["BasePlugin"]
        plugin_data["test_plugin_dsn"] = dbi
        plugin_data["test_plugin_sql_username"] = "testuser"
        plugin_data ["test_plugin_sql_password"] = "password"

        plugin.finish_parsing_end(self.mock_ruleset)
        mock_dbi.assert_called_with(dbi, "testuser", "password")
        self.mock_create_engine.assert_called_with(alchemy)

    def test_create_engine_from_alchemy_real_context(self):
        alchemy = "mysql://testuser:password@localhost/spamassassin"
        context = oa.context.GlobalContext()

        oa.plugins.base.BasePlugin.dsn_name = "test_plugin"
        plugin = oa.plugins.base.BasePlugin(context)

        plugin_data = context.plugin_data["BasePlugin"]
        plugin_data["test_plugin_dsn"] = alchemy

        plugin.finish_parsing_end(self.mock_ruleset)
        self.mock_create_engine.assert_called_with(alchemy)

    def test_get_session(self):
        engine = MagicMock()
        context = oa.context.GlobalContext()

        oa.plugins.base.BasePlugin.dsn_name = "test_plugin"
        plugin = oa.plugins.base.BasePlugin(context)

        plugin_data = context.plugin_data["BasePlugin"]
        plugin_data["engine"] = engine

        result = plugin.get_session()
        self.mock_session_maker.assert_called_with(bind=engine)
        expected = self.mock_session_maker(bind=engine)()
        self.assertEqual(result, expected)


class TestDBItoAlchemy(unittest.TestCase):
    """Test converting Perl DBI to SQLAlchemy engine format."""
    def setUp(self):
        unittest.TestCase.setUp(self)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_mysql(self):
        """Test converting MySQL DBI to Alchemy"""
        expected = "mysql+pymysql://testuser:password@localhost/spamassassin"
        dsn = "DBI:mysql:spamassassin:localhost"
        user = "testuser"
        password = "password"
        result = oa.plugins.base.dbi_to_alchemy(dsn, user, password)
        self.assertEqual(result, expected)

    def test_mysql_port(self):
        """Test converting MySQL DBI to Alchemy with custom port specified"""
        expected = "mysql+pymysql://testuser:password@localhost:3306/spamassassin"
        dsn = "DBI:mysql:spamassassin:localhost:3306"
        user = "testuser"
        password = "password"
        result = oa.plugins.base.dbi_to_alchemy(dsn, user, password)
        self.assertEqual(result, expected)

    def test_postgress(self):
        """Test converting PostgreSQL DBI to Alchemy"""
        expected = "postgresql://testuser:password@localhost/spamassassin"
        dsn = "DBI:Pg:dbname=spamassassin;host=localhost"
        user = "testuser"
        password = "password"
        result = oa.plugins.base.dbi_to_alchemy(dsn, user, password)
        self.assertEqual(result, expected)

    def test_postgress_port(self):
        """Test converting PostgreSQL DBI to Alchemy with custom port."""
        expected = "postgresql://testuser:password@localhost:3306/spamassassin"
        dsn = "DBI:Pg:dbname=spamassassin;host=localhost;port=3306"
        user = "testuser"
        password = "password"
        result = oa.plugins.base.dbi_to_alchemy(dsn, user, password)
        self.assertEqual(result, expected)

    def test_sqlite(self):
        """Test converting PostgreSQL DBI to Alchemy"""
        expected = "sqlite:////path/spamassassin.db"
        dsn = "DBI:SQLite:dbname=/path/spamassassin.db"
        user = ""
        password = ""
        result = oa.plugins.base.dbi_to_alchemy(dsn, user, password)
        self.assertEqual(result, expected)

    def test_unknown_driver(self):
        expected = ""
        dsn = "DBI:Oracle:somethingelse"
        user = "testuser"
        password = "password"
        result = oa.plugins.base.dbi_to_alchemy(dsn, user, password)
        self.assertEqual(result, expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestBasePlugin, "test"))
    test_suite.addTest(unittest.makeSuite(TestDBItoAlchemy, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
