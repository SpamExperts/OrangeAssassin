"""Base for SA plugins."""

from __future__ import absolute_import

from builtins import tuple
from builtins import object

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
except ImportError:
    create_engine = None
    sessionmaker = None

import sa.errors


def dbi_to_alchemy(dsn, user, password):
    """Convert perl DBI setting to SQLAlchemy settings."""
    dummy, driver, connection = dsn.split(":", 2)
    if driver.lower() == "mysql":
        driver = "mysql"
        db_name, hostname = connection.split(":", 1)
    elif driver.lower() == "pg":
        driver = "postgresql"
        values = dict(item.split("=") for item in connection.split(";"))
        db_name = values["dbname"]
        hostname = values["host"]
        if "port" in values:
            hostname = "%s:%s" % (hostname, values["port"])
    elif driver.lower() == "sqlite":
        driver = "sqlite"
        user, password, hostname = "", "", ""
        values = dict(item.split("=") for item in connection.split(";"))
        db_name = values["dbname"]
    else:
        return ""
    if not user or not password:
        return "%s://%s/%s" % (driver, hostname, db_name)
    return "%s://%s:%s@%s/%s" % (driver, user, password, hostname, db_name)


class BasePlugin(object):
    """Abstract class for plugins. All plugins must inherit from this class.

    This exposes methods to methods to store data and configuration options
    in the "global" context and the "local" context.

     * The "global" context is loaded once when the configuration is parsed
     and persists throughout until the plugin is reloaded.
     * The "local" context is stored per message and each new message parsed
     has its one context.

    The methods automatically stores the data under the plugin names to ensure
    that there are no name clashes between plugins.

    The plugin can also define eval rules by implementing a method and adding
    it to the eval_rules list. These will be registered after the plugin has
    been initialized.
    """
    eval_rules = tuple()
    # Dictionary that matches options to tuples like (type, default_value)
    # Supported types are "int", "float", "bool", "str", "list".
    options = None
    # The name of the DSN options
    dsn_name = None

    def __init__(self, context):
        """Initialize the plugin and parses all options specified in
        options.
        """
        self.ctxt = context
        self._plugin_name = self.__class__.__name__
        if self.dsn_name:
            self.options[self.dsn_name + "_dsn"] = ("str", "")
            self.options[self.dsn_name + "_sql_username"] = ("str", "")
            self.options[self.dsn_name + "_sql_password"] = ("str", "")
        for key, (dummy, value) in self.options.items():
            self.set_global(key, value)

    def set_global(self, key, value):
        """Store data in the global context"""
        self.ctxt.set_plugin_data(self._plugin_name, key, value)

    def get_global(self, key=None):
        """Get data from the global context"""
        return self.ctxt.get_plugin_data(self._plugin_name, key)

    def del_global(self, key=None):
        """Delete data from the global context"""
        return self.ctxt.del_plugin_data(self._plugin_name, key)

    def set_local(self, msg, key, value):
        """Store data in the local message context"""
        msg.set_plugin_data(self._plugin_name, key, value)

    def get_local(self, msg, key=None):
        """Get data from the local message context"""
        return msg.get_plugin_data(self._plugin_name, key)

    def del_local(self, msg, key=None):
        """Delete data from the local message context"""
        return msg.del_plugin_data(self._plugin_name, key)

    def set_int_option(self, global_key, value):
        """Parse and set a integer option."""
        try:
            self.set_global(global_key, int(value))
        except ValueError:
            raise sa.errors.PluginError("Invalid value for %s: %s" %
                                        (global_key, value))

    def set_float_option(self, global_key, value):
        """Parse and set a float option."""
        try:
            self.set_global(global_key, float(value))
        except ValueError:
            raise sa.errors.PluginError("Invalid value for %s: %s" %
                                        (global_key, value))

    def set_bool_option(self, global_key, value):
        """Parse and set a bool option."""
        self.set_global(global_key, value.lower() in ("1", "true"))

    def set_str_option(self, global_key, value):
        """Parse and set a string option."""
        self.set_global(global_key, value)

    def set_list_option(self, global_key, value, separator=","):
        """Parse and set a list option."""
        self.set_global(global_key, value.split(separator))

    def inhibit_further_callbacks(self):
        """Tells the plugin handler to inhibit calling into other plugins in
        the plugin chain for the current callback.
        """
        raise sa.errors.InhibitCallbacks()

    def parse_config(self, key, value):
        """Parse a config line that the normal parses doesn't know how to
        interpret.

        Use self.inhibit_further_callbacks to stop other plugins from
        processing this line.

        May be overridden.
        """
        if key in self.options:
            set_func = getattr(self, "set_%s_option" % self.options[key][0])
            set_func(key, value)
            self.inhibit_further_callbacks()

    # XXX The name method for this is horrible, but it's likely better to have
    # XXX it the same as SA.
    def finish_parsing_end(self, ruleset):
        """Called when the configuration parsing has finished, but before the
        post-parsing. This hook can be used for e.g. to add rules to the
        ruleset.

        By default this prepares the SQLAlchemy engine if the plugin has any
        set.
        """
        connect_string = None
        if self.dsn_name:
            dsn = self.get_global(self.dsn_name + "_dsn")
            if dsn.upper().startswith("DBI"):
                # Convert from SA format.
                user = self.get_global(self.dsn_name + "_sql_username")
                password = self.get_global(self.dsn_name + "_sql_password")
                connect_string = dbi_to_alchemy(dsn, user, password)
            elif dsn:
                # The connect string is already in the correct format
                connect_string = dsn
        if connect_string is not None:
            self.set_global("engine", create_engine(connect_string))

    def get_session(self):
        """Open a new SQLAlchemy session."""
        engine = self.get_global("engine")
        return sessionmaker(bind=engine)()

    def check_start(self, msg):
        """Called before the metadata is extracted from the message. The
        message object passed will only have raw_msg and msg available.

        May be overridden.
        """

    def extract_metadata(self, msg, paylod, part):
        """Called while the message metadata is extracted for every message
        part. If the part contains text, corresponding payload is provided,
        else it will be None.

        May be overridden.
        """

    def parsed_metadata(self, msg):
        """The message has been parsed and all the information can be accessed
        by the plugin.

        May be overridden.
        """

    def check_end(self, msg):
        """The message check operation has just finished, and the results are
        about to be returned to the caller

        May be overridden.
        """

    def plugin_report(self, msg):
        """Called when a message should be reported as spam.

        May be overridden.
        """

    def plugin_revoke(self, msg):
        """Called when a message should be reported as ham.

        May be overridden.
        """
