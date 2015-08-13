"""Base for SA plugins."""

from __future__ import absolute_import

from builtins import tuple
from builtins import object

import sys

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
except:
    pass

import sa.errors


class BasePlugin(object):
    """Abstract class for plugins. All plugins must inherit from this class."""
    # List of methods that will be registered as eval rules after the plugin
    # has been initialized.
    eval_rules = tuple()
    # Dictionary that matches options to tuples like (type, defaul_value)
    # Supported types are "int", "float", "bool", "str", "list".
    options = {
            "user_scores_dsn": "",
            "user_scores_sql_username": "",
            "user_scores_sql_password": "",
            }

    def __init__(self, context):
        """Initialize the plugin and parses all options specified in
        options.
        """
        self.ctxt = context
        self._plugin_name = self.__class__.__name__
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

        May be overridden.
        """

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

    def open_dsn_session(self):
        """Open a new DSN session
        """
        if 'sqlalchemy' not in sys.modules:
            return
        splits = self.get_local('user_scores_dsn').split(":")
        dbtype, dbname, host, port = ("","","","")
        if not splits:
            #No database connection has been configured
            return
        if len(split[1:]) < 3:
            # Wrong configuration, we need dbtype, dbname and host
            return
        #First parts is the DBI.
        if len(split[1:]) == 3:
            dbtype, dbname, host = split[1:]
        else:
            # We just care about the next four items
            dbtype, dbname, host, port = split[1:4]
        if "" in (dbtype,host):
            # We don't know what driver to use and 
            # we don't know where to connect.
            return
        username = self.get_local('user_scores_username')
        password = self.get_local('user_scores_password')
        up = ":".join([k for k in [username, password] if k])
        host = "@%s"%host if up else host
        hp = ":".join([k for k in [host,port] if k])
        engine = create_engine('%s://%s%s/%s'%(dbype, up, hp, dbname))
        Session = sessionmaker(bind=engine)
        return Session()


