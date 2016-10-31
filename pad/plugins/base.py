"""Base for PAD plugins."""

from __future__ import absolute_import

from builtins import tuple
from builtins import object

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
except ImportError:
    create_engine = None
    sessionmaker = None

from collections import defaultdict

import pad.conf


def dbi_to_mysql(dsn, user, password):
    conection_dates = defaultdict(int)
    dummy, driver, connection = dsn.split(":", 2)
    if driver.lower() == "mysql":
        driver = "mysql"
        db_name, hostname = connection.split(":", 1)
        conection_dates["driver"] = driver
        conection_dates["hostname"] = hostname
        conection_dates["db_name"] = db_name
        if not user or not password:
            return conection_dates
        conection_dates["user"] = user
        conection_dates["password"] = password
        return conection_dates

def dbi_to_alchemy(dsn, user, password):
    """Convert perl DBI setting to SQLAlchemy settings."""
    dummy, driver, connection = dsn.split(":", 2)
    if driver.lower() == "mysql":
        driver = "mysql+pymysql"
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


class BasePlugin(pad.conf.Conf, object):
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
    # Defines any new rules that the plugins implements.
    cmds = None
    # See pad.conf.Conf for details on options.
    options = None
    # The name of the DSN options
    dsn_name = None

    def __init__(self, ctxt):
        if self.dsn_name:
            self.options[self.dsn_name + "_dsn"] = ("str", "")
            self.options[self.dsn_name + "_sql_username"] = ("str", "")
            self.options[self.dsn_name + "_sql_password"] = ("str", "")
        super(BasePlugin, self).__init__(ctxt)

    def finish_parsing_start(self, results):
        """Called when the configuration parsing has finished but before
        the has actually been initialized from the parsed data.

        This can be used to insert new data after parsing.

        :param results: A dictionary that maps the rule names to the
          rest of the data extracted from the configuration (e.g. the
          score, description etc.)
        :return: Nothing

        """

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
        self["engine"] = None
        if self.dsn_name:
            dsn = self[self.dsn_name + "_dsn"]
            if dsn.upper().startswith("DBI"):
                # Convert from SA format.
                user = self[self.dsn_name + "_sql_username"]
                password = self[self.dsn_name + "_sql_password"]
                if not create_engine:
                    self["engine"] = dbi_to_mysql(dsn, user, password)
                else:
                    connect_string = dbi_to_alchemy(dsn, user, password)
            elif dsn:
                # The connect string is already in the correct format
                connect_string = dsn
        if connect_string is not None:
            self["engine"] = create_engine(connect_string)

    def get_engine(self):
        return self["engine"]

    def get_session(self):
        """Open a new SQLAlchemy session."""
        engine = self["engine"]
        return sessionmaker(bind=engine)()

    def check_start(self, msg):
        """Called before the metadata is extracted from the message. The
        message object passed will only have raw_msg and msg available.

        May be overridden.
        """

    def extract_metadata(self, msg, payload, text, part):
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

    def check_end(self, ruleset, msg):
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

    def parse_config(self, key, value):
        """Parse a config line that the normal parses doesn't know how to
        interpret.

        Use self.inhibit_further_callbacks to stop other plugins from
        processing this line.

        May be overridden.
        """
        super(BasePlugin, self).parse_config(key, value)
