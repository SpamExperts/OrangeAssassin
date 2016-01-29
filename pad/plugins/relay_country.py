""" RelayCountry Plugin. """

from __future__ import absolute_import

from builtins import str

import re

import pad.errors

try:
    import pygeoip
except ImportError:
    raise pad.errors.PluginLoadError(
        "RelayCountryPlugin not loaded, You must install pygeoip to use "
        "this plugin")

try:
    import ipaddress
except ImportError:
    raise pad.errors.PluginLoadError(
        "RelayCountryPlugin not loaded, You must install py2-ipaddress to "
        "use this plugin")


import pad.plugins.base


class RelayCountryPlugin(pad.plugins.base.BasePlugin):
    """This plugin exposes the countries that a mail was relayed from.

    There is an option to specify the path for the database, it is called
    "geodb", is a string and points to the file where the database is.

    The database is a csv file that can be downloaded from maxmind server:
    http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
    """
    options = {"geodb": ("str", "GeoIP.dat"),
               "geodb-ipv6": ("str", "GeoIPv6.dat")}

    def finish_parsing_end(self, ruleset):
        super(RelayCountryPlugin, self).finish_parsing_end(ruleset)
        reader_ipv4 = self.load_database()
        reader_ipv6 = self.load_database("-ipv6")
        self.set_global("ipv4", reader_ipv4)
        self.set_global("ipv6", reader_ipv6)

    def load_database(self, which=""):
        """Load the csv file and create a list of items where to search the IP.
        """
        try:
            return pygeoip.GeoIP(self.get_global("geodb" + which))
        except IOError as exc:
            self.ctxt.log.warning("Unable to open geo database file: %r", exc)
        return None

    def get_country(self, ipaddr):
        """Return the country corresponding to an IP based on the
        network range database.
        """
        if ipaddr.is_private:
            return "**"
        if ipaddr.version == 4:
            reader = self.get_global("ipv4")
        else:
            reader = self.get_global("ipv6")
        if not reader:
            self.ctxt.log.warning("Database not loaded.")
            return "XX"
        response = reader.country_code_by_addr(str(ipaddr))
        if not response:
            self.ctxt.log.info("Can't locate IP '%s' in database", ipaddr)
            # Cant locate the IP in database.
            return "XX"
        return response

    def parsed_metadata(self, msg):
        """Check the X-Relay-Countries in the message and exposes the
        countries that a mail was relayed from
        """
        ips = msg.get_header_ips()
        result = []
        for ipaddr in ips:
            country = self.get_country(ipaddr)
            result.append(str(country))
        if result:
            result = " ".join(result)
            msg.headers["X-Relay-Countries"].append(result)
            self.ctxt.log.debug("X-Relay-Countries: '%s'", result)
            msg.plugin_tags["RELAYCOUNTRY"] = result
