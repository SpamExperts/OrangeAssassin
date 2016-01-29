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
    options = {"geodb": ("str", ""),}

    def __init__(self, *args, **kwargs):
        self.reader = None
        super(RelayCountryPlugin, self).__init__(*args, **kwargs)

    def load_database(self):
        """Load the csv file and create a list of items where to search the IP.
        """
        try:
            self.reader = pygeoip.GeoIP(self.get_global("geodb"))
            return True
        except IOError as exc:
            self.ctxt.log.warning("Unable to open geo database file: %r", exc)

    def get_country(self, ipaddr):
        """Return the country corresponding to an IP based on the
        network range database.
        """
        if ipaddr.is_private:
            return "**"
        response = self.reader.country_code_by_addr(str(ipaddr))
        if not response:
            self.ctxt.log.info("Can't locate IP '%s' in database", ipaddr)
            #Cant locate the IP in database.
            return "XX"
        return response

    def parsed_metadata(self, msg):
        """Check the X-Relay-Countries in the message and exposes the
        countries that a mail was relayed from
        """
        if not self.get_global("geodb"):
            self.ctxt.log.info("Unable to locate the geo database")
            return
        if not self.load_database():
            return
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
