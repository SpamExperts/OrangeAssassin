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

IPFRE = re.compile(r"[\[\(\s\/]{0,1}((?:[0-9]{1,3}\.){3}[0-9]{1,3})[\s\]\)\/]{0,1}")


class RelayCountryPlugin(pad.plugins.base.BasePlugin):
    """This plugin exposes the countries that a mail was relayed from.

    There is an option to specify the path for the database, it is called
    "geodb", is a string and points to the file where the database is.

    The database is a csv file that can be downloaded from maxmind server:
    http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz
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
        try:
            ipadobj = ipaddress.ip_address(str(ipaddr.encode('utf8'), "utf8"))
        except (ipaddress.AddressValueError, ValueError):
            self.ctxt.log.log.warning("Invalid IP address: '%s', ipaddr")
            return ""
        if ipadobj.is_private:
            return "**"
        response = self.reader.country_code_by_addr(ipaddr)
        if not response:
            self.ctxt.log.info("Can't locate IP '%s' in database", ipaddr)
            #Cant locate the IP in database.
            return "XX"
        return response

    def check_start(self, msg):
        """Check the X-Relay-Countries in the message and exposes the
        countries that a mail was relayed from
        """
        if not self.get_global("geodb"):
            self.ctxt.log.info("Unable to locate the geo database")
            return
        if not self.load_database():
            return
        all_received = msg.msg.get_all("Received")
        if not all_received:
            self.ctxt.log.info("No 'Received' headers found")
            return
        all_received = "\n".join(all_received)
        ips = IPFRE.findall(all_received)
        result = []
        self.ctxt.log.debug("IPS found: %r", ips)
        for ipaddr in ips:
            country = self.get_country(ipaddr)
            if not country: #Invalid IP address
                continue
            result.append(str(country))
        if result:
            msg.headers["X-Relay-Country"].append(" ".join(result))
            self.ctxt.log.debug("X-Relay-Country: '%s'", msg.headers["X-Relay-Country"])
