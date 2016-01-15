""" RelayCountry Plugin. """

from __future__ import absolute_import

import re
import socket
import struct

import pad.errors
try:
    import geoip2.database
except ImportError:
    raise pad.errors.PluginLoadError(
            "RelayCountryPlugin not loaded, You must install geoip2 to use this plugin")

import pad.plugins.base

IPFRE = re.compile(r"[\[\(\s\/]((?:[0-9]{1,3}\.){3}[0-9]{1,3})[\s\]\)\/]")
LOWER_172_IP = 2886729728
UPPER_172_IP = 2887778303

def ip2long(ip):
    """
    Convert an IP string to long
    """
    try:
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]
    except (socket.error, struct.error):
        pass

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
            self.reader = geoip2.database.Reader(self.get_global("geodb"))
            return True
        except IOError as exc:
            self.ctxt.log.warning("Unable to open geo database file: %r", exc)

    def get_country(self, ipaddress):
        """Return the country corresponding to an IP based on the
        network range database.
        """
        if (ipaddress.startswith("10") or
                ipaddress.startswith("192.168.") or
                ipaddress.startswith("127.0.0.1")):
            return "**"
        if ipaddress.startswith("172"):
            #The 20-bit block goes from 172.16.0.0 to 172.32.255.255
            longip = ip2long(ipaddress)
            if longip >= LOWER_172_IP and longip <= UPPER_172_IP:
                return "**"
        try:
            response = self.reader.country(ipaddress)
        except geoip2.errors.AddressNotFoundError:
            self.ctxt.log.info("Can't locate IP '%s' in database", ipaddress)
            #Cant locate the IP in database.
            return "XX"
        return response.country.iso_code # pylint: disable=maybe-no-member

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
        for ipaddress in ips:
            country = self.get_country(ipaddress)
            result.append(str(country))
        if result:
            msg.headers["X-Relay-Country"].append(" ".join(result))
            self.ctxt.log.debug("X-Relay-Country: '%s'", msg.headers["X-Relay-Country"])
