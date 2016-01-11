""" RelayCountry Plugin. """

from __future__ import absolute_import

import re
import csv
import socket
import struct

import pad.plugins.base

# XXX: Need to set this in a configuration parameter.
# The database can be downloaded from here:
# http://geolite.maxmind.com/download/geoip/database/GeoIPCountryCSV.zip
DATABASE_PATH = "geo.csv"

def ip2long(ip):
    """
    Convert an IP string to long
    """
    try:
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]
    except:
        pass


class RelayCountry(pad.plugins.base.BasePlugin):
    """ This plugin exposes the countris that a mail was relayed from.
    """
    def __init__(self, *args, **kwargs):
        self.ipranges = []
        super(pad.plugins.base.BasePlugin, self).__init__(*args, **kwargs)

    def load_database(self):
        try:
            databasecsv = csv.reader(open(DATABASE_PATH))
        except (IOError, OSError):
            #Can't open the file
            return
        self.ipranges = []
        for item in databasecsv:
            ip_range_start, country_code = ip2long(item[0]), item[4]
            self.ipranges.append((ip_range_start, country_code))

    def get_country(self, IP):
        """ Return the country corresponding to an IP based on the
        network range database.
        """
        if not self.ipranges:
            self.load_database()
        if (IP.startswith("10") or 
                IP.startswith("172.16") or 
                IP.startswith("192.168") or
                IP.startswith("127.0.0.1")):
            return
        ipl = ip2long(IP)
        for index, item in enumerate(self.ipranges):
            try:
                nextitem = self.ipranges[index + 1]
            except IndexError:
                nextitem = (0,"NONE")
            #print ipl, item[0], nextitem[0]
            if ipl >= item[0] and ipl <= nextitem[0]:
                return item[1]
        return

    def check_start(self, msg):
        """ Check the X-Relay-Countries in the message and exposes the 
        countries that a mail was relayed from
        """
        ipfindregex = re.compile("[\[\(\s\/]((?:[0-9]{1,3}\.){3}[0-9]{1,3})[\s\]\)\/]")
        all_received = msg.msg.get_all("Received")
        all_received.extend(msg.msg.get_all("X-Received"))
        all_received = "\n".join(all_received)
        ips = ipfindregex.finall(all_received)
        result = []
        for ip in ips:
            country = self.get_country(ip)
            if country:
                result.appen(country)
        if result:
            msg.headers.append("X-Spam-Relay-Country", 
                               " ".join(result))
        
