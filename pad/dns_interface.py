""" DNS wrapper that takes the user options into consideration
when performing queries"""

import random
import struct
import logging
import datetime

import dns
import dns.resolver
import dns.reversename


class DNSInterface(object):
    """Interface for various dns related actions"""

    test_qnames = [
        "adelphia.net",
        "akamai.com",
        "apache.org",
        "cingular.com",
        "colorado.edu",
        "comcast.net",
        "doubleclick.com",
        "ebay.com",
        "gmx.net",
        "google.com",
        "intel.com",
        "kernel.org",
        "linux.org",
        "mit.edu",
        "motorola.com",
        "msn.com",
        "sourceforge.net",
        "sun.com",
        "w3.org",
        "yahoo.com",
    ]

    def __init__(self):
        self.log = logging.getLogger("pad-logger")
        self._resolver = dns.resolver.Resolver()
        self.query_restrictions = {}
        self.next_test = datetime.datetime.now()
        self._test_interval = datetime.timedelta(seconds=600)
        self.test = False
        self._resolver.edns = 0
        self._resolver.rotate = False
        self._available = True

    @property
    def port(self):
        return self._resolver.port

    @port.setter
    def port(self, port):
        self._resolver.port = port

    @property
    def rotate_nameservers(self):
        return self._resolver.rotate

    @rotate_nameservers.setter
    def rotate_nameservers(self, rotate):
        self._resolver.rotate = rotate == "rotate"

    @property
    def edns(self):
        return bool(self._resolver.payload)

    @edns.setter
    def edns(self, value):
        if value.startswith("no"):
            self._resolver.payload = 512
        else:
            self._resolver.payload = int(value.split("=", 1)[1])

    @property
    def test_interval(self):
        return self._test_interval

    @test_interval.setter
    def test_interval(self, value):
        "Set the test_interval as relative delta object"
        if value.endswith("s"):
            self._test_interval = datetime.timedelta(seconds=int(value[:-1]))
        elif value.endswith("m"):
            self._test_interval = datetime.timedelta(minutes=int(value[:-1]))
        elif value.endswith("h"):
            self._test_interval = datetime.timedelta(hours=int(value[:-1]))
        elif value.endswith("d"):
            self._test_interval = datetime.timedelta(days=int(value[:-1]))
        elif value.endswith("w"):
            self._test_interval = datetime.timedelta(weeks=int(value[:-1]))
        else:
            self._test_interval = datetime.timedelta(seconds=int(value))

    @property
    def nameservers(self):
        "get the nameservers from the resolver"
        return self._resolver.nameservers

    @nameservers.setter
    def namerservers(self, nameservers):
        "set the nameservers for the resolver"
        self._resolver.nameservers = nameservers

    @property
    def available(self):
        """Checks whether the dns is available. Depending on how it is
        configured a test may be performed to determine the result"""
        if self.test and self.next_test <= datetime.datetime.now():
            for qname in random.sample(
                    set(self.test_qnames), min(3, len(self.test_qnames))):
                if self._query(qname, "A"):
                    self._available = True
                    break
            else:
                self._available = False
            self.next_test = datetime.datetime.now() + self.test_interval

        return self._available

    @available.setter
    def available(self, value):
        self._available = value == "yes"
        print("VALUE: ", value)
        if value.startswith("test"):
            self.test = True
            if ":" in value:
                test_servers = value.split(":")[1].split()
                self.test_qnames = test_servers

    def is_query_restricted(self, qname):
        """Checks whether the qname is restricted by the dns_query_restriction
        option if the qname or one of it's parent domains matches an entry in
        the restriction that is returned, by default qnames are not
        restricted

        :param qname: The domain.
        :return: True if it's restricted, False if it's allowed or not found.
        """

        if not self.query_restrictions:
            return False

        while True:
            if qname in self.query_restrictions:
                return self.query_restrictions[qname]
            try:
                qname = qname.split(".", 1)[1]
            except KeyError:
                return False

    def query(self, qname, qtype="A"):
        """This method should be used for any DNS queries.

        :param qname: The DNS question.
        :param qtype: The DNS query type.
        :return: The result of the DNS query.
        """

        if self.is_query_restricted(qname):
            self.log.debug("Querying %s is restricted", qname)
            return []

        if not self.available:
            self.log.debug("DNS querying is not available")
            return []

        self.log.debug("Querying %s for %s record", qname, qtype)
        return self._query(qname, qtype)

    def _query(self, qname, qtype):
        if qtype == "PTR":
            qname = dns.reversename.from_address(qname)
        try:
            return self._resolver.query(qname, qtype)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
            self.log.warn("Failed to resolve %s (%s): %s", qname, qtype, e)
            return []
        except (ValueError, IndexError, struct.error) as e:
            self.log.info("Invalid DNS entry %s (%s): %s", qname, qtype, e)
            return []

    def reverse_ip(self, ip):
        reversed_ip = str(dns.reversename.from_address(ip.exploded))
        return reversed_ip.rstrip(".").rsplit(".", 2)[0]
