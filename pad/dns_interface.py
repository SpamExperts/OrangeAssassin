""" DNS wrapper that takes the user options into consideration
when performing queries"""

import struct
import logging
import datetime

import dns
import dns.resolver
import dns.reversename


class DNSInterface(object):
    """Interface for various dns related actions"""

    def __init__(self):
        self.log = logging.getLogger("pad-logger")
        self._resolver = dns.resolver.Resolver()
        self.restrictions = {}
        self.test_qnames = []
        self.retest = datetime.datetime.now()
        self._test_interval = None
        self.dns_available = True
        self.test = False
        self._resolver.edns = 0
        self._resolver.rotate = False

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
            self._test_interval = relativedelta(seconds=int(value))

    @property
    def nameservers(self):
        "get the nameservers from the resolver"
        return self._resolver.nameservers

    @nameservers.setter
    def namerservers(self, nameservers):
        "set the nameservers for the resolver"
        self._resolver.nameservers = nameservers

    def _is_available(self):
        if self.test and self.next_test <= datetime.datetime.now():
            for qname in self.test_qnames:
                if self._query(qname, "A"):
                    self.available = True
                    break
            else:
                self.available = False
            self.next_test = datetime.datetime.now() + self.test_interval

        return self.available

    def is_query_restricted(self, qname):
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
        # XXX This needs to take into account various the
        # XXX network options. #40.
        # XXX We should likely cache responses here as
        # XXX well.

        if self.is_query_restricted(qname):
            self.log.debug("Querying %s is restricted", qname)
            return []

        if not self.available():
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
