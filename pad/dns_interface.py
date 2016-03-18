""" DNS wrapper that takes the user options into consideration
when performing queries"""

import struct
import logging

import dns
import dns.resolver
import dns.reversename


class DNSInterface(object):
    """Interface for various dns related actions"""

    def __init__(self):

        self._resolver = dns.resolver.Resolver()
        self.log = logging.getLogger("pad-logger")

    @property
    def port(self):
        return self._resolver.port

    @port.setter
    def port(self, port):
        self._resolver.port = port

    @property
    def nameservers(self):
        return self._resolver.nameservers

    @nameservers.setter
    def namerservers(self, nameservers):
        self._resolver.nameservers = nameservers

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
        self.log.debug("Querying %s for %s record", qname, qtype)
        if qtype == "PTR":
            qname = dns.reversename.from_address(qname)
        try:
            return self._resolver.query(qname, qtype)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
            self.log.warn("Failed to resolved %s (%s): %s", qname, qtype, e)
            return []
        except (ValueError, IndexError, struct.error) as e:
            self.log.info("Invalid DNS entry %s (%s): %s", qname, qtype, e)
            return []

    def reverse_ip(self, ip):
        reversed = str(dns.reversename.from_address(ip.exploded))
        return reversed.rstrip(".").rsplit(".", 2)[0]
