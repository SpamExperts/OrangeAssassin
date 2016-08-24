import re
import logging
import ipaddress

from builtins import str
from builtins import object

_NETWORK_RE = re.compile(r"""
^(?P<exclude>!?)
    \[?
        (?P<ip>
            [0-9.]+|           # IPv4
            [0-9a-f:]*         # IPv6
        )
    \]?

    /?(?P<port>[0-9]{0,5})$
""", re.I | re.S | re.M | re.X)


def _format_network_str(network, mask):
    padding = ""
    length = len(network.split("."))
    if length == 3 or length == 7:
        network = network + "."

    if network.endswith("."):
        padding = ".".join(["0"] * (4 - network.count(".")))
        if not mask:
            mask = network.count(".") * 8
    if mask:
        return str("%s%s/%s" % (network, padding, mask))
    return str("%s%s" % (network, padding))

class NetworkListBase(object):
    _always_accepted = ()
    configured = False

    def __init__(self):
        self._networks = []
        self._networks.extend(self._always_accepted)

    def add(self, network, accepted):
        self._networks.append((network, accepted))

    def clear(self):
        self._networks = []
        self._networks.extend(self._always_accepted)

    def __contains__(self, query):
        for network, accepted in self._networks:
            if query in network:
                return accepted
        return False


class TrustedNetworks(NetworkListBase):
    _always_accepted = (
        (ipaddress.ip_network(str("127.0.0.0/8")), True),
        (ipaddress.ip_network(str("::1")), True),
    )


class InternalNetworks(TrustedNetworks):
    pass


class MSANetworks(NetworkListBase):
    pass


class NetworkList(object):
    internal = InternalNetworks()
    trusted = TrustedNetworks()
    msa = MSANetworks()

    def __init__(self):
        self.log = logging.getLogger("pad-logger")

    @property
    def configured(self):
        return self.internal.configured or self.trusted.configured



    def _extract_network(self, network_str):
        excluded, network, mask = _NETWORK_RE.match(network_str).groups()
        clean_value = _format_network_str(network, mask)
        try:
            network = ipaddress.ip_network(clean_value)
        except ValueError:
            return excluded, None
        return excluded, network

    def add_trusted_network(self, network_str):
        excluded, network = self._extract_network(network_str)
        self.trusted.configured = True
        self.trusted.add(network, not excluded)
        if not self.internal.configured:
            self.internal.add(network, not excluded)

    def add_internal_network(self, network_str):
        excluded, network = self._extract_network(network_str)
        if not self.internal.configured and self.internal:
            self.internal.clear()
        self.internal.configured = True
        self.trusted.add(network, not excluded)
        self.internal.add(network, not excluded)

    def add_msa_network(self, network_str):
        excluded, network = self._extract_network(network_str)
        self.internal.configured = True
        self.msa.add(network, not excluded)
